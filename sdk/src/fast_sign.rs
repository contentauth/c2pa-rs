// Copyright 2024 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

// Unless required by applicable law or agreed to in writing,
// this software is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR REPRESENTATIONS OF ANY KIND, either express or
// implied. See the LICENSE-MIT and LICENSE-APACHE files for the
// specific language governing permissions and limitations under
// each license.
//
// True single-pass BMFF C2PA signing: reads source once, writes output once,
// computes SHA-256 hash simultaneously during the write pass, then seek-patches
// the signed JUMBF.
//
// Standard flow (save_to_stream for BMFF) does 7 passes:
//   1. Copy source -> intermediate stream (full copy)
//   2. Parse BMFF tree + build exclusion map
//   3. Write intermediate + placeholder JUMBF -> output (full copy + parse)
//   4. Hash entire output with BMFF exclusions (full read + parse -- BOTTLENECK)
//   5. Regenerate JUMBF with real hash
//   6. COSE Sign1
//   7. Re-copy intermediate + signed JUMBF -> output (full copy)
//
// Single-pass flow:
//   1. Parse source BMFF tree (headers only -- O(num_boxes), negligible I/O)
//   2. Pre-compute: JUMBF placeholder, insertion point, output layout, exclusion
//      ranges, and all absolute-offset patches (stco/co64/iloc/tfhd/tfra/saio)
//   3. ONE PASS: read source -> write dest, inserting JUMBF at the right offset,
//      applying offset patches in-flight, feeding non-excluded bytes to SHA-256
//      hasher as they flow through
//   4. Sign (in-memory, ~1ms)
//   5. Seek-patch JUMBF region with signed version (O(1))

use std::collections::HashMap;
use std::io::{Read, Seek, SeekFrom, Write};

use atree::{Arena, Token};
use byteorder::{BigEndian, ReadBytesExt};
use uuid::Uuid;

use crate::{
    assertion::AssertionBase,
    assertions::{BmffHash, DataMap, ExclusionsMap},
    asset_handlers::bmff_io::{
        build_bmff_tree, get_uuid_token, read_bmff_ftyp_box, write_c2pa_box, BoxInfo, BoxType,
        C2PA_UUID, MANIFEST,
    },
    error::{Error, Result},
    fast_sign_common::{copy_with_patches, SourcePatch, StreamingHasher, JUMBF_MANIFEST_NAME},
    jumbf_io::is_bmff_format,
    store::Store,
    utils::{
        hash_utils::HashRange,
        io_utils::stream_len,
        mime::format_to_mime,
        patch::patch_bytes,
    },
    Builder, Signer,
};

/// Size of a standard BMFF box header (4-byte size + 4-byte type).
const HEADER_SIZE: u64 = 8;
/// Size of the FullBox prefix (version + flags) that follows the header.
const FULLBOX_PREFIX_SIZE: u64 = 4;

// --- Output Plan ------------------------------------------------------------

/// Pre-computed output layout: describes exactly what bytes go where in the
/// output file, enabling a single sequential pass.
struct OutputPlan {
    /// Ordered list of segments to write.
    segments: Vec<BmffOutputSegment>,
    /// Absolute byte offset in the output where the JUMBF data starts.
    jumbf_data_offset: u64,
    /// Total output file size.
    output_size: u64,
    /// The C2PA uuid box bytes (header + uuid + version/flags + purpose + merkle_offset + JUMBF).
    c2pa_box: Vec<u8>,
    /// Byte offset adjustment for absolute offsets in the file.
    offset_adjust: i64,
    /// Source offset where the JUMBF insertion happens.
    insertion_point: u64,
    /// Size of the existing C2PA box being replaced (0 if fresh insertion).
    existing_c2pa_size: u64,
}

/// BMFF-specific output segment. Uses a dedicated C2paBox variant because
/// the C2PA uuid box bytes are stored in the OutputPlan, not inline.
#[derive(Debug, Clone)]
enum BmffOutputSegment {
    /// Copy bytes from source file at [offset..offset+length).
    SourceRange { offset: u64, length: u64 },
    /// Write the C2PA uuid box (pre-computed bytes stored in OutputPlan).
    C2paBox,
}

/// Plan the output layout given the source BMFF tree.
fn plan_output(
    source_size: u64,
    bmff_tree: &Arena<BoxInfo>,
    bmff_map: &HashMap<String, Vec<Token>>,
    jumbf_bytes: &[u8],
) -> Result<OutputPlan> {
    let ftyp_token = bmff_map.get("/ftyp").ok_or(Error::UnsupportedType)?;
    let ftyp_info = &bmff_tree[ftyp_token[0]].data;
    let ftyp_end = ftyp_info.offset + ftyp_info.size;

    let (insertion_point, existing_c2pa_size) =
        if let Some(c2pa_token) = get_uuid_token(bmff_tree, bmff_map, &C2PA_UUID) {
            let uuid_info = &bmff_tree[c2pa_token].data;
            (uuid_info.offset, Some(uuid_info.size))
        } else {
            (ftyp_end, None)
        };

    // uuid box header + uuid bytes + version/flags + purpose + merkle_offset overhead
    let mut c2pa_box: Vec<u8> = Vec::with_capacity(jumbf_bytes.len() + 64);
    write_c2pa_box(&mut c2pa_box, jumbf_bytes, MANIFEST, &[], 0)?;
    let c2pa_box_size = c2pa_box.len() as u64;

    if source_size > i64::MAX as u64 {
        return Err(Error::InvalidAsset("file too large".to_string()));
    }
    let existing_size = existing_c2pa_size.unwrap_or(0);
    if existing_size > i64::MAX as u64 {
        return Err(Error::InvalidAsset("file too large".to_string()));
    }
    if c2pa_box_size > i64::MAX as u64 {
        return Err(Error::InvalidAsset("c2pa box too large".to_string()));
    }
    let offset_adjust: i64 = c2pa_box_size as i64 - existing_size as i64;
    let output_size_signed = source_size as i64 + offset_adjust;
    if output_size_signed < 0 {
        return Err(Error::InvalidAsset("invalid output size".to_string()));
    }
    let output_size = output_size_signed as u64;

    let mut segments = Vec::new();
    if insertion_point > 0 {
        segments.push(BmffOutputSegment::SourceRange {
            offset: 0,
            length: insertion_point,
        });
    }
    segments.push(BmffOutputSegment::C2paBox);
    let after_insertion = insertion_point + existing_size;
    if after_insertion < source_size {
        segments.push(BmffOutputSegment::SourceRange {
            offset: after_insertion,
            length: source_size - after_insertion,
        });
    }

    // JUMBF data is the last thing write_c2pa_box writes.
    let jumbf_data_offset = insertion_point + c2pa_box_size - jumbf_bytes.len() as u64;

    Ok(OutputPlan {
        segments,
        jumbf_data_offset,
        output_size,
        c2pa_box,
        offset_adjust,
        insertion_point,
        existing_c2pa_size: existing_size,
    })
}

// --- Exclusion Computation --------------------------------------------------

/// Compute BMFF hash exclusion ranges against the OUTPUT layout (pre-computed,
/// no I/O required).
fn compute_output_exclusions(
    bmff_tree: &Arena<BoxInfo>,
    bmff_map: &HashMap<String, Vec<Token>>,
    plan: &OutputPlan,
) -> Result<Vec<HashRange>> {
    let shift = plan.offset_adjust;
    let insertion_point = plan.insertion_point;
    let c2pa_box_size = plan.c2pa_box.len() as u64;
    let source_after = insertion_point + plan.existing_c2pa_size;

    let source_to_output = |src_offset: u64| -> u64 {
        if src_offset >= source_after {
            (src_offset as i64 + shift) as u64
        } else {
            src_offset
        }
    };

    let mut exclusions: Vec<HashRange> = Vec::new();
    let mut tl_offsets: Vec<u64> = Vec::new();

    for (path, tokens) in bmff_map.iter() {
        if path.matches('/').count() != 1 {
            continue;
        }
        for token in tokens {
            let box_info = &bmff_tree[*token].data;
            let output_offset = source_to_output(box_info.offset);

            if path == "/ftyp" {
                exclusions.push(HashRange::new(output_offset, box_info.size));
                continue;
            }
            if path == "/mfra" {
                exclusions.push(HashRange::new(output_offset, box_info.size));
                continue;
            }
            if path == "/uuid" && box_info.box_type == BoxType::UuidBox {
                if let Some(ref user_type) = box_info.user_type {
                    if user_type.as_slice() == C2PA_UUID {
                        // Old C2PA box being replaced -- skip, we add the new one below
                        continue;
                    }
                }
            }
            tl_offsets.push(output_offset);
        }
    }

    // The new C2PA uuid box
    exclusions.push(HashRange::new(insertion_point, c2pa_box_size));

    // BMFF v2 offset markers for non-excluded top-level boxes
    tl_offsets.sort();
    for tl_start in &tl_offsets {
        let mut hr = HashRange::new(*tl_start, 1);
        hr.set_bmff_offset(*tl_start);
        exclusions.push(hr);
    }

    Ok(exclusions)
}

// --- Offset Patches ---------------------------------------------------------

/// Collect all absolute-offset patches needed from the source BMFF tree.
///
/// These are stco, co64, iloc, tfhd, tfra, and saio entries that contain
/// absolute file offsets which shift when the C2PA box is inserted/replaced.
fn collect_offset_patches<R: Read + Seek>(
    source: &mut R,
    bmff_tree: &Arena<BoxInfo>,
    bmff_map: &HashMap<String, Vec<Token>>,
    adjust: i64,
) -> Result<Vec<SourcePatch>> {
    if adjust == 0 {
        return Ok(Vec::new());
    }

    let mut patches = Vec::new();

    // stco: 32-bit chunk offsets
    if let Some(stco_list) = bmff_map.get("/moov/trak/mdia/minf/stbl/stco") {
        for stco_token in stco_list {
            let box_info = &bmff_tree[*stco_token].data;
            source.seek(SeekFrom::Start(box_info.offset + HEADER_SIZE + FULLBOX_PREFIX_SIZE))?;
            let entry_count = source.read_u32::<BigEndian>()?;
            let header_overhead = HEADER_SIZE + FULLBOX_PREFIX_SIZE + 4; // + entry_count field
            if (entry_count as u64) * 4 > box_info.size.saturating_sub(header_overhead) {
                return Err(Error::InvalidAsset("stco entry_count exceeds box size".to_string()));
            }
            let entries_start = source.stream_position()?;
            for i in 0..entry_count {
                patches.push(SourcePatch {
                    source_offset: entries_start + (i as u64) * 4,
                    field_size: 4,
                    adjust,
                });
            }
        }
    }

    // co64: 64-bit chunk offsets
    if let Some(co64_list) = bmff_map.get("/moov/trak/mdia/minf/stbl/co64") {
        for co64_token in co64_list {
            let box_info = &bmff_tree[*co64_token].data;
            source.seek(SeekFrom::Start(box_info.offset + HEADER_SIZE + FULLBOX_PREFIX_SIZE))?;
            let entry_count = source.read_u32::<BigEndian>()?;
            let header_overhead = HEADER_SIZE + FULLBOX_PREFIX_SIZE + 4;
            if (entry_count as u64) * 8 > box_info.size.saturating_sub(header_overhead) {
                return Err(Error::InvalidAsset("co64 entry_count exceeds box size".to_string()));
            }
            let entries_start = source.stream_position()?;
            for i in 0..entry_count {
                patches.push(SourcePatch {
                    source_offset: entries_start + (i as u64) * 8,
                    field_size: 8,
                    adjust,
                });
            }
        }
    }

    // iloc: item location offsets (HEIF/AVIF)
    if let Some(iloc_list) = bmff_map.get("/meta/iloc") {
        for iloc_token in iloc_list {
            let box_info = &bmff_tree[*iloc_token].data;
            source.seek(SeekFrom::Start(box_info.offset + HEADER_SIZE))?;
            let version = source.read_u8()?;
            let _flags = {
                let mut buf = [0u8; 3];
                source.read_exact(&mut buf)?;
                u32::from_be_bytes([0, buf[0], buf[1], buf[2]])
            };

            let mut iloc_header = [0u8; 2];
            source.read_exact(&mut iloc_header)?;
            let offset_size = (iloc_header[0] & 0xf0) >> 4;
            let length_size = iloc_header[0] & 0x0f;
            let base_offset_size = (iloc_header[1] & 0xf0) >> 4;
            let index_size = iloc_header[1] & 0x0f;

            let item_count = if version < 2 {
                source.read_u16::<BigEndian>()? as u32
            } else {
                source.read_u32::<BigEndian>()?
            };

            // Validate item_count against remaining box bytes
            {
                let item_id_sz: u64 = if version < 2 { 2 } else { 4 };
                let cm_sz: u64 = if version == 1 || version == 2 { 2 } else { 0 };
                let dri_sz: u64 = 2;
                let min_bytes_per_item = item_id_sz + cm_sz + dri_sz + base_offset_size as u64 + 2; // +2 for extent_count
                let header_read = HEADER_SIZE + FULLBOX_PREFIX_SIZE + 2 + if version < 2 { 2 } else { 4 };
                if (item_count as u64) * min_bytes_per_item > box_info.size.saturating_sub(header_read) {
                    return Err(Error::InvalidAsset("iloc item_count exceeds box size".to_string()));
                }
            }

            for _ in 0..item_count {
                // item_id
                if version < 2 {
                    source.read_u16::<BigEndian>()?;
                } else {
                    source.read_u32::<BigEndian>()?;
                }
                // construction_method
                let construction_method = if version == 1 || version == 2 {
                    let mut cm = [0u8; 2];
                    source.read_exact(&mut cm)?;
                    cm[1] & 0x0f
                } else {
                    0
                };
                // data_reference_index
                source.read_u16::<BigEndian>()?;

                // base_offset
                let base_offset_pos = source.stream_position()?;
                let base_offset = match base_offset_size {
                    0 => 0u64,
                    4 => source.read_u32::<BigEndian>()? as u64,
                    8 => source.read_u64::<BigEndian>()?,
                    _ => {
                        return Err(Error::InvalidAsset(
                            "Bad BMFF iloc offset size".to_string(),
                        ))
                    }
                };

                if construction_method == 0 && base_offset_size == 4 {
                    patches.push(SourcePatch {
                        source_offset: base_offset_pos,
                        field_size: 4,
                        adjust,
                    });
                }
                if construction_method == 0 && base_offset_size == 8 {
                    patches.push(SourcePatch {
                        source_offset: base_offset_pos,
                        field_size: 8,
                        adjust,
                    });
                }

                // extents
                let extent_count = source.read_u16::<BigEndian>()?;
                {
                    let idx_sz: u64 = if (version == 1 || version == 2) && index_size > 0 { index_size as u64 } else { 0 };
                    let min_bytes_per_extent = idx_sz + offset_size as u64 + length_size as u64;
                    let pos_now = source.stream_position()?;
                    let box_end = box_info.offset + box_info.size;
                    if (extent_count as u64) * min_bytes_per_extent > box_end.saturating_sub(pos_now) {
                        return Err(Error::InvalidAsset("iloc extent_count exceeds box size".to_string()));
                    }
                }
                for _ in 0..extent_count {
                    // extent_index
                    if version == 1 || (version == 2 && index_size > 0) {
                        match index_size {
                            4 => {
                                source.read_u32::<BigEndian>()?;
                            }
                            8 => {
                                source.read_u64::<BigEndian>()?;
                            }
                            _ => {}
                        }
                    }
                    // extent_offset
                    let extent_offset_pos = source.stream_position()?;
                    let extent_offset = match offset_size {
                        0 => 0u64,
                        4 => source.read_u32::<BigEndian>()? as u64,
                        8 => source.read_u64::<BigEndian>()?,
                        _ => {
                            return Err(Error::InvalidAsset(
                                "Bad BMFF iloc extent_offset size".to_string(),
                            ))
                        }
                    };
                    // Adjust extent_offset if no base_offset and construction_method == 0
                    if construction_method == 0 && base_offset == 0 && extent_offset != 0 {
                        match offset_size {
                            4 | 8 => {
                                patches.push(SourcePatch {
                                    source_offset: extent_offset_pos,
                                    field_size: offset_size,
                                    adjust,
                                });
                            }
                            _ => {}
                        }
                    }
                    // extent_length
                    match length_size {
                        0 => {}
                        4 => {
                            source.read_u32::<BigEndian>()?;
                        }
                        8 => {
                            source.read_u64::<BigEndian>()?;
                        }
                        _ => {
                            return Err(Error::InvalidAsset(
                                "Bad BMFF iloc length size".to_string(),
                            ))
                        }
                    }
                }
            }
        }
    }

    // tfhd: track fragment header base_data_offset
    if let Some(tfhd_list) = bmff_map.get("/moof/traf/tfhd") {
        for tfhd_token in tfhd_list {
            let box_info = &bmff_tree[*tfhd_token].data;
            source.seek(SeekFrom::Start(box_info.offset + HEADER_SIZE))?;
            let _version = source.read_u8()?;
            let mut flag_buf = [0u8; 3];
            source.read_exact(&mut flag_buf)?;
            let tf_flags =
                u32::from_be_bytes([0, flag_buf[0], flag_buf[1], flag_buf[2]]);
            let _track_id = source.read_u32::<BigEndian>()?;

            if tf_flags & 1 == 1 {
                let bdo_pos = source.stream_position()?;
                patches.push(SourcePatch {
                    source_offset: bdo_pos,
                    field_size: 8,
                    adjust,
                });
            }
        }
    }

    // saio: sample auxiliary information offsets
    if let Some(saio_list) = bmff_map.get("/moov/trak/mdia/minf/stbl/saio") {
        for saio_token in saio_list {
            let box_info = &bmff_tree[*saio_token].data;
            source.seek(SeekFrom::Start(box_info.offset + HEADER_SIZE))?;
            let version = source.read_u8()?;
            let mut flag_buf = [0u8; 3];
            source.read_exact(&mut flag_buf)?;
            let flags = u32::from_be_bytes([0, flag_buf[0], flag_buf[1], flag_buf[2]]);
            if (flags & 1) == 1 {
                source.read_u32::<BigEndian>()?; // aux_info_type
                source.read_u32::<BigEndian>()?; // aux_info_type_parameter
            }
            let entry_count = source.read_u32::<BigEndian>()?;
            {
                let field_sz: u64 = if version == 0 { 4 } else { 8 };
                let header_overhead = HEADER_SIZE + FULLBOX_PREFIX_SIZE + if (flags & 1) == 1 { 8 } else { 0 } + 4;
                if (entry_count as u64) * field_sz > box_info.size.saturating_sub(header_overhead) {
                    return Err(Error::InvalidAsset("saio entry_count exceeds box size".to_string()));
                }
            }
            let entries_start = source.stream_position()?;
            for i in 0..entry_count {
                if version == 0 {
                    patches.push(SourcePatch {
                        source_offset: entries_start + (i as u64) * 4,
                        field_size: 4,
                        adjust,
                    });
                } else {
                    patches.push(SourcePatch {
                        source_offset: entries_start + (i as u64) * 8,
                        field_size: 8,
                        adjust,
                    });
                }
            }
        }
    }

    patches.sort_by_key(|p| p.source_offset);
    Ok(patches)
}

// --- Main Entry Point -------------------------------------------------------

/// True single-pass BMFF signing -- reads source once, writes output once.
///
/// 1. Parses the source BMFF tree (headers only, O(num_boxes))
/// 2. Pre-computes: JUMBF placeholder, insertion point, output exclusion ranges,
///    and all absolute-offset patches
/// 3. Streams source -> dest in one pass, inserting the C2PA box at the right
///    offset, applying offset patches in-flight, and simultaneously computing
///    the SHA-256 hash over non-excluded regions
/// 4. Signs the claim in-memory (~1ms)
/// 5. Seek-patches the JUMBF region with the signed version (O(1))
///
/// For non-BMFF formats, falls back to `Builder.sign()`.
pub fn sign_bmff_fast<R, W>(
    builder: &mut Builder,
    signer: &dyn Signer,
    format: &str,
    source: &mut R,
    dest: &mut W,
) -> Result<Vec<u8>>
where
    R: Read + Seek + Send,
    W: Write + Read + Seek + Send,
{
    let mime_format = format_to_mime(format);
    if !is_bmff_format(&mime_format) {
        return builder.sign(signer, format, source, dest);
    }

    let t_total = std::time::Instant::now();
    let settings = crate::settings::Settings::default();

    // -- Prepare builder + store --
    builder.definition.format.clone_from(&mime_format);
    if !builder.deterministic {
        builder.definition.instance_id = format!("xmp:iid:{}", Uuid::new_v4());
    }
    let deterministic = builder.deterministic;
    let mut store = builder.to_store()?;

    // -- Step 1: Parse source BMFF tree (headers only) --
    let t0 = std::time::Instant::now();
    let source_size = stream_len(source)?;
    source.rewind()?;

    let root_box = BoxInfo {
        path: "".to_string(),
        offset: 0,
        size: source_size,
        box_type: BoxType::Empty,
        parent: None,
        user_type: None,
        version: None,
        flags: None,
    };
    let (mut bmff_tree, root_token) = Arena::with_data(root_box);
    let mut bmff_map: HashMap<String, Vec<Token>> = HashMap::new();
    let ftyp = read_bmff_ftyp_box(source)?;
    source.rewind()?;
    let mut recursion_level: usize = 0;
    build_bmff_tree(source, source_size, &mut bmff_tree, &root_token, &mut bmff_map, &mut recursion_level, &ftyp)?;
    log::debug!(
        "[c2pa-fast-sign] parse_source_tree: {}ms",
        t0.elapsed().as_millis()
    );

    // -- Step 2: Build BmffHash assertion with placeholder hash --
    let t1 = std::time::Instant::now();
    let pc = store.provenance_claim_mut().ok_or(Error::ClaimEncoding)?;
    let alg = pc.alg().to_string();

    let mut bmff_hash = BmffHash::new(JUMBF_MANIFEST_NAME, &alg, None);
    {
        let exclusions = bmff_hash.exclusions_mut();
        let mut uuid_exc = ExclusionsMap::new("/uuid".to_owned());
        uuid_exc.data = Some(vec![DataMap {
            offset: HEADER_SIZE,
            value: C2PA_UUID.to_vec(),
        }]);
        exclusions.push(uuid_exc);
        exclusions.push(ExclusionsMap::new("/ftyp".to_owned()));
        exclusions.push(ExclusionsMap::new("/mfra".to_owned()));
    }
    if pc.version() < 2 {
        bmff_hash.set_bmff_version(2);
    }

    let hash_size = crate::fast_sign_common::placeholder_hash_size(&alg)?;
    let placeholder_hash = vec![0u8; hash_size];
    bmff_hash.set_hash(placeholder_hash);
    if deterministic {
        pc.add_assertion_with_salt(&bmff_hash, &crate::salt::NoSalt)?;
    } else {
        pc.add_assertion(&bmff_hash)?;
    }

    let placeholder_jumbf = store.to_jumbf_internal(signer.reserve_size())?;
    let jumbf_size = placeholder_jumbf.len();
    log::debug!(
        "[c2pa-fast-sign] build_placeholder_jumbf: {}ms (jumbf={}B)",
        t1.elapsed().as_millis(),
        jumbf_size
    );

    // -- Step 3: Plan output layout + compute exclusions + collect patches --
    let t2 = std::time::Instant::now();
    let plan = plan_output(source_size, &bmff_tree, &bmff_map, &placeholder_jumbf)?;
    let output_exclusions = compute_output_exclusions(&bmff_tree, &bmff_map, &plan)?;
    let offset_patches = collect_offset_patches(source, &bmff_tree, &bmff_map, plan.offset_adjust)?;
    log::debug!(
        "[c2pa-fast-sign] plan+exclusions+patches: {}ms (output={}B, adjust={}, {} excl, {} patches)",
        t2.elapsed().as_millis(),
        plan.output_size,
        plan.offset_adjust,
        output_exclusions.len(),
        offset_patches.len()
    );

    // -- Step 4: Single streaming pass -- write + patch + hash simultaneously --
    let t3 = std::time::Instant::now();
    let mut hasher = StreamingHasher::new(&alg, plan.output_size, output_exclusions)?;
    let hasher_action_count = hasher.actions.len();
    source.rewind()?;

    let mut total_source_bytes = 0u64;
    for segment in &plan.segments {
        match segment {
            BmffOutputSegment::SourceRange { offset, length } => {
                total_source_bytes += *length;
                copy_with_patches(
                    source,
                    dest,
                    &mut hasher,
                    *offset,
                    *length,
                    &offset_patches,
                )?;
            }
            BmffOutputSegment::C2paBox => {
                hasher.feed(&plan.c2pa_box);
                dest.write_all(&plan.c2pa_box)?;
            }
        }
    }
    dest.flush()?;
    let hash_value = hasher.finalize();
    log::debug!(
        "[c2pa-fast-sign] stream_write+hash: {}ms ({}KB source, {} patches, {} hasher_actions)",
        t3.elapsed().as_millis(),
        total_source_bytes / 1024,
        offset_patches.len(),
        hasher_action_count,
    );

    // -- Step 5: Update BmffHash with real hash, regenerate JUMBF --
    let t4 = std::time::Instant::now();
    let pc = store.provenance_claim_mut().ok_or(Error::ClaimEncoding)?;
    let mut real_bmff_hash = BmffHash::from_assertion(
        pc.bmff_hash_assertions()
            .first()
            .ok_or(Error::ClaimEncoding)?
            .assertion(),
    )?;
    real_bmff_hash.set_hash(hash_value);
    pc.update_bmff_hash(real_bmff_hash)?;

    let final_jumbf_unsigned = store.to_jumbf_internal(signer.reserve_size())?;
    if final_jumbf_unsigned.len() != jumbf_size {
        log::error!(
            "[c2pa-fast-sign] JUMBF size mismatch: expected {}, got {}",
            jumbf_size,
            final_jumbf_unsigned.len()
        );
        return Err(Error::JumbfCreationError);
    }
    log::debug!(
        "[c2pa-fast-sign] update_hash+regen_jumbf: {}ms",
        t4.elapsed().as_millis()
    );

    // -- Step 6: Sign the claim --
    let t5 = std::time::Instant::now();
    let pc = store.provenance_claim().ok_or(Error::ClaimEncoding)?;
    let sig = store.sign_claim(pc, signer, signer.reserve_size(), &settings)?;
    let sig_placeholder = Store::sign_claim_placeholder(pc, signer.reserve_size());
    log::debug!(
        "[c2pa-fast-sign] sign_claim: {}ms",
        t5.elapsed().as_millis()
    );

    // -- Step 7: Patch signature into JUMBF, seek-patch output --
    let mut final_jumbf = final_jumbf_unsigned;
    if sig_placeholder.len() != sig.len() {
        return Err(Error::CoseSigboxTooSmall);
    }
    patch_bytes(&mut final_jumbf, &sig_placeholder, &sig)
        .map_err(|_| Error::JumbfCreationError)?;
    if final_jumbf.len() != jumbf_size {
        log::error!(
            "[c2pa-fast-sign] JUMBF size mismatch after signing: expected {}, got {}",
            jumbf_size,
            final_jumbf.len()
        );
        return Err(Error::JumbfCreationError);
    }

    dest.seek(SeekFrom::Start(plan.jumbf_data_offset))?;
    dest.write_all(&final_jumbf)?;
    dest.flush()?;

    if let Some(pc_mut) = store.provenance_claim_mut() {
        pc_mut.set_signature_val(sig);
    }

    log::debug!(
        "[c2pa-fast-sign] total: {}ms",
        t_total.elapsed().as_millis()
    );

    Ok(final_jumbf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_plan_output_fresh_insertion() {
        let ftyp_box = BoxInfo {
            path: "/ftyp".to_string(),
            offset: 0,
            size: 24,
            box_type: BoxType::FtypBox,
            parent: None,
            user_type: None,
            version: None,
            flags: None,
        };
        let moov_box = BoxInfo {
            path: "/moov".to_string(),
            offset: 24,
            size: 76,
            box_type: BoxType::MoovBox,
            parent: None,
            user_type: None,
            version: None,
            flags: None,
        };
        let root_box = BoxInfo {
            path: "".to_string(),
            offset: 0,
            size: 100,
            box_type: BoxType::Empty,
            parent: None,
            user_type: None,
            version: None,
            flags: None,
        };

        let (mut tree, root_token) = Arena::with_data(root_box);
        let ftyp_token = root_token.append(&mut tree, ftyp_box);
        let moov_token = root_token.append(&mut tree, moov_box);

        let mut map: HashMap<String, Vec<Token>> = HashMap::new();
        map.entry("/ftyp".to_string()).or_default().push(ftyp_token);
        map.entry("/moov".to_string()).or_default().push(moov_token);

        let fake_jumbf = vec![0u8; 128];
        let plan = plan_output(100, &tree, &map, &fake_jumbf).unwrap();

        assert_eq!(plan.insertion_point, 24);
        assert_eq!(plan.existing_c2pa_size, 0);

        let c2pa_box_size = plan.c2pa_box.len() as u64;
        assert_eq!(plan.output_size, 100 + c2pa_box_size);

        assert_eq!(plan.segments.len(), 3);
        match &plan.segments[0] {
            BmffOutputSegment::SourceRange { offset, length } => {
                assert_eq!(*offset, 0);
                assert_eq!(*length, 24);
            }
            _ => panic!("Expected SourceRange"),
        }
        assert!(matches!(plan.segments[1], BmffOutputSegment::C2paBox));
        match &plan.segments[2] {
            BmffOutputSegment::SourceRange { offset, length } => {
                assert_eq!(*offset, 24);
                assert_eq!(*length, 76);
            }
            _ => panic!("Expected SourceRange"),
        }
    }
}
