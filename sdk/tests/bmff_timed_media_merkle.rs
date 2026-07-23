// Copyright 2026 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

// Unless required by applicable law or agreed to in writing, this software is
// distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY
// KIND, either express or implied. See the LICENSE-MIT and LICENSE-APACHE
// files for the specific language governing permissions and limitations under
// each license.

//! Characterization tests for the BMFF *timed-media, track-based Merkle*
//! verification path in [`BmffHash::verify_stream_hash`].
//!
//! This is the branch in `bmff_hash.rs` that enumerates tracks and reads
//! individual samples (historically via the third-party `mp4` crate's
//! `Mp4Reader::read_header` / `tracks()` / `read_sample()`), where a Merkle
//! map's `local_id` is a *track id* rather than an `mdat` index. It is a
//! verify-only, legacy BMFF-v2 interop path: no current signer emits it, so it
//! has no end-to-end coverage.
//!
//! These tests build minimal MP4s by hand and drive the path exclusively
//! through the public API, pinning the observable behavior (successful
//! verification of a valid asset, plus the exact error surface for malformed
//! inputs) so that a future reimplementation of the sample reader can be proven
//! equivalent.

#![allow(clippy::unwrap_used)]

use std::io::Cursor;

use c2pa::assertions::{BmffHash, ExclusionsMap, MerkleMap, VecByteBuf};
use serde_bytes::ByteBuf;
use sha2::{Digest, Sha256};

const C2PA_UUID: [u8; 16] = [
    0xd8, 0xfe, 0xc3, 0xd6, 0x1b, 0x0e, 0x48, 0x3c, 0x92, 0x97, 0x58, 0x28, 0x87, 0x7e, 0xc4, 0x81,
];

/// Builds a plain BMFF box: 4-byte big-endian size, 4-byte fourcc, payload.
fn build_box(fourcc: &[u8; 4], payload: &[u8]) -> Vec<u8> {
    let s = (8 + payload.len()) as u32;
    [&s.to_be_bytes()[..], fourcc.as_slice(), payload].concat()
}

/// Builds a BMFF FullBox: box header, 1-byte version, 3-byte flags, payload.
fn build_fullbox(fourcc: &[u8; 4], ver: u8, flags: u32, payload: &[u8]) -> Vec<u8> {
    let s = (12 + payload.len()) as u32;
    let vf = [
        ver,
        ((flags >> 16) & 0xff) as u8,
        ((flags >> 8) & 0xff) as u8,
        (flags & 0xff) as u8,
    ];
    [&s.to_be_bytes()[..], fourcc.as_slice(), &vf, payload].concat()
}

/// A single `stsc` entry as it appears on disk (first_sample is derived, not stored).
#[derive(Clone, Copy)]
struct StscEntry {
    first_chunk: u32,
    samples_per_chunk: u32,
    sample_description_index: u32,
}

/// Chunk offset table: either 32-bit (`stco`) or 64-bit (`co64`).
enum ChunkOffsets {
    Stco(Vec<u32>),
    Co64(Vec<u64>),
}

/// Sample size table: either a single fixed size, or one size per sample.
enum SampleSizes {
    Fixed(u32),
    Variable(Vec<u32>),
}

/// Description of a timed-media track to synthesize.
struct TrackSpec {
    track_id: u32,
    stsc: Vec<StscEntry>,
    sample_sizes: SampleSizes,
    // Chunk offsets are filled in by the assembler once the file layout is known,
    // so the spec only records whether to emit `stco` or `co64`.
    use_co64: bool,
}

fn build_stsc(entries: &[StscEntry]) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&(entries.len() as u32).to_be_bytes());
    for e in entries {
        p.extend_from_slice(&e.first_chunk.to_be_bytes());
        p.extend_from_slice(&e.samples_per_chunk.to_be_bytes());
        p.extend_from_slice(&e.sample_description_index.to_be_bytes());
    }
    build_fullbox(b"stsc", 0, 0, &p)
}

fn build_chunk_offsets(offsets: &ChunkOffsets) -> Vec<u8> {
    match offsets {
        ChunkOffsets::Stco(v) => {
            let mut p = Vec::new();
            p.extend_from_slice(&(v.len() as u32).to_be_bytes());
            for o in v {
                p.extend_from_slice(&o.to_be_bytes());
            }
            build_fullbox(b"stco", 0, 0, &p)
        }
        ChunkOffsets::Co64(v) => {
            let mut p = Vec::new();
            p.extend_from_slice(&(v.len() as u32).to_be_bytes());
            for o in v {
                p.extend_from_slice(&o.to_be_bytes());
            }
            build_fullbox(b"co64", 0, 0, &p)
        }
    }
}

fn build_stsz(sizes: &SampleSizes, sample_count: u32) -> Vec<u8> {
    match sizes {
        SampleSizes::Fixed(sz) => {
            let mut p = Vec::new();
            p.extend_from_slice(&sz.to_be_bytes());
            p.extend_from_slice(&sample_count.to_be_bytes());
            build_fullbox(b"stsz", 0, 0, &p)
        }
        SampleSizes::Variable(v) => {
            let mut p = Vec::new();
            p.extend_from_slice(&0u32.to_be_bytes()); // sample_size = 0 => per-sample table
            p.extend_from_slice(&(v.len() as u32).to_be_bytes());
            for s in v {
                p.extend_from_slice(&s.to_be_bytes());
            }
            build_fullbox(b"stsz", 0, 0, &p)
        }
    }
}

/// Builds the `stbl` for a track given a chunk-offset table (resolved once the
/// file layout is known).
fn build_stbl(track: &TrackSpec, sample_count: u32, offsets: &ChunkOffsets) -> Vec<u8> {
    // stsd with a single sample-entry child. The mp4 crate unconditionally reads
    // one child box after entry_count; an unrecognized codec fourcc is accepted
    // and skipped, which is all the offset/size math needs.
    let sample_entry = build_box(b"c2pv", &[0u8; 8]);
    let mut stsd_p = Vec::new();
    stsd_p.extend_from_slice(&1u32.to_be_bytes()); // entry_count
    stsd_p.extend_from_slice(&sample_entry);
    let stsd = build_fullbox(b"stsd", 0, 0, &stsd_p);

    // A single stts run covering every sample with a fixed delta. The mp4 crate's
    // read_sample() consults stts (via sample_time) and unwraps, so a valid asset
    // must supply a covering entry even though the delta is irrelevant to hashing.
    let stts = if sample_count == 0 {
        build_fullbox(b"stts", 0, 0, &0u32.to_be_bytes())
    } else {
        let mut p = Vec::new();
        p.extend_from_slice(&1u32.to_be_bytes()); // entry_count
        p.extend_from_slice(&sample_count.to_be_bytes()); // sample_count
        p.extend_from_slice(&1000u32.to_be_bytes()); // sample_delta
        build_fullbox(b"stts", 0, 0, &p)
    };

    let stsc = build_stsc(&track.stsc);
    let stsz = build_stsz(&track.sample_sizes, sample_count);
    let stco = build_chunk_offsets(offsets);
    build_box(b"stbl", &[stsd, stts, stsc, stsz, stco].concat())
}

fn build_trak(track: &TrackSpec, sample_count: u32, offsets: &ChunkOffsets) -> Vec<u8> {
    let mut tkhd_p = vec![0u8; 8]; // creation/modification time
    tkhd_p.extend_from_slice(&track.track_id.to_be_bytes());
    tkhd_p.extend_from_slice(&[0u8; 12]);
    tkhd_p.extend_from_slice(&[0u8; 4]);
    tkhd_p.extend_from_slice(&0x0100u16.to_be_bytes());
    tkhd_p.extend_from_slice(&[0u8; 2]);
    for v in [0x00010000u32, 0, 0, 0, 0x00010000, 0, 0, 0, 0x40000000] {
        tkhd_p.extend_from_slice(&v.to_be_bytes());
    }
    tkhd_p.extend_from_slice(&[0u8; 8]);
    let tkhd = build_fullbox(b"tkhd", 0, 1, &tkhd_p);

    let mut mdhd_p = vec![0u8; 8];
    mdhd_p.extend_from_slice(&1000u32.to_be_bytes());
    mdhd_p.extend_from_slice(&0u32.to_be_bytes());
    mdhd_p.extend_from_slice(&0x55c4u16.to_be_bytes());
    mdhd_p.extend_from_slice(&0u16.to_be_bytes());
    let mdhd = build_fullbox(b"mdhd", 0, 0, &mdhd_p);

    let mut hdlr_p = vec![0u8; 4];
    hdlr_p.extend_from_slice(b"vide");
    hdlr_p.extend_from_slice(&[0u8; 12]);
    hdlr_p.push(0);
    let hdlr = build_fullbox(b"hdlr", 0, 0, &hdlr_p);

    let stbl = build_stbl(track, sample_count, offsets);

    let vmhd = build_fullbox(
        b"vmhd",
        0,
        1,
        &[&0u16.to_be_bytes()[..], &[0u8; 6]].concat(),
    );
    let url_box = build_fullbox(b"url ", 0, 1, &[]);
    let dref = build_fullbox(b"dref", 0, 0, &[&1u32.to_be_bytes()[..], &url_box].concat());
    let dinf = build_box(b"dinf", &dref);
    let minf = build_box(b"minf", &[vmhd, dinf, stbl].concat());
    let mdia = build_box(b"mdia", &[mdhd, hdlr, minf].concat());
    build_box(b"trak", &[tkhd, mdia].concat())
}

fn build_mvhd() -> Vec<u8> {
    let mut mvhd_p = vec![0u8; 8];
    mvhd_p.extend_from_slice(&1000u32.to_be_bytes());
    mvhd_p.extend_from_slice(&0u32.to_be_bytes());
    mvhd_p.extend_from_slice(&0x00010000u32.to_be_bytes());
    mvhd_p.extend_from_slice(&0x0100u16.to_be_bytes());
    mvhd_p.extend_from_slice(&[0u8; 10]);
    for v in [0x00010000u32, 0, 0, 0, 0x00010000, 0, 0, 0, 0x40000000] {
        mvhd_p.extend_from_slice(&v.to_be_bytes());
    }
    mvhd_p.extend_from_slice(&[0u8; 24]);
    mvhd_p.extend_from_slice(&2u32.to_be_bytes());
    build_fullbox(b"mvhd", 0, 0, &mvhd_p)
}

/// Builds a C2PA `uuid` box carrying the "merkle" purpose and a BmffMerkleMap
/// CBOR record `{ uniqueId, localId, location }` (no proof `hashes` field).
fn build_merkle_uuid_box(unique_id: u64, local_id: u64, location: u64) -> Vec<u8> {
    // CBOR map(3): "uniqueId" => unique_id, "localId" => local_id, "location" => location.
    let mut cbor = vec![0xa3];
    let put_uint = |c: &mut Vec<u8>, v: u64| {
        if v < 24 {
            c.push(v as u8);
        } else if v < 256 {
            c.push(0x18);
            c.push(v as u8);
        } else {
            c.push(0x19);
            c.extend_from_slice(&(v as u16).to_be_bytes());
        }
    };
    cbor.extend_from_slice(&[0x68]);
    cbor.extend_from_slice(b"uniqueId");
    put_uint(&mut cbor, unique_id);
    cbor.extend_from_slice(&[0x67]);
    cbor.extend_from_slice(b"localId");
    put_uint(&mut cbor, local_id);
    cbor.extend_from_slice(&[0x68]);
    cbor.extend_from_slice(b"location");
    put_uint(&mut cbor, location);

    let mut payload = Vec::new();
    payload.extend_from_slice(&C2PA_UUID);
    payload.extend_from_slice(&[0u8; 4]); // version = 0, flags = 0
    payload.extend_from_slice(b"merkle\x00");
    payload.extend_from_slice(&cbor);
    build_box(b"uuid", &payload)
}

/// Assembles a complete single-track timed-media MP4 whose sample bytes are laid
/// out contiguously in a single `mdat`, one chunk per `stsc` run. Returns the
/// file bytes together with the per-chunk root hashes (SHA-256 over each chunk's
/// concatenated sample bytes) so the caller can populate a matching assertion.
fn build_single_track_asset(track: TrackSpec, samples: &[&[u8]]) -> (Vec<u8>, Vec<Vec<u8>>) {
    let sample_count = samples.len() as u32;

    // Group samples into chunks per the stsc runs. Since we use one chunk per
    // run with `samples_per_chunk` samples each, walk the samples accordingly.
    let mut chunk_sample_ranges: Vec<(usize, usize)> = Vec::new();
    let mut idx = 0usize;
    for (i, entry) in track.stsc.iter().enumerate() {
        let next_first_chunk = track
            .stsc
            .get(i + 1)
            .map(|e| e.first_chunk)
            .unwrap_or(entry.first_chunk + 1);
        let chunk_runs = next_first_chunk - entry.first_chunk;

        // Clamp to at least 1 for layout purposes so a deliberately malformed
        // `samples_per_chunk == 0` entry (written verbatim to disk by build_stsc)
        // does not stall this grouping loop.
        let spc = (entry.samples_per_chunk as usize).max(1);
        for _ in 0..chunk_runs {
            let start = idx;
            let end = (idx + spc).min(samples.len());
            chunk_sample_ranges.push((start, end));
            idx = end;
        }
    }
    // Any remaining samples belong to more chunks of the last run.
    if let Some(last) = track.stsc.last() {
        let spc = (last.samples_per_chunk as usize).max(1);
        while idx < samples.len() {
            let start = idx;
            let end = (idx + spc).min(samples.len());
            chunk_sample_ranges.push((start, end));
            idx = end;
        }
    }

    // Compute per-chunk root hashes.
    let mut roots = Vec::new();
    for (start, end) in &chunk_sample_ranges {
        let mut h = Sha256::new();
        for s in &samples[*start..*end] {
            h.update(s);
        }
        roots.push(h.finalize().to_vec());
    }

    // Build the front of the file with placeholder chunk offsets so we can learn
    // moov's length, then rebuild with the real offsets (same widths => stable).
    let ftyp = build_box(b"ftyp", b"isom\x00\x00\x00\x00isom");

    let placeholder_offsets = match track.use_co64 {
        true => ChunkOffsets::Co64(vec![0u64; chunk_sample_ranges.len()]),
        false => ChunkOffsets::Stco(vec![0u32; chunk_sample_ranges.len()]),
    };
    let moov_placeholder = build_box(
        b"moov",
        &[
            build_mvhd(),
            build_trak(&track, sample_count, &placeholder_offsets),
        ]
        .concat(),
    );

    // One C2PA merkle uuid box per chunk. The verifier maps each box's `location`
    // to chunk id `location + 1`, so emit them in ascending location order.
    let mut uuid_boxes = Vec::new();
    for location in 0..chunk_sample_ranges.len() as u64 {
        uuid_boxes.extend_from_slice(&build_merkle_uuid_box(0, track.track_id as u64, location));
    }

    let mdat_payload_offset = (ftyp.len() + uuid_boxes.len() + moov_placeholder.len() + 8) as u64;

    // Concatenate sample bytes and compute each chunk's absolute file offset.
    let mut mdat_payload = Vec::new();
    let mut chunk_file_offsets = Vec::new();
    for (start, end) in &chunk_sample_ranges {
        chunk_file_offsets.push(mdat_payload_offset + mdat_payload.len() as u64);
        for s in &samples[*start..*end] {
            mdat_payload.extend_from_slice(s);
        }
    }

    let real_offsets = match track.use_co64 {
        true => ChunkOffsets::Co64(chunk_file_offsets.clone()),
        false => ChunkOffsets::Stco(chunk_file_offsets.iter().map(|o| *o as u32).collect()),
    };
    let moov = build_box(
        b"moov",
        &[
            build_mvhd(),
            build_trak(&track, sample_count, &real_offsets),
        ]
        .concat(),
    );
    assert_eq!(
        moov.len(),
        moov_placeholder.len(),
        "moov length must be stable"
    );

    let mut file = Vec::new();
    file.extend_from_slice(&ftyp);
    file.extend_from_slice(&uuid_boxes);
    file.extend_from_slice(&moov);
    file.extend_from_slice(&build_box(b"mdat", &mdat_payload));

    (file, roots)
}

/// Builds a `BmffHash` assertion with a single track-based Merkle map.
fn track_merkle_assertion(local_id: usize, roots: &[Vec<u8>]) -> BmffHash {
    let mut bmff_hash = BmffHash::new("test", "sha256", None);
    bmff_hash.add_exclusions(&mut vec![ExclusionsMap::new("/uuid".to_owned())]);
    bmff_hash.set_merkle(vec![MerkleMap {
        unique_id: 0,
        local_id,
        count: roots.len(),
        alg: Some("sha256".into()),
        init_hash: None,
        hashes: VecByteBuf(roots.iter().map(|r| ByteBuf::from(r.clone())).collect()),
        fixed_block_size: None,
        variable_block_sizes: None,
    }]);
    bmff_hash
}

/// The happy path: a single track, single chunk, single sample. Verification
/// must succeed, proving `read_sample` reads the correct bytes and the computed
/// leaf hash matches the stored root.
#[test]
fn valid_single_sample_verifies() {
    let track = TrackSpec {
        track_id: 1,
        stsc: vec![StscEntry {
            first_chunk: 1,
            samples_per_chunk: 1,
            sample_description_index: 1,
        }],
        sample_sizes: SampleSizes::Variable(vec![23]),
        use_co64: false,
    };
    let sample: &[u8] = b"hello world sample data";
    let (file, roots) = build_single_track_asset(track, &[sample]);

    let bmff_hash = track_merkle_assertion(1, &roots);
    let mut reader = Cursor::new(file);
    bmff_hash
        .verify_stream_hash(&mut reader, Some("sha256"))
        .expect("valid timed-media asset should verify");
}

/// Multiple samples spread across multiple single-sample chunks, verifying the
/// per-chunk grouping and the `stsc` sample->chunk mapping over more than one
/// chunk.
#[test]
fn valid_multi_chunk_verifies() {
    let track = TrackSpec {
        track_id: 1,
        stsc: vec![StscEntry {
            first_chunk: 1,
            samples_per_chunk: 1,
            sample_description_index: 1,
        }],
        sample_sizes: SampleSizes::Variable(vec![5, 7, 3]),
        use_co64: false,
    };
    let samples: [&[u8]; 3] = [b"aaaaa", b"bbbbbbb", b"ccc"];
    let (file, roots) = build_single_track_asset(track, &samples);
    assert_eq!(roots.len(), 3, "expected one chunk per sample");

    let bmff_hash = track_merkle_assertion(1, &roots);
    let mut reader = Cursor::new(file);
    bmff_hash
        .verify_stream_hash(&mut reader, Some("sha256"))
        .expect("multi-chunk asset should verify");
}

/// Several samples packed into a single chunk (`samples_per_chunk > 1`). The
/// chunk root hashes the concatenation of every sample in the chunk, exercising
/// the intra-chunk offset accumulation.
#[test]
fn valid_multi_sample_single_chunk_verifies() {
    let track = TrackSpec {
        track_id: 1,
        stsc: vec![StscEntry {
            first_chunk: 1,
            samples_per_chunk: 3,
            sample_description_index: 1,
        }],
        sample_sizes: SampleSizes::Variable(vec![4, 6, 2]),
        use_co64: false,
    };
    let samples: [&[u8]; 3] = [b"wxyz", b"uvwxyz", b"pq"];
    let (file, roots) = build_single_track_asset(track, &samples);
    assert_eq!(roots.len(), 1, "all samples belong to one chunk");

    let bmff_hash = track_merkle_assertion(1, &roots);
    let mut reader = Cursor::new(file);
    bmff_hash
        .verify_stream_hash(&mut reader, Some("sha256"))
        .expect("multi-sample single-chunk asset should verify");
}

/// 64-bit chunk offsets (`co64`) rather than 32-bit (`stco`).
#[test]
fn valid_co64_offsets_verify() {
    let track = TrackSpec {
        track_id: 1,
        stsc: vec![StscEntry {
            first_chunk: 1,
            samples_per_chunk: 1,
            sample_description_index: 1,
        }],
        sample_sizes: SampleSizes::Variable(vec![9, 9]),
        use_co64: true,
    };
    let samples: [&[u8]; 2] = [b"123456789", b"987654321"];
    let (file, roots) = build_single_track_asset(track, &samples);

    let bmff_hash = track_merkle_assertion(1, &roots);
    let mut reader = Cursor::new(file);
    bmff_hash
        .verify_stream_hash(&mut reader, Some("sha256"))
        .expect("co64 asset should verify");
}

/// A fixed sample size (`stsz.sample_size > 0`, empty per-sample table) instead
/// of a variable table.
#[test]
fn valid_fixed_sample_size_verifies() {
    let track = TrackSpec {
        track_id: 1,
        stsc: vec![StscEntry {
            first_chunk: 1,
            samples_per_chunk: 2,
            sample_description_index: 1,
        }],
        sample_sizes: SampleSizes::Fixed(4),
        use_co64: false,
    };
    let samples: [&[u8]; 2] = [b"aaaa", b"bbbb"];
    let (file, roots) = build_single_track_asset(track, &samples);

    let bmff_hash = track_merkle_assertion(1, &roots);
    let mut reader = Cursor::new(file);
    bmff_hash
        .verify_stream_hash(&mut reader, Some("sha256"))
        .expect("fixed sample size asset should verify");
}

/// Two `stsc` runs (e.g. first chunk holds 2 samples, later chunks hold 1),
/// exercising the run-length expansion of `first_sample` across entries.
#[test]
fn valid_multi_stsc_run_verifies() {
    let track = TrackSpec {
        track_id: 1,
        stsc: vec![
            StscEntry {
                first_chunk: 1,
                samples_per_chunk: 2,
                sample_description_index: 1,
            },
            StscEntry {
                first_chunk: 2,
                samples_per_chunk: 1,
                sample_description_index: 1,
            },
        ],
        sample_sizes: SampleSizes::Variable(vec![3, 3, 5, 7]),
        use_co64: false,
    };
    // Chunk 1: samples 0,1 (per first run); chunk 2: sample 2; chunk 3: sample 3.
    let samples: [&[u8]; 4] = [b"aaa", b"bbb", b"ccccc", b"ddddddd"];
    let (file, roots) = build_single_track_asset(track, &samples);
    assert_eq!(roots.len(), 3, "expected 3 chunks from the two stsc runs");

    let bmff_hash = track_merkle_assertion(1, &roots);
    let mut reader = Cursor::new(file);
    bmff_hash
        .verify_stream_hash(&mut reader, Some("sha256"))
        .expect("multi-stsc-run asset should verify");
}

/// A tampered sample (byte flipped after the roots were computed) must fail with
/// a hash mismatch, confirming the sample bytes actually feed the Merkle check.
#[test]
fn tampered_sample_fails_hash() {
    let track = TrackSpec {
        track_id: 1,
        stsc: vec![StscEntry {
            first_chunk: 1,
            samples_per_chunk: 1,
            sample_description_index: 1,
        }],
        sample_sizes: SampleSizes::Variable(vec![8]),
        use_co64: false,
    };
    let sample: &[u8] = b"original";
    let (mut file, roots) = build_single_track_asset(track, &[sample]);
    // Flip the last byte of the file (inside the mdat sample payload).
    let last = file.len() - 1;
    file[last] ^= 0xff;

    let bmff_hash = track_merkle_assertion(1, &roots);
    let mut reader = Cursor::new(file);
    let err = bmff_hash
        .verify_stream_hash(&mut reader, Some("sha256"))
        .unwrap_err();
    assert!(
        matches!(err, c2pa::Error::HashMismatch(_)),
        "expected HashMismatch, got: {err:?}"
    );
}

/// A Merkle map whose `local_id` matches no track id must be rejected.
#[test]
fn unknown_track_local_id_is_rejected() {
    let track = TrackSpec {
        track_id: 1,
        stsc: vec![StscEntry {
            first_chunk: 1,
            samples_per_chunk: 1,
            sample_description_index: 1,
        }],
        sample_sizes: SampleSizes::Variable(vec![4]),
        use_co64: false,
    };
    let sample: &[u8] = b"data";
    let (file, roots) = build_single_track_asset(track, &[sample]);
    // Assertion references track id 9, which does not exist.
    let bmff_hash = track_merkle_assertion(9, &roots);
    let mut reader = Cursor::new(file);
    let err = bmff_hash
        .verify_stream_hash(&mut reader, Some("sha256"))
        .unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("Merkle location not found") || msg.contains("location"),
        "unexpected error: {msg}"
    );
}

/// An `stsc` box with zero entries (while `stsz` still reports a sample) must
/// surface as a clean error, not a panic. Built by zeroing the `stsc`
/// entry_count of an otherwise-valid asset so the map/leaf counts still line up
/// and the failure is reached inside the sample walk.
#[test]
fn empty_stsc_is_rejected() {
    let track = TrackSpec {
        track_id: 1,
        stsc: vec![StscEntry {
            first_chunk: 1,
            samples_per_chunk: 1,
            sample_description_index: 1,
        }],
        sample_sizes: SampleSizes::Variable(vec![4]),
        use_co64: false,
    };
    let (mut file, roots) = build_single_track_asset(track, &[b"aaaa"]);

    // Locate the stsc box and set its entry_count (12 bytes past the box start:
    // 4 size + 4 fourcc + 1 version + 3 flags) to zero.
    let pos = file
        .windows(4)
        .position(|w| w == b"stsc")
        .expect("stsc box present");
    let ec = pos + 4 + 4; // fourcc start -> past fourcc -> version/flags
    file[ec..ec + 4].copy_from_slice(&0u32.to_be_bytes());

    let bmff_hash = track_merkle_assertion(1, &roots);
    let mut reader = Cursor::new(file);
    let err = bmff_hash
        .verify_stream_hash(&mut reader, Some("sha256"))
        .unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("no stsc entries") || msg.contains("stsc"),
        "unexpected error: {msg}"
    );
}

/// A crafted `stsc` entry with `samples_per_chunk == 0` must be rejected without
/// a divide-by-zero panic.
#[test]
fn zero_samples_per_chunk_is_rejected() {
    let track = TrackSpec {
        track_id: 1,
        stsc: vec![StscEntry {
            first_chunk: 1,
            samples_per_chunk: 0,
            sample_description_index: 1,
        }],
        sample_sizes: SampleSizes::Fixed(4),
        use_co64: false,
    };
    // One sample so sample_count > 0 and the timed-media path reaches the chunk
    // mapping, where the zero divisor is caught. The root value is irrelevant
    // because rejection happens before any hashing.
    let (file, _roots) = build_single_track_asset(track, &[b"aaaa"]);
    let bmff_hash = track_merkle_assertion(1, &[vec![0u8; 32]]);
    let mut reader = Cursor::new(file);
    let err = bmff_hash
        .verify_stream_hash(&mut reader, Some("sha256"))
        .unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("samples_per_chunk") || msg.contains("stsc"),
        "unexpected error: {msg}"
    );
}

// --- Regression: CAI-12277 / VULN-35208 -----------------------------------
//
// A crafted MP4 with a malformed `emsg` box (a scheme_id_uri string with no
// null terminator inside the box) drove an integer underflow panic in the old
// third-party `mp4` crate's EmsgBox::read_box. The native reader never parses
// `emsg`, so the same input must now fail cleanly instead of panicking.

/// Builds the emsg-underflow MP4 from the ticket's proof-of-concept: an `emsg`
/// box whose 38-byte scheme_id_uri runs to the following box header, followed by
/// a C2PA merkle `uuid` box and a minimal `moov`.
fn build_emsg_crash_mp4() -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&build_box(b"ftyp", b"isom\x00\x00\x00\x00isom"));

    // emsg: declared size 50, body = version/flags (4) + 38 bytes of 0x41 with
    // no null terminator inside the box.
    let mut emsg = Vec::new();
    emsg.extend_from_slice(&50u32.to_be_bytes());
    emsg.extend_from_slice(b"emsg");
    emsg.push(0);
    emsg.extend_from_slice(&[0u8; 3]);
    emsg.extend_from_slice(&[0x41u8; 38]);
    f.extend_from_slice(&emsg);

    // C2PA merkle uuid box (localId 1, location 0).
    f.extend_from_slice(&build_merkle_uuid_box(0, 1, 0));

    // Minimal moov with one track and an empty stbl.
    let mvhd = build_fullbox(b"mvhd", 0, 0, &[0u8; 96]);
    let mut tkhd_p = vec![0u8; 8];
    tkhd_p.extend_from_slice(&1u32.to_be_bytes());
    tkhd_p.extend_from_slice(&[0u8; 76]);
    let tkhd = build_fullbox(b"tkhd", 0, 1, &tkhd_p);
    let stsd = build_fullbox(b"stsd", 0, 0, &0u32.to_be_bytes());
    let stts = build_fullbox(b"stts", 0, 0, &0u32.to_be_bytes());
    let stsc = build_fullbox(b"stsc", 0, 0, &0u32.to_be_bytes());
    let stsz = build_fullbox(b"stsz", 0, 0, &[0u8; 8]);
    let stco = build_fullbox(b"stco", 0, 0, &0u32.to_be_bytes());
    let stbl = build_box(b"stbl", &[stsd, stts, stsc, stsz, stco].concat());
    let minf = build_box(b"minf", &stbl);
    let mdia = build_box(b"mdia", &minf);
    let trak = build_box(b"trak", &[tkhd, mdia].concat());
    let moov = build_box(b"moov", &[mvhd, trak].concat());
    f.extend_from_slice(&moov);

    f.extend_from_slice(&build_box(b"mdat", &[0u8; 8]));
    f
}

/// The crafted `emsg` asset must return an error, not panic. (Before the native
/// reader, this input panicked with an integer underflow / capacity overflow.)
#[test]
fn crafted_emsg_does_not_panic() {
    let mut bmff_hash = BmffHash::new("test", "sha256", None);
    bmff_hash.add_exclusions(&mut vec![ExclusionsMap::new("/uuid".to_owned())]);
    bmff_hash.set_merkle(vec![MerkleMap {
        unique_id: 0,
        local_id: 1,
        count: 1,
        alg: Some("sha256".into()),
        init_hash: None,
        hashes: VecByteBuf(vec![ByteBuf::from(vec![0u8; 32])]),
        fixed_block_size: None,
        variable_block_sizes: None,
    }]);

    let mut reader = Cursor::new(build_emsg_crash_mp4());
    // Must not panic; the malformed asset is rejected with an error.
    let result = bmff_hash.verify_stream_hash(&mut reader, Some("sha256"));
    assert!(result.is_err(), "crafted emsg asset should be rejected");
}

/// A sample whose declared (fixed) size runs past the end of the stream must be
/// rejected before allocating, guarding against memory-amplification.
#[test]
fn oversized_sample_is_rejected() {
    let track = TrackSpec {
        track_id: 1,
        stsc: vec![StscEntry {
            first_chunk: 1,
            samples_per_chunk: 1,
            sample_description_index: 1,
        }],
        // Fixed sample size far larger than the file.
        sample_sizes: SampleSizes::Fixed(0xffff_ff00),
        use_co64: false,
    };
    let (file, roots) = build_single_track_asset(track, &[b"tiny"]);
    let bmff_hash = track_merkle_assertion(1, &roots);
    let mut reader = Cursor::new(file);
    let err = bmff_hash
        .verify_stream_hash(&mut reader, Some("sha256"))
        .unwrap_err();
    // Rejected cleanly (no OOM / panic).
    assert!(
        matches!(
            err,
            c2pa::Error::InvalidAsset(_) | c2pa::Error::HashMismatch(_)
        ),
        "expected a clean rejection, got: {err:?}"
    );
}

/// An `stco` box declaring far more entries than its size can hold must be
/// rejected at parse time, not drive a huge allocation.
#[test]
fn oversized_stco_entry_count_is_rejected() {
    let track = TrackSpec {
        track_id: 1,
        stsc: vec![StscEntry {
            first_chunk: 1,
            samples_per_chunk: 1,
            sample_description_index: 1,
        }],
        sample_sizes: SampleSizes::Variable(vec![4]),
        use_co64: false,
    };
    let (mut file, roots) = build_single_track_asset(track, &[b"data"]);

    // Overwrite the stco entry_count with a huge value.
    let pos = file
        .windows(4)
        .position(|w| w == b"stco")
        .expect("stco box present");
    let ec = pos + 4 + 4; // past fourcc + version/flags
    file[ec..ec + 4].copy_from_slice(&0xffff_ffffu32.to_be_bytes());

    let bmff_hash = track_merkle_assertion(1, &roots);
    let mut reader = Cursor::new(file);
    let err = bmff_hash
        .verify_stream_hash(&mut reader, Some("sha256"))
        .unwrap_err();
    assert!(
        matches!(
            err,
            c2pa::Error::InvalidAsset(_) | c2pa::Error::HashMismatch(_)
        ),
        "expected a clean rejection, got: {err:?}"
    );
}
