// Copyright 2026 Adobe. All rights reserved.
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

use std::{
    fs,
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use c2pa::{
    format_from_path,
    live_video::{Ed25519SessionKey, LiveVideoSigner, LiveVideoVsiSigner},
    Signer,
};

/// Signs a sequence of media segments using the per-segment C2PA Manifest Box method (§19.3).
///
/// Segments are discovered by resolving `segments_glob` relative to `segments_dir` and processed
/// in natural (numeric-aware) filename order. Signed files are written to `output_dir` preserving
/// file names.
///
/// If `init_path` is provided, the init segment is also signed and written to `output_dir`.
/// Per §19.2.3, signing the init segment is optional.
pub fn sign_live_video(
    segments_dir: &Path,
    segments_glob: &Path,
    init_path: Option<&Path>,
    previous_segment_path: Option<&Path>,
    manifest_json: &str,
    output_dir: &Path,
    signer: &dyn Signer,
) -> Result<()> {
    fs::create_dir_all(output_dir)
        .with_context(|| format!("Failed to create output directory: {output_dir:?}"))?;

    let mut live_signer = LiveVideoSigner::from_manifest_json(manifest_json)
        .context("Failed to initialize live video signer from manifest")?;

    if let Some(prev_path) = previous_segment_path {
        let format = format_from_path(prev_path).unwrap_or_else(|| "video/mp4".to_string());
        let prev_data = fs::read(prev_path)
            .with_context(|| format!("Failed to read previous segment: {prev_path:?}"))?;
        live_signer
            .resume_from_segment(&prev_data, &format)
            .with_context(|| format!("Failed to read manifest ID from: {prev_path:?}"))?;
    }

    if let Some(init) = init_path {
        sign_init_segment(init, output_dir, &live_signer, signer)?;
    }

    let segment_paths = crate::live_video_common::collect_segments(segments_dir, segments_glob)?;

    if segment_paths.is_empty() {
        println!(
            "No segments found matching: {:?}",
            segments_dir.join(segments_glob)
        );
        return Ok(());
    }

    let mut signed_count = 0usize;
    let mut failed_count = 0usize;

    for segment_path in &segment_paths {
        match sign_segment(segment_path, output_dir, &mut live_signer, signer) {
            Ok(output_path) => {
                println!("Segment signed: {output_path:?}");
                signed_count += 1;
            }
            Err(e) => {
                eprintln!("Segment FAIL [{segment_path:?}]: {e}");
                failed_count += 1;
            }
        }
    }

    if failed_count > 0 {
        bail!(
            "Live video signing failed: {failed_count}/{} segment(s) failed",
            segment_paths.len()
        )
    }

    println!("\n{signed_count} segment(s) signed successfully.");
    Ok(())
}

fn sign_init_segment(
    init_path: &Path,
    output_dir: &Path,
    live_signer: &LiveVideoSigner,
    signer: &dyn Signer,
) -> Result<()> {
    let init_data = fs::read(init_path)
        .with_context(|| format!("Failed to read init segment: {init_path:?}"))?;
    let format = format_from_path(init_path).unwrap_or_else(|| "video/mp4".to_string());
    let signed_init = live_signer
        .sign_init_segment(&init_data, &format, signer)
        .with_context(|| format!("Failed to sign init segment: {init_path:?}"))?;
    let output_path = output_path_for(init_path, output_dir)?;
    fs::write(&output_path, &signed_init)
        .with_context(|| format!("Failed to write signed init segment: {output_path:?}"))?;
    println!("Init signed: {output_path:?}");
    Ok(())
}

fn sign_segment(
    segment_path: &Path,
    output_dir: &Path,
    live_signer: &mut LiveVideoSigner,
    signer: &dyn Signer,
) -> Result<PathBuf> {
    let segment_data =
        fs::read(segment_path).with_context(|| format!("Cannot read segment: {segment_path:?}"))?;

    let format = format_from_path(segment_path).unwrap_or_else(|| "video/mp4".to_string());

    let signed_bytes = live_signer
        .sign_media_segment(&segment_data, &format, signer)
        .with_context(|| format!("Failed to sign segment: {segment_path:?}"))?;

    let output_path = output_path_for(segment_path, output_dir)?;
    fs::write(&output_path, &signed_bytes)
        .with_context(|| format!("Failed to write signed segment: {output_path:?}"))?;

    Ok(output_path)
}

fn output_path_for(input_path: &Path, output_dir: &Path) -> Result<PathBuf> {
    let file_name = input_path
        .file_name()
        .context("input path has no file name")?;
    Ok(output_dir.join(file_name))
}

/// Arguments for [`sign_live_video_vsi`].
pub struct VsiSignArgs<'a> {
    pub segments_dir: &'a Path,
    pub segments_glob: &'a Path,
    pub init_path: &'a Path,
    pub previous_segment_path: Option<&'a Path>,
    pub manifest_json: &'a str,
    pub output_dir: &'a Path,
    pub session_key_path: &'a Path,
    pub signer: &'a dyn Signer,
    pub min_sequence_number: Option<u64>,
}

/// Signs a sequence of media segments using the Verifiable Segment Info method (§19.4).
///
/// The Ed25519 session key is loaded from `args.session_key_path` (raw 32-byte seed).
/// The init segment (required for §19.4) is always signed with the manifest signer
/// and carries a `c2pa.session-keys` assertion.
///
/// If `args.previous_segment_path` is provided, the sequence number is resumed from
/// the previous segment's `emsg` box.
///
/// If `args.min_sequence_number` is `None` and this is the first invocation (no
/// `previous_segment_path`), it's inferred from the first media segment's own
/// `moof/mfhd.sequence_number` rather than assumed to be 1 — real packagers commonly start a
/// live stream's sequence numbers elsewhere (e.g. FFmpeg continues counting from stream start,
/// not from when the signer attaches).
pub fn sign_live_video_vsi(args: VsiSignArgs) -> Result<()> {
    let VsiSignArgs {
        segments_dir,
        segments_glob,
        init_path,
        previous_segment_path,
        manifest_json,
        output_dir,
        session_key_path,
        signer,
        min_sequence_number,
    } = args;

    fs::create_dir_all(output_dir)
        .with_context(|| format!("Failed to create output directory: {output_dir:?}"))?;

    let session_key = load_ed25519_session_key(session_key_path)?;

    let segment_paths = crate::live_video_common::collect_segments(segments_dir, segments_glob)?;

    // Only meaningful on the first invocation: a resumed session (--previous-segment) restores
    // its counter from the already-signed init/segment instead, so any value works there.
    let min_sequence_number = match min_sequence_number {
        Some(n) => n,
        None if previous_segment_path.is_some() => 1,
        None => infer_min_sequence_number(segment_paths.first())?,
    };

    let mut vsi_signer = LiveVideoVsiSigner::from_signing_key(
        manifest_json,
        signer,
        session_key,
        b"session-key-1".to_vec(),
        min_sequence_number,
        3600,
    )
    .context("Failed to initialize VSI signer")?;

    if let Some(prev_path) = previous_segment_path {
        // Resuming an existing session: restore state from previously signed outputs.
        // Re-signing the init would produce a new UUID, breaking manifestId continuity
        // across segments per §19.4.
        let prev_data = fs::read(prev_path)
            .with_context(|| format!("Failed to read previous segment: {prev_path:?}"))?;
        vsi_signer
            .resume_from_segment(&prev_data)
            .with_context(|| format!("Failed to resume from segment: {prev_path:?}"))?;

        let signed_init_path = output_path_for(init_path, output_dir)?;
        let signed_init_data = fs::read(&signed_init_path).with_context(|| {
            format!(
                "Failed to read signed init segment from output dir: {signed_init_path:?}. \
                 Run without --previous-segment first to sign the init segment."
            )
        })?;
        let format = format_from_path(init_path).unwrap_or_else(|| "video/mp4".to_string());
        vsi_signer
            .restore_manifest_id_from_signed_init(&signed_init_data, &format)
            .with_context(|| {
                format!("Failed to restore manifest ID from signed init: {signed_init_path:?}")
            })?;
    } else {
        // First invocation: sign the init segment and capture its manifest ID.
        sign_vsi_init_segment(init_path, output_dir, &mut vsi_signer, signer)?;
    }

    if segment_paths.is_empty() {
        println!(
            "No segments found matching: {:?}",
            segments_dir.join(segments_glob)
        );
        return Ok(());
    }

    let mut signed_count = 0usize;
    let mut failed_count = 0usize;

    for segment_path in &segment_paths {
        match sign_vsi_segment(segment_path, output_dir, &mut vsi_signer) {
            Ok(output_path) => {
                println!("Segment signed (VSI): {output_path:?}");
                signed_count += 1;
            }
            Err(e) => {
                eprintln!("Segment FAIL [{segment_path:?}]: {e}");
                failed_count += 1;
            }
        }
    }

    if failed_count > 0 {
        bail!(
            "VSI signing failed: {failed_count}/{} segment(s) failed",
            segment_paths.len()
        )
    }

    println!("\n{signed_count} segment(s) signed successfully (VSI).");
    Ok(())
}

fn sign_vsi_init_segment(
    init_path: &Path,
    output_dir: &Path,
    vsi_signer: &mut LiveVideoVsiSigner,
    signer: &dyn Signer,
) -> Result<()> {
    let init_data = fs::read(init_path)
        .with_context(|| format!("Failed to read init segment: {init_path:?}"))?;
    let format = format_from_path(init_path).unwrap_or_else(|| "video/mp4".to_string());
    let signed_init = vsi_signer
        .sign_init_segment(&init_data, &format, signer)
        .with_context(|| format!("Failed to sign init segment: {init_path:?}"))?;
    let output_path = output_path_for(init_path, output_dir)?;
    fs::write(&output_path, &signed_init)
        .with_context(|| format!("Failed to write signed init segment: {output_path:?}"))?;
    println!("Init signed (VSI): {output_path:?}");
    Ok(())
}

fn sign_vsi_segment(
    segment_path: &Path,
    output_dir: &Path,
    vsi_signer: &mut LiveVideoVsiSigner,
) -> Result<PathBuf> {
    let segment_data =
        fs::read(segment_path).with_context(|| format!("Cannot read segment: {segment_path:?}"))?;

    let signed_bytes = vsi_signer
        .sign_media_segment(&segment_data)
        .with_context(|| format!("Failed to sign segment: {segment_path:?}"))?;

    let output_path = output_path_for(segment_path, output_dir)?;
    fs::write(&output_path, &signed_bytes)
        .with_context(|| format!("Failed to write signed segment: {output_path:?}"))?;

    Ok(output_path)
}

fn load_ed25519_session_key(path: &Path) -> Result<Ed25519SessionKey> {
    let bytes =
        fs::read(path).with_context(|| format!("Failed to read session key file: {path:?}"))?;
    if bytes.len() != 32 {
        bail!(
            "Session key file must contain exactly 32 bytes (Ed25519 seed), got {}",
            bytes.len()
        );
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes);
    Ok(Ed25519SessionKey::from_bytes(&seed))
}

/// Infers `minSequenceNumber` from `first_segment`'s own `moof/mfhd.sequence_number`, falling
/// back to 1 if there's no segment yet or it has no `moof` box. `sign_media_segment` cross-checks
/// every segment's own `mfhd.sequence_number` against the signer's counter (§19.4.1) and errors
/// on drift, so this must match the very first segment that's about to be signed.
fn infer_min_sequence_number(first_segment: Option<&PathBuf>) -> Result<u64> {
    let Some(path) = first_segment else {
        return Ok(1);
    };
    let data = fs::read(path).with_context(|| format!("Cannot read segment: {path:?}"))?;
    Ok(c2pa::live_video::moof_sequence_number(&data)
        .map(u64::from)
        .unwrap_or(1))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn output_path_for_preserves_file_name() {
        let dir = tempfile::tempdir().unwrap();
        let input = PathBuf::from("/some/path/seg_001.m4s");
        let result = output_path_for(&input, dir.path()).unwrap();
        assert_eq!(result.file_name().unwrap(), "seg_001.m4s");
        assert_eq!(result.parent().unwrap(), dir.path());
    }
}
