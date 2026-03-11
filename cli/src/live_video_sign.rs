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
use c2pa::{format_from_path, live_video::LiveVideoSigner, Signer};

/// Signs a sequence of media segments using the per-segment C2PA Manifest Box method (§19.3).
///
/// Segments are discovered by resolving `segments_glob` relative to `segments_dir` and processed
/// in lexicographic order. Signed files are written to `output_dir` preserving file names.
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

    let segment_paths = collect_segments(segments_dir, segments_glob)?;

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
    let segment_data = fs::read(segment_path)
        .with_context(|| format!("Cannot read segment: {segment_path:?}"))?;

    let format = format_from_path(segment_path).unwrap_or_else(|| "video/mp4".to_string());

    let signed_bytes = live_signer
        .sign_media_segment(&segment_data, &format, signer)
        .with_context(|| format!("Failed to sign segment: {segment_path:?}"))?;

    let output_path = output_path_for(segment_path, output_dir)?;
    fs::write(&output_path, &signed_bytes)
        .with_context(|| format!("Failed to write signed segment: {output_path:?}"))?;

    Ok(output_path)
}

fn collect_segments(base_dir: &Path, segments_glob: &Path) -> Result<Vec<PathBuf>> {
    let seg_glob = base_dir.join(segments_glob);
    let seg_glob_str = seg_glob
        .to_str()
        .context("segment glob path is not valid UTF-8")?;

    let mut paths: Vec<PathBuf> = glob::glob(seg_glob_str)
        .context("invalid segment glob pattern")?
        .filter_map(|r| r.ok())
        .collect();

    paths.sort();
    Ok(paths)
}

fn output_path_for(input_path: &Path, output_dir: &Path) -> Result<PathBuf> {
    let file_name = input_path
        .file_name()
        .context("input path has no file name")?;
    Ok(output_dir.join(file_name))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use std::fs;

    use tempfile::TempDir;

    use super::*;

    fn write_temp_file(dir: &TempDir, name: &str, content: &[u8]) -> PathBuf {
        let path = dir.path().join(name);
        fs::write(&path, content).unwrap();
        path
    }

    #[test]
    fn collect_segments_returns_sorted_paths() {
        let dir = tempfile::tempdir().unwrap();
        write_temp_file(&dir, "seg_003.m4s", b"x");
        write_temp_file(&dir, "seg_001.m4s", b"x");
        write_temp_file(&dir, "seg_002.m4s", b"x");

        let segments = collect_segments(dir.path(), Path::new("seg_*.m4s")).unwrap();

        let names: Vec<_> = segments
            .iter()
            .map(|p| p.file_name().unwrap().to_str().unwrap())
            .collect();
        assert_eq!(names, ["seg_001.m4s", "seg_002.m4s", "seg_003.m4s"]);
    }

    #[test]
    fn collect_segments_returns_empty_when_no_match() {
        let dir = tempfile::tempdir().unwrap();

        let segments = collect_segments(dir.path(), Path::new("seg_*.m4s")).unwrap();

        assert!(segments.is_empty());
    }

    #[test]
    fn output_path_for_preserves_file_name() {
        let dir = tempfile::tempdir().unwrap();
        let input = PathBuf::from("/some/path/seg_001.m4s");
        let result = output_path_for(&input, dir.path()).unwrap();
        assert_eq!(result.file_name().unwrap(), "seg_001.m4s");
        assert_eq!(result.parent().unwrap(), dir.path());
    }
}
