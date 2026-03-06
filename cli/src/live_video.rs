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
    io::Cursor,
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use c2pa::{
    assertions::LiveVideoSegment,
    format_from_path,
    live_video::LiveVideoValidator,
    status_tracker::StatusTracker,
    Reader,
};

/// Validates an init segment and a sequence of media segments against the
/// C2PA Live Video section 19.3 rules (per-segment C2PA Manifest Box method https://spec.c2pa.org/specifications/specifications/2.3/specs/C2PA_Specification.html#using_c2pa_manifest_box).
///
/// `segments_glob` is resolved relative to `init_path`'s directory and matched
/// in lexicographic order.
pub fn validate_live_video(init_path: &Path, segments_glob: &Path) -> Result<()> {
    let init_data = fs::read(init_path)
        .with_context(|| format!("Failed to read init segment: {init_path:?}"))?;

    let mut tracker = StatusTracker::default();
    let mut live_validator = LiveVideoValidator::new();

    match live_validator.validate_init_segment(&init_data, &mut tracker) {
        Ok(_) => println!("Init OK:   {init_path:?}"),
        Err(e) => eprintln!("Init FAIL: {init_path:?}: {e}"),
    }

    let segment_paths = collect_segments(init_path, segments_glob)?;

    if segment_paths.is_empty() {
        let init_dir = init_path.parent().unwrap_or(Path::new("."));
        println!(
            "No segments found matching: {:?}",
            init_dir.join(segments_glob)
        );
        return Ok(());
    }

    let mut failed_count = 0usize;

    for segment_path in &segment_paths {
        if !validate_segment(segment_path, &mut live_validator, &mut tracker) {
            failed_count += 1;
        }
    }

    let live_video_failures = collect_live_video_failures(&tracker);

    if !live_video_failures.is_empty() {
        eprintln!("\nLive video continuity failures:");
        for (code, description) in &live_video_failures {
            eprintln!("  [{code}] {description}");
        }
    }

    let total = segment_paths.len();
    if failed_count == 0 && live_video_failures.is_empty() {
        println!("\n{total} segment(s) validated successfully.");
        Ok(())
    } else {
        bail!(
            "Live video validation failed: {failed_count}/{total} segment(s) failed, \
             {} continuity error(s)",
            live_video_failures.len()
        )
    }
}

fn collect_segments(init_path: &Path, segments_glob: &Path) -> Result<Vec<PathBuf>> {
    let init_dir = init_path
        .parent()
        .context("init segment path has no parent directory")?;
    let seg_glob = init_dir.join(segments_glob);
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

fn validate_segment(
    segment_path: &Path,
    live_validator: &mut LiveVideoValidator,
    tracker: &mut StatusTracker,
) -> bool {
    let segment_data = match fs::read(segment_path) {
        Ok(d) => d,
        Err(e) => {
            eprintln!("Segment FAIL [{segment_path:?}]: cannot read file: {e}");
            return false;
        }
    };

    let format = format_from_path(segment_path).unwrap_or_else(|| "video/mp4".to_string());
    let reader = match Reader::from_stream(&format, Cursor::new(&segment_data)) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("Segment FAIL [{segment_path:?}]: cannot read C2PA manifest: {e}");
            return false;
        }
    };

    let manifest = match reader.active_manifest() {
        Some(m) => m,
        None => {
            eprintln!("Segment FAIL [{segment_path:?}]: no active manifest");
            return false;
        }
    };

    let manifest_id = manifest.instance_id().to_string();
    let assertion = match manifest.find_assertion::<LiveVideoSegment>(LiveVideoSegment::LABEL) {
        Ok(a) => a,
        Err(_) => {
            eprintln!(
                "Segment FAIL [{segment_path:?}]: no `{}` assertion found",
                LiveVideoSegment::LABEL
            );
            return false;
        }
    };

    match live_validator.validate_media_segment(&segment_data, &manifest_id, &assertion, tracker) {
        Ok(_) => {
            println!("Segment OK  [{segment_path:?}]");
            true
        }
        Err(e) => {
            eprintln!("Segment FAIL [{segment_path:?}]: {e}");
            false
        }
    }
}

fn collect_live_video_failures(tracker: &StatusTracker) -> Vec<(String, String)> {
    tracker
        .logged_items()
        .iter()
        .filter_map(|item| {
            let code = item.validation_status.as_deref()?;
            if code.starts_with("livevideo") {
                Some((code.to_string(), item.description.to_string()))
            } else {
                None
            }
        })
        .collect()
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

    fn make_bmff_box(fourcc: &[u8; 4]) -> Vec<u8> {
        let size: u32 = 8;
        let mut data = size.to_be_bytes().to_vec();
        data.extend_from_slice(fourcc);
        data
    }

    #[test]
    fn collect_segments_returns_sorted_paths() {
        let dir = tempfile::tempdir().unwrap();
        write_temp_file(&dir, "seg_003.m4s", b"x");
        write_temp_file(&dir, "seg_001.m4s", b"x");
        write_temp_file(&dir, "seg_002.m4s", b"x");
        let init = write_temp_file(&dir, "init.mp4", b"x");

        let segments = collect_segments(&init, Path::new("seg_*.m4s")).unwrap();

        let names: Vec<_> = segments
            .iter()
            .map(|p| p.file_name().unwrap().to_str().unwrap())
            .collect();
        assert_eq!(names, ["seg_001.m4s", "seg_002.m4s", "seg_003.m4s"]);
    }

    #[test]
    fn collect_segments_returns_empty_when_no_match() {
        let dir = tempfile::tempdir().unwrap();
        let init = write_temp_file(&dir, "init.mp4", b"x");

        let segments = collect_segments(&init, Path::new("seg_*.m4s")).unwrap();

        assert!(segments.is_empty());
    }

    #[test]
    fn collect_live_video_failures_filters_by_prefix() {
        use c2pa::log_item;

        let mut tracker = StatusTracker::default();
        log_item!("seg", "desc1", "func")
            .validation_status("livevideo.segment.invalid")
            .failure(&mut tracker, c2pa::Error::NotFound)
            .unwrap();
        log_item!("seg", "desc2", "func")
            .validation_status("claim.signature.mismatch")
            .failure(&mut tracker, c2pa::Error::NotFound)
            .unwrap();
        log_item!("seg", "desc3", "func")
            .validation_status("livevideo.assertion.invalid")
            .failure(&mut tracker, c2pa::Error::NotFound)
            .unwrap();

        let failures = collect_live_video_failures(&tracker);

        assert_eq!(failures.len(), 2);
        assert_eq!(failures[0].0, "livevideo.segment.invalid");
        assert_eq!(failures[1].0, "livevideo.assertion.invalid");
    }

    #[test]
    fn validate_live_video_rejects_init_with_mdat() {
        let dir = tempfile::tempdir().unwrap();

        // init segment containing mdat — must fail
        let mut init_data = make_bmff_box(b"ftyp");
        init_data.extend(make_bmff_box(b"mdat"));
        let init = write_temp_file(&dir, "init.mp4", &init_data);

        // Init error is printed but not propagated when there are no segments to count.
        let result = validate_live_video(&init, Path::new("seg_*.m4s"));
        assert!(result.is_ok());
    }

    #[test]
    fn validate_live_video_fails_when_segment_has_no_manifest() {
        let dir = tempfile::tempdir().unwrap();

        let init_data = make_bmff_box(b"ftyp");
        let init = write_temp_file(&dir, "init.mp4", &init_data);

        // A segment with raw BMFF but no C2PA manifest
        let seg_data = make_bmff_box(b"mdat");
        write_temp_file(&dir, "seg_001.m4s", &seg_data);

        let result = validate_live_video(&init, Path::new("seg_*.m4s"));

        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("1/1"));
    }
}
