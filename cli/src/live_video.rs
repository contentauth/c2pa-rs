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
    sync::Arc,
};

use anyhow::{bail, Context, Result};
use c2pa::{
    assertions::{LiveVideoSegment, SessionKeys},
    format_from_path,
    live_video::LiveVideoValidator,
    status_tracker::StatusTracker,
    validation_results::validation_codes::{LIVEVIDEO_INIT_INVALID, LIVEVIDEO_SESSIONKEY_INVALID},
    Context as C2paContext, Manifest, Reader,
};

/// Which C2PA Live Video validation method the init segment advertises.
enum ValidationMethod {
    /// Section 19.3: each segment carries a C2PA Manifest Box with a `LiveVideoSegment` assertion.
    ManifestBox,
    /// Section 19.4: each segment carries a `COSE_Sign1` in an `emsg` box (Verifiable Segment Info).
    VerifiableSegmentInfo,
}

/// Validates an init segment and a sequence of media segments against C2PA Live Video rules.
///
/// The validation method (section 19.3 or 19.4) is detected automatically from the init
/// segment manifest:
/// - If the manifest contains a `c2pa.session-keys` assertion → section 19.4 (VSI).
/// - Otherwise → section 19.3 (per-segment C2PA Manifest Box).
///
/// `segments_glob` is resolved relative to `init_path`'s directory and matched
/// in natural (numeric-aware) filename order.
pub fn validate_live_video(
    context: &Arc<C2paContext>,
    init_path: &Path,
    segments_glob: &Path,
) -> Result<()> {
    let init_data = fs::read(init_path)
        .with_context(|| format!("Failed to read init segment: {init_path:?}"))?;

    let mut tracker = StatusTracker::default();
    let mut live_validator = LiveVideoValidator::new();

    match live_validator.validate_init_segment(&init_data, &mut tracker) {
        Ok(_) => println!("Init OK:   {init_path:?}"),
        Err(e) => eprintln!("Init FAIL: {init_path:?}: {e}"),
    }

    let method = detect_validation_method(
        context,
        init_path,
        &init_data,
        &mut live_validator,
        &mut tracker,
    );

    // If the init segment's manifest failed trust/signature validation, don't proceed to
    // validate segments under a guessed fallback method — the segments' actual method (and
    // any VSI session keys) can't be trusted to have been read correctly from an untrusted
    // manifest, so per-segment errors from here on would be confusing rather than useful.
    if tracker
        .logged_items()
        .iter()
        .any(|i| i.validation_status.as_deref() == Some(LIVEVIDEO_INIT_INVALID))
    {
        bail!("Live video validation failed: init segment manifest is not valid/trusted");
    }

    match &method {
        ValidationMethod::ManifestBox => {
            println!("Method:    19.3 (per-segment C2PA Manifest Box)")
        }
        ValidationMethod::VerifiableSegmentInfo => {
            println!("Method:    19.4 (Verifiable Segment Info)")
        }
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
        let ok = match method {
            ValidationMethod::ManifestBox => validate_segment_manifest_box(
                context,
                segment_path,
                &mut live_validator,
                &mut tracker,
            ),
            ValidationMethod::VerifiableSegmentInfo => {
                validate_segment_vsi(segment_path, &mut live_validator, &mut tracker)
            }
        };
        if !ok {
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

/// Returns a description of the first non-passed validation status on `reader`, if any.
///
/// A `Reader` built via `with_stream` can return `Ok` even when the manifest's signature is
/// invalid or its certificate is untrusted — the SDK logs those as validation statuses rather
/// than hard errors, so a successful `Result` alone does not mean the manifest is trustworthy.
fn reader_trust_failure(reader: &Reader) -> Option<String> {
    reader
        .validation_status()?
        .iter()
        .find(|status| !status.passed())
        .map(|status| {
            format!(
                "{}{}",
                status.code(),
                status
                    .explanation()
                    .map(|e| format!(": {e}"))
                    .unwrap_or_default()
            )
        })
}

/// Detects the validation method from the init segment manifest.
///
/// If the manifest contains a `c2pa.session-keys` assertion, validates and registers the keys
/// in `live_validator` for subsequent VSI segment validation. Returns the detected method.
fn detect_validation_method(
    context: &Arc<C2paContext>,
    init_path: &Path,
    init_data: &[u8],
    live_validator: &mut LiveVideoValidator,
    tracker: &mut StatusTracker,
) -> ValidationMethod {
    let format = format_from_path(init_path).unwrap_or_else(|| "video/mp4".to_string());

    let reader =
        match Reader::from_shared_context(context).with_stream(&format, Cursor::new(init_data)) {
            Ok(r) => r,
            Err(_) => return ValidationMethod::ManifestBox,
        };

    if let Some(reason) = reader_trust_failure(&reader) {
        let _ = live_validator.fail_init_manifest(
            format!("init segment manifest is not valid/trusted: {reason}"),
            tracker,
        );
        eprintln!("Init segment manifest is not valid/trusted: {reason}");
        return ValidationMethod::ManifestBox;
    }

    let manifest = match reader.active_manifest() {
        Some(m) => m,
        None => return ValidationMethod::ManifestBox,
    };

    match manifest.find_assertion::<SessionKeys>(SessionKeys::LABEL) {
        Ok(session_keys) => {
            let manifest_id = manifest.label().unwrap_or_default().to_string();
            let ee_cert_der = extract_ee_cert_der(manifest);

            let failures_before = tracker.logged_items().len();
            let _ = live_validator.validate_session_keys(
                &session_keys,
                &manifest_id,
                ee_cert_der.as_deref(),
                tracker,
            );
            if let Some(item) = tracker.logged_items()[failures_before..]
                .iter()
                .find(|i| i.validation_status.as_deref() == Some(LIVEVIDEO_SESSIONKEY_INVALID))
            {
                eprintln!("Session keys FAIL: {}", item.description);
            }

            ValidationMethod::VerifiableSegmentInfo
        }
        Err(_) => ValidationMethod::ManifestBox,
    }
}

/// Extracts the DER-encoded end-entity certificate from a manifest's PEM cert chain.
fn extract_ee_cert_der(manifest: &Manifest) -> Option<Vec<u8>> {
    let si = manifest.signature_info()?;
    let pems = pem::parse_many(si.cert_chain()).ok()?;
    let first = pems.into_iter().next()?;
    Some(first.into_contents())
}

fn collect_segments(init_path: &Path, segments_glob: &Path) -> Result<Vec<PathBuf>> {
    let init_dir = init_path
        .parent()
        .context("init segment path has no parent directory")?;
    crate::live_video_common::collect_segments(init_dir, segments_glob)
}

/// Validates one segment using section 19.3 (per-segment C2PA Manifest Box).
fn validate_segment_manifest_box(
    context: &Arc<C2paContext>,
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
    let reader = match Reader::from_shared_context(context)
        .with_stream(&format, Cursor::new(&segment_data))
    {
        Ok(r) => r,
        Err(e) => {
            let _ = live_validator
                .fail_segment_manifest(format!("C2PA manifest validation failed: {e}"), tracker);
            eprintln!("Segment FAIL [{segment_path:?}]: cannot read C2PA manifest: {e}");
            return false;
        }
    };

    if let Some(reason) = reader_trust_failure(&reader) {
        let _ = live_validator.fail_segment_manifest(
            format!("segment manifest is not valid/trusted: {reason}"),
            tracker,
        );
        eprintln!("Segment FAIL [{segment_path:?}]: manifest is not valid/trusted: {reason}");
        return false;
    }

    let manifest = match reader.active_manifest() {
        Some(m) => m,
        None => {
            let _ = live_validator.fail_segment_manifest("no active manifest in segment", tracker);
            eprintln!("Segment FAIL [{segment_path:?}]: no active manifest");
            return false;
        }
    };

    let manifest_id = match manifest.label() {
        Some(l) => l.to_string(),
        None => {
            let _ = live_validator.fail_segment_manifest("active manifest has no label", tracker);
            eprintln!("Segment FAIL [{segment_path:?}]: active manifest has no label");
            return false;
        }
    };
    let assertion = match manifest.find_assertion::<LiveVideoSegment>(LiveVideoSegment::LABEL) {
        Ok(a) => a,
        Err(_) => {
            let _ = live_validator.fail_segment_manifest(
                format!("no `{}` assertion found", LiveVideoSegment::LABEL),
                tracker,
            );
            eprintln!(
                "Segment FAIL [{segment_path:?}]: no `{}` assertion found",
                LiveVideoSegment::LABEL
            );
            return false;
        }
    };

    // `validate_media_segment` returns `Ok` even when it has logged a livevideo.* failure to
    // `tracker` (the default StatusTracker behavior continues past validation failures rather
    // than raising them as errors), so a successful `Result` alone does not mean the segment
    // is valid — check whether a new failure was logged too.
    let failures_before = collect_live_video_failures(tracker).len();
    let result = live_validator.validate_media_segment(&segment_data, &manifest_id, &assertion, tracker);
    let has_new_failure = collect_live_video_failures(tracker).len() > failures_before;

    match result {
        Ok(_) if !has_new_failure => {
            println!("Segment OK  [{segment_path:?}]");
            true
        }
        Ok(_) => {
            eprintln!(
                "Segment FAIL [{segment_path:?}]: validation failure recorded \
                 (see live video continuity failures below)"
            );
            false
        }
        Err(e) => {
            eprintln!("Segment FAIL [{segment_path:?}]: {e}");
            false
        }
    }
}

/// Validates one segment using section 19.4 (Verifiable Segment Info).
fn validate_segment_vsi(
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

    // `validate_verifiable_segment_info` returns `Ok` even when it has logged a
    // livevideo.* failure to `tracker` (the default StatusTracker behavior continues past
    // validation failures rather than raising them as errors), so a successful `Result` alone
    // does not mean the segment is valid — check whether a new failure was logged too.
    let failures_before = collect_live_video_failures(tracker).len();
    let result = live_validator.validate_verifiable_segment_info(&segment_data, tracker);
    let has_new_failure = collect_live_video_failures(tracker).len() > failures_before;

    match result {
        Ok(_) if !has_new_failure => {
            println!("Segment OK  [{segment_path:?}]");
            true
        }
        Ok(_) => {
            eprintln!(
                "Segment FAIL [{segment_path:?}]: validation failure recorded \
                 (see live video continuity failures below)"
            );
            false
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

    /// Per §19.7.1, an `mdat` box in an initialization segment is a hard failure
    /// (`livevideo.init.invalid`) that must propagate as an error, even when there are no
    /// media segments to separately fail on.
    #[test]
    fn validate_live_video_rejects_init_with_mdat() {
        let dir = tempfile::tempdir().unwrap();

        // init segment containing mdat — must fail
        let mut init_data = make_bmff_box(b"ftyp");
        init_data.extend(make_bmff_box(b"mdat"));
        let init = write_temp_file(&dir, "init.mp4", &init_data);

        let result =
            validate_live_video(&Arc::new(C2paContext::new()), &init, Path::new("seg_*.m4s"));

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("not valid/trusted"));
    }

    #[test]
    fn validate_live_video_fails_when_segment_has_no_manifest() {
        let dir = tempfile::tempdir().unwrap();

        let init_data = make_bmff_box(b"ftyp");
        let init = write_temp_file(&dir, "init.mp4", &init_data);

        // A segment with raw BMFF but no C2PA manifest
        let seg_data = make_bmff_box(b"mdat");
        write_temp_file(&dir, "seg_001.m4s", &seg_data);

        let result =
            validate_live_video(&Arc::new(C2paContext::new()), &init, Path::new("seg_*.m4s"));

        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("1/1"));
    }
}
