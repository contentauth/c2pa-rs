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
    pub session_key_validity: u64,
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
        session_key_validity,
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
        session_key_validity,
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

    fn make_box(fourcc: &[u8; 4], payload: &[u8]) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&((8 + payload.len()) as u32).to_be_bytes());
        b.extend_from_slice(fourcc);
        b.extend_from_slice(payload);
        b
    }

    fn make_moof_with_mfhd(sequence_number: u32) -> Vec<u8> {
        let mut mfhd_payload = vec![0u8; 4]; // FullBox version(1) + flags(3)
        mfhd_payload.extend_from_slice(&sequence_number.to_be_bytes());
        let mfhd = make_box(b"mfhd", &mfhd_payload);
        make_box(b"moof", &mfhd)
    }

    #[test]
    fn infer_min_sequence_number_defaults_to_one_without_a_segment() {
        assert_eq!(infer_min_sequence_number(None).unwrap(), 1);
    }

    #[test]
    fn infer_min_sequence_number_defaults_to_one_without_a_moof_box() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("seg_001.m4s");
        fs::write(&path, make_box(b"mdat", &[0u8; 4])).unwrap();

        assert_eq!(infer_min_sequence_number(Some(&path)).unwrap(), 1);
    }

    #[test]
    fn infer_min_sequence_number_reads_moof_mfhd_sequence_number() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("seg_001.m4s");
        fs::write(&path, make_moof_with_mfhd(277)).unwrap();

        assert_eq!(infer_min_sequence_number(Some(&path)).unwrap(), 277);
    }

    #[test]
    fn load_ed25519_session_key_accepts_a_32_byte_seed() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("session.key");
        fs::write(&path, [0x42u8; 32]).unwrap();

        assert!(load_ed25519_session_key(&path).is_ok());
    }

    #[test]
    fn load_ed25519_session_key_rejects_wrong_length() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("session.key");
        fs::write(&path, [0x42u8; 16]).unwrap();

        let err = load_ed25519_session_key(&path).unwrap_err();
        assert!(
            format!("{err}").contains("32 bytes"),
            "unexpected error: {}",
            err
        );
    }

    // ── VSI end-to-end: init signing and the resume flow ─────────────────────
    //
    // These exercise `sign_live_video_vsi` for real (signing a genuine BMFF init segment with
    // the sample certs), rather than the synthetic-box unit tests above. The resume path is
    // what keeps `manifestId` stable across process restarts, so a regression there silently
    // produces segments that a validator rejects.

    /// A real fragmented-MP4 init segment (`ftyp` + `moov`, no `mdat`, per §19.2.3).
    const INIT_FIXTURE: &[u8] = include_bytes!("../tests/fixtures/live_video/init.mp4");

    fn sample_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("sample")
            .join(name)
    }

    fn test_signer() -> Box<dyn Signer> {
        Box::new(
            c2pa::create_signer::from_files(
                sample_path("es256_certs.pem"),
                sample_path("es256_private.key"),
                c2pa::SigningAlg::Es256,
                None,
            )
            .unwrap(),
        )
    }

    fn vsi_manifest_json() -> &'static str {
        r#"{"assertions": [{"label": "c2pa.actions", "data": {"actions": [{"action": "c2pa.created", "digitalSourceType": "http://c2pa.org/digitalsourcetype/empty"}]}}]}"#
    }

    /// Writes an `mdat`-only media segment. It carries no `moof/mfhd`, so the signer's
    /// sequence-number cross-check (§19.4.1) has nothing to compare against and won't object.
    fn write_media_segment(dir: &Path, name: &str) -> PathBuf {
        let path = dir.join(name);
        fs::write(&path, make_box(b"mdat", &[0u8; 16])).unwrap();
        path
    }

    /// Reads the `manifestId` a signed segment actually carries in its VSI `emsg` box.
    fn signed_segment_manifest_id(path: &Path) -> String {
        let data = fs::read(path).unwrap();
        let text = String::from_utf8_lossy(&data);
        let start = text
            .find("urn:")
            .expect("signed segment should carry a c2pa URN manifestId");
        text[start..]
            .chars()
            .take_while(|c| !c.is_control())
            .collect()
    }

    /// Writes `verify.verify_trust` into the thread-local settings the signer reads.
    ///
    /// The non-deprecated builders deliberately don't touch thread-local state, so the
    /// deprecated entry point is the only way to reach it from here.
    fn set_verify_trust(enabled: bool) {
        #[allow(deprecated)]
        c2pa::settings::Settings::from_string(
            &format!(r#"{{"verify": {{"verify_trust": {enabled}}}}}"#),
            "json",
        )
        .unwrap();
    }

    /// Turns trust verification off while alive, and restores the SDK default on drop.
    ///
    /// The sample certs aren't on a trust list, and signing reads the init back through a full
    /// manifest validation, so these tests have to turn it off. Since `cargo test` reuses
    /// threads and the setting is thread-local, leaving it off would let a later test on the
    /// same thread pass while masking a real trust failure.
    struct TrustVerificationOff;

    impl TrustVerificationOff {
        fn new() -> Self {
            set_verify_trust(false);
            Self
        }
    }

    impl Drop for TrustVerificationOff {
        fn drop(&mut self) {
            set_verify_trust(true);
        }
    }

    /// Sets up a signing run: a segments dir with `count` media segments, plus an output dir.
    ///
    /// The returned guard must be held for the duration of the test; dropping it early puts
    /// trust verification back and the signing calls start failing.
    fn setup_vsi_dirs(
        count: usize,
    ) -> (
        (tempfile::TempDir, TrustVerificationOff),
        PathBuf,
        PathBuf,
        PathBuf,
    ) {
        let trust_guard = TrustVerificationOff::new();

        let dir = tempfile::tempdir().unwrap();
        let segments_dir = dir.path().join("in");
        let output_dir = dir.path().join("out");
        fs::create_dir_all(&segments_dir).unwrap();

        let init_path = segments_dir.join("init.mp4");
        fs::write(&init_path, INIT_FIXTURE).unwrap();
        for i in 1..=count {
            write_media_segment(&segments_dir, &format!("seg_{i:03}.m4s"));
        }

        ((dir, trust_guard), segments_dir, output_dir, init_path)
    }

    #[test]
    fn session_key_validity_reaches_the_signed_assertion() {
        for validity in [60, 3600, 86_400] {
            let (_guard, segments_dir, output_dir, init_path) = setup_vsi_dirs(1);
            let key_path = segments_dir.join("session.key");
            fs::write(&key_path, [0x42u8; 32]).unwrap();
            let signer = test_signer();

            sign_live_video_vsi(VsiSignArgs {
                segments_dir: &segments_dir,
                segments_glob: Path::new("seg_*.m4s"),
                init_path: &init_path,
                previous_segment_path: None,
                manifest_json: vsi_manifest_json(),
                output_dir: &output_dir,
                session_key_path: &key_path,
                signer: signer.as_ref(),
                min_sequence_number: Some(1),
                session_key_validity: validity,
            })
            .unwrap();

            let signed_init = fs::read(output_dir.join("init.mp4")).unwrap();
            let reader = c2pa::Reader::from_context(c2pa::Context::new())
                .with_stream("video/mp4", std::io::Cursor::new(&signed_init))
                .unwrap();
            let keys: c2pa::assertions::SessionKeys = reader
                .active_manifest()
                .unwrap()
                .find_assertion(c2pa::assertions::SessionKeys::LABEL)
                .unwrap();

            assert_eq!(
                keys.keys[0].validity_period, validity,
                "the signed validityPeriod must be what --session-key-validity asked for"
            );
        }
    }

    #[test]
    fn vsi_signs_init_and_media_segments() {
        let (_guard, segments_dir, output_dir, init_path) = setup_vsi_dirs(2);
        let key_path = segments_dir.join("session.key");
        fs::write(&key_path, [0x42u8; 32]).unwrap();
        let signer = test_signer();

        sign_live_video_vsi(VsiSignArgs {
            segments_dir: &segments_dir,
            segments_glob: Path::new("seg_*.m4s"),
            init_path: &init_path,
            previous_segment_path: None,
            manifest_json: vsi_manifest_json(),
            output_dir: &output_dir,
            session_key_path: &key_path,
            signer: signer.as_ref(),
            min_sequence_number: Some(1),
            session_key_validity: 3600,
        })
        .unwrap();

        // The init segment is signed and carries the session-keys assertion.
        let signed_init = fs::read(output_dir.join("init.mp4")).unwrap();
        assert!(signed_init.len() > INIT_FIXTURE.len());
        assert!(
            String::from_utf8_lossy(&signed_init).contains("c2pa.session-keys"),
            "signed init must carry the c2pa.session-keys assertion (§19.4)"
        );

        // Both media segments got a VSI emsg box.
        for name in ["seg_001.m4s", "seg_002.m4s"] {
            let signed = fs::read(output_dir.join(name)).unwrap();
            assert!(
                String::from_utf8_lossy(&signed).contains("urn:c2pa:verifiable-segment-info"),
                "{} must carry a VSI emsg box",
                name
            );
        }
    }

    /// Regression test for the resume flow: a second invocation with `--previous-segment` must
    /// reuse the already-signed init's `manifestId` rather than re-signing the init and
    /// minting a new one, which would break §19.4.4 continuity across a process restart.
    #[test]
    fn vsi_resume_keeps_manifest_id_stable_across_invocations() {
        let (_guard, segments_dir, output_dir, init_path) = setup_vsi_dirs(1);
        let key_path = segments_dir.join("session.key");
        fs::write(&key_path, [0x42u8; 32]).unwrap();
        let signer = test_signer();

        // First invocation: signs the init plus seg_001.
        sign_live_video_vsi(VsiSignArgs {
            segments_dir: &segments_dir,
            segments_glob: Path::new("seg_001.m4s"),
            init_path: &init_path,
            previous_segment_path: None,
            manifest_json: vsi_manifest_json(),
            output_dir: &output_dir,
            session_key_path: &key_path,
            signer: signer.as_ref(),
            min_sequence_number: Some(1),
            session_key_validity: 3600,
        })
        .unwrap();
        let first_id = signed_segment_manifest_id(&output_dir.join("seg_001.m4s"));
        let signed_init_before = fs::read(output_dir.join("init.mp4")).unwrap();

        // Second invocation resumes from the previously signed segment.
        write_media_segment(&segments_dir, "seg_002.m4s");
        let previous = output_dir.join("seg_001.m4s");
        sign_live_video_vsi(VsiSignArgs {
            segments_dir: &segments_dir,
            segments_glob: Path::new("seg_002.m4s"),
            init_path: &init_path,
            previous_segment_path: Some(&previous),
            manifest_json: vsi_manifest_json(),
            output_dir: &output_dir,
            session_key_path: &key_path,
            signer: signer.as_ref(),
            min_sequence_number: Some(1),
            session_key_validity: 3600,
        })
        .unwrap();

        let second_id = signed_segment_manifest_id(&output_dir.join("seg_002.m4s"));
        assert_eq!(
            first_id, second_id,
            "resuming must preserve the manifestId from the already-signed init (§19.4.4)"
        );

        assert_eq!(
            signed_init_before,
            fs::read(output_dir.join("init.mp4")).unwrap(),
            "resuming must not re-sign the init segment"
        );
    }

    /// The resume path reads the signed init back out of the output dir; if a caller passes
    /// `--previous-segment` without having run a first invocation, that has to be a clear
    /// error rather than a silent re-sign with a fresh manifestId.
    #[test]
    fn vsi_resume_without_a_signed_init_fails_clearly() {
        let (_guard, segments_dir, output_dir, init_path) = setup_vsi_dirs(1);
        let key_path = segments_dir.join("session.key");
        fs::write(&key_path, [0x42u8; 32]).unwrap();
        let signer = test_signer();

        // Produce a signed segment to resume from, but in a *different* output dir, so the
        // real output dir has no signed init.
        let staging = segments_dir.join("staging");
        fs::create_dir_all(&staging).unwrap();
        sign_live_video_vsi(VsiSignArgs {
            segments_dir: &segments_dir,
            segments_glob: Path::new("seg_001.m4s"),
            init_path: &init_path,
            previous_segment_path: None,
            manifest_json: vsi_manifest_json(),
            output_dir: &staging,
            session_key_path: &key_path,
            signer: signer.as_ref(),
            min_sequence_number: Some(1),
            session_key_validity: 3600,
        })
        .unwrap();

        let previous = staging.join("seg_001.m4s");
        let err = sign_live_video_vsi(VsiSignArgs {
            segments_dir: &segments_dir,
            segments_glob: Path::new("seg_001.m4s"),
            init_path: &init_path,
            previous_segment_path: Some(&previous),
            manifest_json: vsi_manifest_json(),
            output_dir: &output_dir,
            session_key_path: &key_path,
            signer: signer.as_ref(),
            min_sequence_number: Some(1),
            session_key_validity: 3600,
        })
        .unwrap_err();

        let msg = format!("{err:#}");
        assert!(
            msg.contains("signed init segment"),
            "error should name the missing signed init, got: {}",
            msg
        );
    }
}
