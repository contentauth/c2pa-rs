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
    settings::Settings,
    status_tracker::{LogItem, StatusTracker},
    validation_results::validation_codes::{LIVEVIDEO_INIT_INVALID, SIGNING_CREDENTIAL_UNTRUSTED},
    Context as C2paContext, Error, Manifest, Reader, ValidationState,
};
use serde::Serialize;

/// Shared prefix of the §19.7 live video status codes, used to pick them out of the tracker.
const LIVEVIDEO_CODE_PREFIX: &str = "livevideo";

/// One `livevideo.*` (or manifest-level) status in the JSON report.
///
/// Mirrors the shape the rest of the CLI emits for `validation_results`, so consumers can parse
/// live video output with the same code they already use for a single asset.
#[derive(Serialize)]
struct ReportStatus {
    code: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    explanation: Option<String>,
}

/// Per-segment outcome in the JSON report.
#[derive(Serialize)]
struct SegmentReport {
    path: String,
    /// Kept as the typed state rather than its spelling, so the stream-level fold reads it
    /// straight from the reports instead of from a second vector that could drift.
    #[serde(serialize_with = "serialize_validation_state")]
    state: ValidationState,
}

fn serialize_validation_state<S: serde::Serializer>(
    state: &ValidationState,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    serializer.serialize_str(state_name(*state))
}

/// Machine-readable result of validating a live video stream.
#[derive(Serialize)]
struct LiveVideoReport {
    validation_state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    method: Option<&'static str>,
    init_segment: String,
    segments: Vec<SegmentReport>,
    validation_results: ReportResults,
}

#[derive(Serialize, Default)]
struct ReportResults {
    failure: Vec<ReportStatus>,
}

impl LiveVideoReport {
    /// Writes the report to stdout. Human-readable progress goes to stderr, so redirecting
    /// stdout yields valid JSON on its own.
    fn emit(&self) {
        match serde_json::to_string_pretty(self) {
            Ok(json) => println!("{json}"),
            Err(e) => eprintln!("could not serialize validation report: {e}"),
        }
    }
}

/// Result of validating a single media segment.
struct SegmentOutcome {
    /// Whether the segment passed every §19.7 check.
    ok: bool,
    /// The segment manifest's own state, so the report can distinguish a Trusted stream from a
    /// merely Valid one instead of collapsing both to "passed".
    state: ValidationState,
}

impl SegmentOutcome {
    /// A segment that failed: `Invalid` regardless of the trust configuration, since the
    /// failure is either structural or a content mismatch.
    fn invalid() -> Self {
        Self {
            ok: false,
            state: ValidationState::Invalid,
        }
    }
}

/// Folds the init segment's state and every segment's state into the stream's own.
///
/// `init` is `None` when the init segment carried no C2PA manifest, which §19.2.3 permits for
/// §19.3: it then contributes nothing, and the stream is judged on its media segments alone.
/// A stream with nothing to judge at all is `Valid`, since nothing failed.
fn fold_stream_state(
    init: Option<ValidationState>,
    segments: impl IntoIterator<Item = ValidationState>,
) -> ValidationState {
    segments
        .into_iter()
        .fold(init, |acc, state| {
            Some(match acc {
                Some(current) => weaker(current, state),
                None => state,
            })
        })
        .unwrap_or(ValidationState::Valid)
}

/// Returns the weaker of two states, per §14.3.2's nesting (Trusted implies Valid, which
/// implies Well-Formed). A stream is only as strong as its weakest segment.
fn weaker(a: ValidationState, b: ValidationState) -> ValidationState {
    fn rank(s: ValidationState) -> u8 {
        match s {
            ValidationState::Invalid => 0,
            ValidationState::Valid => 1,
            ValidationState::Trusted => 2,
        }
    }
    if rank(a) <= rank(b) {
        a
    } else {
        b
    }
}

fn state_name(state: ValidationState) -> &'static str {
    match state {
        ValidationState::Invalid => "Invalid",
        ValidationState::Valid => "Valid",
        ValidationState::Trusted => "Trusted",
    }
}

/// The state every validation step needs, threaded as one value rather than as four
/// parameters that always travel together through `validate_init`, `validate_segments` and
/// both per-segment validators.
struct ValidationCtx<'a> {
    context: &'a Arc<C2paContext>,
    validator: &'a mut LiveVideoValidator,
    tracker: &'a mut StatusTracker,
    /// Whether the operator provisioned trust material, which decides whether a Valid but
    /// untrusted manifest is accepted (§15.7).
    trust_configured: bool,
}

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
    let trust_configured = trust_material_configured(context.settings());
    let init_data = fs::read(init_path)
        .with_context(|| format!("Failed to read init segment: {init_path:?}"))?;

    let mut tracker = StatusTracker::default();
    let mut live_validator = LiveVideoValidator::new();
    let mut ctx = ValidationCtx {
        context,
        validator: &mut live_validator,
        tracker: &mut tracker,
        trust_configured,
    };

    let (method, init_state) = validate_init(&mut ctx, init_path, &init_data)?;

    eprintln!("Method:    {}", method_label(&method));

    let segment_paths = collect_segments(init_path, segments_glob)?;

    if segment_paths.is_empty() {
        let init_dir = init_path.parent().unwrap_or(Path::new("."));
        eprintln!(
            "No segments found matching: {:?}",
            init_dir.join(segments_glob)
        );
        LiveVideoReport {
            validation_state: state_name(init_state.unwrap_or(ValidationState::Valid)),
            method: Some(method_label(&method)),
            init_segment: init_path.display().to_string(),
            segments: Vec::new(),
            validation_results: ReportResults::default(),
        }
        .emit();
        return Ok(());
    }

    let (segment_reports, failed_count) =
        validate_segments(&mut ctx, &segment_paths, &method, init_state);

    let failures = collect_live_video_failures(&tracker);

    if !failures.is_empty() {
        eprintln!("\nLive video continuity failures:");
        for f in &failures {
            eprintln!(
                "  [{}] {}",
                f.code,
                f.explanation.as_deref().unwrap_or_default()
            );
        }
    }

    let total = segment_paths.len();
    let failure_count = failures.len();
    let valid = failed_count == 0 && failures.is_empty();
    let stream_state = if valid {
        fold_stream_state(init_state, segment_reports.iter().map(|r| r.state))
    } else {
        ValidationState::Invalid
    };

    LiveVideoReport {
        validation_state: state_name(stream_state),
        method: Some(method_label(&method)),
        init_segment: init_path.display().to_string(),
        segments: segment_reports,
        validation_results: ReportResults { failure: failures },
    }
    .emit();

    if valid {
        eprintln!("\n{total} segment(s) validated successfully.");
        Ok(())
    } else {
        bail!(
            "Live video validation failed: {failed_count}/{total} segment(s) failed, \
             {} continuity error(s)",
            failure_count
        )
    }
}

/// Human- and machine-readable name of the detected method.
fn method_label(method: &ValidationMethod) -> &'static str {
    match method {
        ValidationMethod::ManifestBox => "19.3 (per-segment C2PA Manifest Box)",
        ValidationMethod::VerifiableSegmentInfo => "19.4 (Verifiable Segment Info)",
    }
}

/// Builds the report for a stream rejected at the init segment, before any method was
/// established or any media segment was examined.
fn invalid_init_report(init_path: &Path, tracker: &StatusTracker) -> LiveVideoReport {
    LiveVideoReport {
        validation_state: "Invalid",
        method: None,
        init_segment: init_path.display().to_string(),
        segments: Vec::new(),
        validation_results: ReportResults {
            failure: collect_live_video_failures(tracker),
        },
    }
}

/// Returns a diagnostic reason if `reader`'s manifest fails the validation §19.7.1 requires,
/// or `None` if it passes.
///
/// §19.7.1 defers to the general validation rules of Chapter 15, whose outcome is the manifest
/// state defined in §14.3. A [`ValidationState::Valid`] manifest is therefore sufficient:
/// §14.3.3 treats an asset as valid when its active manifest is "either Valid or Trusted", and
/// §15.7 makes verifying a chain of trust a `should`, not a `shall`. Requiring
/// [`ValidationState::Trusted`] unconditionally would reject a conforming stream whenever no
/// trust list is configured, since trust anchors are empty by default.
///
/// Trust is still enforced when the operator asked for it: §15.7 says the claim `shall` be
/// rejected if a chain of trust cannot be verified, so when `trust_configured` is set, a
/// `signingCredential.untrusted` failure is fatal rather than tolerated.
///
/// Basing this on [`Reader::validation_state`] rather than a hand-maintained list of status-code
/// prefixes also rejects content/assertion failures such as `assertion.bmffHash.mismatch`, which
/// indicate the segment's bytes don't match what was signed.
fn reader_invalid_reason(reader: &Reader, trust_configured: bool) -> Option<String> {
    if !manifest_rejected(reader.validation_state(), trust_configured) {
        return None;
    }

    // When no trust material is configured, `signingCredential.untrusted` is expected and is not
    // what made this manifest invalid, so prefer any other failure as the reported reason.
    let reason = reader
        .validation_status()
        .and_then(|statuses| {
            let substantive = statuses.iter().find(|status| {
                !status.passed()
                    && (trust_configured || status.code() != SIGNING_CREDENTIAL_UNTRUSTED)
            });
            substantive.or_else(|| statuses.iter().find(|status| !status.passed()))
        })
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
        .unwrap_or_else(|| "manifest did not validate".to_string());

    Some(reason)
}

/// Returns whether the operator provisioned any X.509 trust material, from a settings file,
/// the `trust` sub-command, or sidecar files next to `--settings`.
///
/// Verifying a chain of trust is a `should` in §15.7 and the SDK's trust lists are empty by
/// default, so an untrusted signer only becomes fatal once anchors exist to check against.
///
/// Only the three PEM fields count. `trust.trust_config` lists allowed EKU OIDs rather than
/// certificates, so on its own it gives the validator nothing to build a chain against. The
/// fields are checked for presence alone, since [`Settings`] rejects unparseable or empty PEM
/// material when it is constructed.
fn trust_material_configured(settings: &Settings) -> bool {
    [
        "trust.trust_anchors",
        "trust.user_anchors",
        "trust.allowed_list",
    ]
    .iter()
    .any(|path| matches!(settings.get_value::<Option<String>>(path), Ok(Some(_))))
}

/// Runs the init segment's own checks and detects the stream's validation method.
///
/// Returns the detected method and the state the init segment contributes, or an error once a
/// report has been emitted: the three ways an init can fail (unreadable, structurally invalid
/// per §19.7.1, or carrying a manifest that did not validate) each stop the run here, since the
/// segments' method and any VSI session keys cannot be read reliably from an init that failed.
fn validate_init(
    ctx: &mut ValidationCtx<'_>,
    init_path: &Path,
    init_data: &[u8],
) -> Result<(ValidationMethod, Option<ValidationState>)> {
    // `validate_init_segment` returns `Ok` even when it has logged a `LIVEVIDEO_INIT_INVALID`
    // failure to `ctx.tracker` (the default StatusTracker behavior continues past validation
    // failures rather than raising them as errors), so a successful `Result` alone does not mean
    // the init segment is structurally valid: check whether a new failure was logged too.
    let structural_failures_before = ctx.tracker.logged_items().len();
    let init_struct_result = ctx.validator.validate_init_segment(init_data, ctx.tracker);
    let init_structurally_invalid = ctx.tracker.logged_items()[structural_failures_before..]
        .iter()
        .any(|i| i.validation_status.as_deref() == Some(LIVEVIDEO_INIT_INVALID));

    if let Err(e) = &init_struct_result {
        eprintln!("Init FAIL: {init_path:?}: {e}");
        invalid_init_report(init_path, ctx.tracker).emit();
        bail!("Live video validation failed: init segment could not be read: {e}");
    }

    if init_structurally_invalid {
        eprintln!(
            "Init FAIL: {init_path:?}: [{LIVEVIDEO_INIT_INVALID}] initialization segment must \
             not contain an mdat box"
        );
        invalid_init_report(init_path, ctx.tracker).emit();
        bail!(
            "Live video validation failed: init segment is structurally invalid \
             (contains an mdat box)"
        );
    }

    let manifest_failures_before = ctx.tracker.logged_items().len();
    let (method, init_state) = detect_validation_method(ctx, init_path, init_data);

    if let Some(reason) = first_failure_since(ctx.tracker, manifest_failures_before) {
        eprintln!("Init FAIL: {init_path:?}: {reason}");
        invalid_init_report(init_path, ctx.tracker).emit();
        bail!("Live video validation failed: init segment manifest did not validate");
    }

    // Only now is the init segment known to be both structurally valid and carrying a manifest
    // that validated, so this is the earliest point at which reporting success is accurate.
    eprintln!("Init OK:   {init_path:?}");

    Ok((method, init_state))
}

/// Validates every media segment under the detected method.
///
/// Returns the per-segment report rows, their states for the stream-level fold, and how many
/// failed. A §19.4 segment carries only an `emsg`, not its own manifest, so its trust standing
/// is the one `init_state` established; `None` means the init carried no manifest at all, which
/// §19.2.3 permits.
fn validate_segments(
    ctx: &mut ValidationCtx<'_>,
    segment_paths: &[PathBuf],
    method: &ValidationMethod,
    init_state: Option<ValidationState>,
) -> (Vec<SegmentReport>, usize) {
    let mut reports = Vec::with_capacity(segment_paths.len());
    let mut failed = 0usize;

    for segment_path in segment_paths {
        let outcome = match method {
            ValidationMethod::ManifestBox => validate_segment_manifest_box(ctx, segment_path),
            ValidationMethod::VerifiableSegmentInfo => {
                validate_segment_vsi(ctx, segment_path, init_state)
            }
        };
        if !outcome.ok {
            failed += 1;
        }
        reports.push(SegmentReport {
            path: segment_path.display().to_string(),
            state: outcome.state,
        });
    }

    (reports, failed)
}

/// Decides whether a manifest in `state` must be rejected under §19.7.1.
///
/// [`ValidationState::Trusted`] always passes and [`ValidationState::Invalid`] always fails.
/// [`ValidationState::Valid`] means the manifest met Chapter 15's requirements but its signer
/// did not chain to a trust anchor; that is acceptable unless the operator supplied trust
/// material, in which case §15.7 requires the claim to be rejected.
fn manifest_rejected(state: ValidationState, trust_configured: bool) -> bool {
    match state {
        ValidationState::Trusted => false,
        ValidationState::Valid => trust_configured,
        ValidationState::Invalid => true,
    }
}

/// Detects the validation method from the init segment manifest.
///
/// If the manifest contains a `c2pa.session-keys` assertion, validates and registers the keys
/// in `live_validator` for subsequent VSI segment validation. Returns the detected method.
fn detect_validation_method(
    ctx: &mut ValidationCtx<'_>,
    init_path: &Path,
    init_data: &[u8],
) -> (ValidationMethod, Option<ValidationState>) {
    let format = format_from_path(init_path).unwrap_or_else(|| "video/mp4".to_string());

    let reader = match Reader::from_shared_context(ctx.context)
        .with_stream(&format, Cursor::new(init_data))
    {
        Ok(r) => r,
        // §19.2.3 makes signing the init segment optional for §19.3, so an init with no
        // manifest at all is legitimate and contributes no state: the stream is then judged
        // on its media segments alone. Any other read error is a real failure.
        Err(Error::JumbfNotFound) => return (ValidationMethod::ManifestBox, None),
        Err(e) => {
            let _ = ctx.validator.fail_init_manifest(
                format!("init segment manifest could not be read: {e}"),
                ctx.tracker,
            );
            return (
                ValidationMethod::ManifestBox,
                Some(ValidationState::Invalid),
            );
        }
    };

    if let Some(reason) = reader_invalid_reason(&reader, ctx.trust_configured) {
        let _ = ctx.validator.fail_init_manifest(
            format!("init segment manifest did not validate: {reason}"),
            ctx.tracker,
        );
        return (
            ValidationMethod::ManifestBox,
            Some(ValidationState::Invalid),
        );
    }

    let init_state = Some(reader.validation_state());

    let manifest = match reader.active_manifest() {
        Some(m) => m,
        None => return (ValidationMethod::ManifestBox, init_state),
    };

    match manifest.find_assertion::<SessionKeys>(SessionKeys::LABEL) {
        Ok(session_keys) => {
            let manifest_id = manifest.label().unwrap_or_default().to_string();
            let ee_cert_der = extract_ee_cert_der(manifest);

            // A `livevideo.sessionkey.invalid` failure logged here is reported by the caller,
            // with its status code attached, when it bails on the init segment.
            let _ = ctx.validator.validate_session_keys(
                &session_keys,
                &manifest_id,
                ee_cert_der.as_deref(),
                ctx.tracker,
            );

            (ValidationMethod::VerifiableSegmentInfo, init_state)
        }
        Err(_) => (ValidationMethod::ManifestBox, init_state),
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

/// Which §19.7 status code a segment failure is recorded under.
enum SegmentFailure {
    /// The segment's manifest was reached and did not validate: `livevideo.manifest.invalid`.
    Manifest,
    /// The segment itself could not be shown to satisfy §19.7: `livevideo.segment.invalid`.
    Segment,
}

/// Records a segment failure, reports it, and returns the outcome to hand back.
///
/// `reason` is written to the tracker as `segment {reason}` and printed after the
/// `Segment FAIL [path]:` prefix, so it reads correctly in both places from one string. Every
/// failure goes through here, which is what keeps the JSON report's failures in step with its
/// `validation_state`: an `Invalid` state with an empty `failure` array means a path returned
/// without recording anything.
fn fail_segment(
    segment_path: &Path,
    reason: impl AsRef<str>,
    kind: SegmentFailure,
    live_validator: &LiveVideoValidator,
    tracker: &mut StatusTracker,
) -> SegmentOutcome {
    let reason = reason.as_ref();
    let logged = format!("segment {reason}");
    let _ = match kind {
        SegmentFailure::Manifest => live_validator.fail_segment_manifest(logged, tracker),
        SegmentFailure::Segment => live_validator.fail_segment_invalid(logged, tracker),
    };
    eprintln!("Segment FAIL [{segment_path:?}]: {reason}");
    SegmentOutcome::invalid()
}

/// Validates one segment using section 19.3 (per-segment C2PA Manifest Box).
fn validate_segment_manifest_box(
    ctx: &mut ValidationCtx<'_>,
    segment_path: &Path,
) -> SegmentOutcome {
    let segment_data = match fs::read(segment_path) {
        Ok(d) => d,
        Err(e) => {
            return fail_segment(
                segment_path,
                format!("could not be read: {e}"),
                SegmentFailure::Segment,
                ctx.validator,
                ctx.tracker,
            );
        }
    };

    let format = format_from_path(segment_path).unwrap_or_else(|| "video/mp4".to_string());
    let reader = match Reader::from_shared_context(ctx.context)
        .with_stream(&format, Cursor::new(&segment_data))
    {
        Ok(r) => r,
        Err(e) => {
            return fail_segment(
                segment_path,
                format!("manifest could not be read: {e}"),
                SegmentFailure::Manifest,
                ctx.validator,
                ctx.tracker,
            );
        }
    };

    if let Some(reason) = reader_invalid_reason(&reader, ctx.trust_configured) {
        return fail_segment(
            segment_path,
            format!("manifest did not validate: {reason}"),
            SegmentFailure::Manifest,
            ctx.validator,
            ctx.tracker,
        );
    }

    let segment_state = reader.validation_state();

    let manifest = match reader.active_manifest() {
        Some(m) => m,
        None => {
            return fail_segment(
                segment_path,
                "has no active manifest",
                SegmentFailure::Manifest,
                ctx.validator,
                ctx.tracker,
            );
        }
    };

    let manifest_id = match manifest.label() {
        Some(l) => l.to_string(),
        None => {
            return fail_segment(
                segment_path,
                "manifest has no label",
                SegmentFailure::Manifest,
                ctx.validator,
                ctx.tracker,
            );
        }
    };
    let assertion = match manifest.find_assertion::<LiveVideoSegment>(LiveVideoSegment::LABEL) {
        Ok(a) => a,
        Err(_) => {
            return fail_segment(
                segment_path,
                format!("has no `{}` assertion", LiveVideoSegment::LABEL),
                SegmentFailure::Manifest,
                ctx.validator,
                ctx.tracker,
            );
        }
    };

    // `validate_media_segment` returns `Ok` even when it has logged a livevideo.* failure to
    // `ctx.tracker` (the default StatusTracker behavior continues past validation failures rather
    // than raising them as errors), so a successful `Result` alone does not mean the segment
    // is valid — check whether a new failure was logged too.
    let logged_items_before = ctx.tracker.logged_items().len();
    let result =
        ctx.validator
            .validate_media_segment(&segment_data, &manifest_id, &assertion, ctx.tracker);
    let has_new_failure = has_new_live_video_failure(ctx.tracker, logged_items_before);

    match result {
        Ok(_) if !has_new_failure => {
            eprintln!("Segment OK  [{segment_path:?}]");
            SegmentOutcome {
                ok: true,
                state: segment_state,
            }
        }
        Ok(_) => {
            eprintln!(
                "Segment FAIL [{segment_path:?}]: validation failure recorded \
                 (see live video continuity failures below)"
            );
            SegmentOutcome::invalid()
        }
        Err(e) => {
            eprintln!("Segment FAIL [{segment_path:?}]: {e}");
            SegmentOutcome::invalid()
        }
    }
}

/// Validates one segment using section 19.4 (Verifiable Segment Info).
/// Validates one segment using section 19.4 (Verifiable Segment Info).
///
/// A VSI media segment carries only an `emsg`, never its own manifest, so a segment that passes
/// inherits `init_state`: the trust standing established once by the init segment's manifest.
fn validate_segment_vsi(
    ctx: &mut ValidationCtx<'_>,
    segment_path: &Path,
    init_state: Option<ValidationState>,
) -> SegmentOutcome {
    let segment_data = match fs::read(segment_path) {
        Ok(d) => d,
        Err(e) => {
            return fail_segment(
                segment_path,
                format!("could not be read: {e}"),
                SegmentFailure::Segment,
                ctx.validator,
                ctx.tracker,
            );
        }
    };

    // `validate_verifiable_segment_info` returns `Ok` even when it has logged a
    // livevideo.* failure to `ctx.tracker` (the default StatusTracker behavior continues past
    // validation failures rather than raising them as errors), so a successful `Result` alone
    // does not mean the segment is valid — check whether a new failure was logged too.
    let logged_items_before = ctx.tracker.logged_items().len();
    let result = ctx
        .validator
        .validate_verifiable_segment_info(&segment_data, ctx.tracker);
    let has_new_failure = has_new_live_video_failure(ctx.tracker, logged_items_before);

    match result {
        Ok(_) if !has_new_failure => {
            eprintln!("Segment OK  [{segment_path:?}]");
            SegmentOutcome {
                ok: true,
                state: init_state.unwrap_or(ValidationState::Valid),
            }
        }
        Ok(_) => {
            eprintln!(
                "Segment FAIL [{segment_path:?}]: validation failure recorded \
                 (see live video continuity failures below)"
            );
            SegmentOutcome::invalid()
        }
        Err(e) => {
            eprintln!("Segment FAIL [{segment_path:?}]: {e}");
            SegmentOutcome::invalid()
        }
    }
}

/// Every `livevideo.*` failure among `items`, as `(code, description)`.
///
/// The helpers below and the JSON report all need the same scan, so it lives in one place:
/// the §19.7 code prefix is then written once rather than in each caller.
fn live_video_failures(items: &[LogItem]) -> impl Iterator<Item = (&str, &str)> {
    items.iter().filter_map(|item| {
        let code = item.validation_status.as_deref()?;
        code.starts_with(LIVEVIDEO_CODE_PREFIX)
            .then(|| (code, item.description.as_ref()))
    })
}

/// Returns whether any `livevideo.*` failure was logged to `tracker` at or after index
/// `logged_items_before`. Only scans the newly logged items rather than re-filtering the
/// whole tracker, so calling this once per segment in a validation loop stays linear in the
/// total number of segments instead of quadratic.
fn has_new_live_video_failure(tracker: &StatusTracker, logged_items_before: usize) -> bool {
    live_video_failures(&tracker.logged_items()[logged_items_before..])
        .next()
        .is_some()
}

/// Returns the first `livevideo.*` failure logged at or after `logged_items_before`, formatted
/// as `[code] description` so every diagnostic the command prints carries its §19.7 status code.
fn first_failure_since(tracker: &StatusTracker, logged_items_before: usize) -> Option<String> {
    live_video_failures(&tracker.logged_items()[logged_items_before..])
        .next()
        .map(|(code, description)| format!("[{code}] {description}"))
}

/// Every `livevideo.*` failure logged to `tracker`, as report statuses.
///
/// The stream summary printed to stderr and the JSON report written to stdout are built from
/// one call, rather than scanning the tracker once for each.
fn collect_live_video_failures(tracker: &StatusTracker) -> Vec<ReportStatus> {
    live_video_failures(tracker.logged_items())
        .map(|(code, description)| ReportStatus {
            code: code.to_string(),
            explanation: Some(description.to_string()),
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
        assert_eq!(failures[0].code, "livevideo.segment.invalid");
        assert_eq!(failures[1].code, "livevideo.assertion.invalid");
    }

    /// §19.7.1 defers to Chapter 15, whose acceptance threshold is a Valid manifest
    /// (§14.3.3), not a Trusted one. Verifying a chain of trust is a `should` in §15.7, so a
    /// Valid-but-untrusted manifest is only rejected once the operator supplies trust material.
    #[test]
    fn valid_manifest_is_accepted_only_until_trust_is_configured() {
        assert!(!manifest_rejected(ValidationState::Valid, false));
        assert!(manifest_rejected(ValidationState::Valid, true));
    }

    #[test]
    fn trusted_manifest_is_always_accepted() {
        assert!(!manifest_rejected(ValidationState::Trusted, false));
        assert!(!manifest_rejected(ValidationState::Trusted, true));
    }

    /// An Invalid manifest covers content failures such as `assertion.bmffHash.mismatch`, which
    /// must fail regardless of whether trust anchors are configured.
    #[test]
    fn invalid_manifest_is_always_rejected() {
        assert!(manifest_rejected(ValidationState::Invalid, false));
        assert!(manifest_rejected(ValidationState::Invalid, true));
    }

    #[test]
    fn first_failure_since_reports_code_and_skips_earlier_items() {
        use c2pa::log_item;

        let mut tracker = StatusTracker::default();
        log_item!("old", "earlier failure", "func")
            .validation_status("livevideo.segment.invalid")
            .failure(&mut tracker, c2pa::Error::NotFound)
            .unwrap();
        let mark = tracker.logged_items().len();
        log_item!("new", "later failure", "func")
            .validation_status("livevideo.manifest.invalid")
            .failure(&mut tracker, c2pa::Error::NotFound)
            .unwrap();

        assert_eq!(
            first_failure_since(&tracker, mark).as_deref(),
            Some("[livevideo.manifest.invalid] later failure")
        );
        assert!(first_failure_since(&tracker, tracker.logged_items().len()).is_none());
    }

    /// The X.509 trust lists are empty by default, so an unconfigured operator must not be
    /// treated as having asked for trust enforcement.
    #[test]
    fn trust_material_is_absent_by_default() {
        assert!(!trust_material_configured(&Settings::default()));
    }

    #[test]
    fn trust_material_is_detected_from_each_pem_field() {
        // Settings validate PEM material on construction, so this has to be a real bundle.
        let pem = fs::read_to_string(
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/trust/no-match.pem"),
        )
        .unwrap();

        for field in ["trust_anchors", "user_anchors", "allowed_list"] {
            let settings = Settings::new()
                .with_toml(&format!("[trust]\n{field} = \"\"\"\n{pem}\"\"\"\n"))
                .unwrap();
            assert!(
                trust_material_configured(&settings),
                "{} should count as trust material",
                field
            );
        }
    }

    /// `trust_config` lists allowed EKU OIDs rather than certificates, so it alone gives the
    /// validator nothing to build a chain against.
    #[test]
    fn trust_config_alone_is_not_trust_material() {
        let settings = Settings::new()
            .with_toml("[trust]\ntrust_config = \"1.3.6.1.5.5.7.3.4\"\n")
            .unwrap();
        assert!(!trust_material_configured(&settings));
    }

    /// The JSON report's failures come from the tracker, so any path that returns an invalid
    /// outcome without recording one produces `"validation_state": "Invalid"` next to an empty
    /// `failure` array: the report says the stream failed but not why, which is the one thing
    /// structured output exists to avoid. That has broken twice, through unrelated paths, so
    /// the invariant is asserted directly rather than re-checked by hand.
    #[test]
    fn an_invalid_segment_always_records_a_failure() {
        let dir = tempfile::tempdir().unwrap();
        let missing = Path::new("/nonexistent/segment_that_cannot_be_read.m4s");
        // Exists but is not BMFF at all, which reaches the validators' error arms rather than
        // the read-failure branch.
        let garbage = write_temp_file(&dir, "garbage.m4s", b"not a bmff file at all");
        // Structurally a BMFF box, but carries neither a Manifest Box nor a VSI `emsg`.
        let bare = write_temp_file(&dir, "bare.m4s", &make_bmff_box(b"mdat"));
        let context = Arc::new(C2paContext::new());

        let cases: Vec<(&str, &Path)> = vec![
            ("unreadable", missing),
            ("not bmff", garbage.as_path()),
            ("no manifest and no emsg", bare.as_path()),
        ];

        for (case, path) in cases {
            for (label, outcome, tracker) in [
                {
                    let mut tracker = StatusTracker::default();
                    let mut validator = LiveVideoValidator::new();
                    let mut ctx = ValidationCtx {
                        context: &context,
                        validator: &mut validator,
                        tracker: &mut tracker,
                        trust_configured: false,
                    };
                    let outcome = validate_segment_manifest_box(&mut ctx, path);
                    ("§19.3", outcome, tracker)
                },
                {
                    let mut tracker = StatusTracker::default();
                    let mut validator = LiveVideoValidator::new();
                    let mut ctx = ValidationCtx {
                        context: &context,
                        validator: &mut validator,
                        tracker: &mut tracker,
                        trust_configured: false,
                    };
                    let outcome = validate_segment_vsi(&mut ctx, path, None);
                    ("§19.4", outcome, tracker)
                },
            ] {
                assert!(!outcome.ok, "{} {}: must fail", label, case);
                assert_eq!(
                    outcome.state,
                    ValidationState::Invalid,
                    "{} {}",
                    label,
                    case
                );
                assert!(
                    !collect_live_video_failures(&tracker).is_empty(),
                    "{} {}: an Invalid outcome must come with a recorded failure, or the \
                     JSON report shows Invalid with an empty failure array",
                    label,
                    case
                );
            }
        }
    }

    /// §14.3.2 nests the states, so a stream is reported at the level of its weakest segment.
    /// §19.2.3 makes signing the init segment optional for §19.3, so an init carrying no
    /// manifest must not drag the stream down: it contributes no state, and the stream is
    /// judged on its segments. Reporting `Invalid` there contradicted both the per-segment
    /// states and the exit code.
    #[test]
    fn an_init_without_a_manifest_does_not_lower_the_stream_state() {
        use ValidationState::{Trusted, Valid};

        assert_eq!(fold_stream_state(None, [Valid, Valid]), Valid);
        assert_eq!(fold_stream_state(None, [Trusted, Trusted]), Trusted);
    }

    #[test]
    fn the_stream_takes_the_state_of_its_weakest_segment() {
        use ValidationState::{Invalid, Trusted, Valid};

        assert_eq!(fold_stream_state(Some(Trusted), [Trusted, Valid]), Valid);
        assert_eq!(
            fold_stream_state(Some(Trusted), [Trusted, Invalid]),
            Invalid
        );
        assert_eq!(fold_stream_state(Some(Valid), [Trusted, Trusted]), Valid);
    }

    /// Nothing to judge is not a failure.
    #[test]
    fn a_stream_with_no_segments_and_no_init_manifest_is_valid() {
        assert_eq!(fold_stream_state(None, []), ValidationState::Valid);
    }

    #[test]
    fn weaker_returns_the_lower_state() {
        use ValidationState::{Invalid, Trusted, Valid};

        assert_eq!(weaker(Trusted, Valid), Valid);
        assert_eq!(weaker(Valid, Trusted), Valid);
        assert_eq!(weaker(Valid, Invalid), Invalid);
        assert_eq!(weaker(Trusted, Trusted), Trusted);
    }

    #[test]
    fn state_name_matches_the_sdk_spelling() {
        assert_eq!(state_name(ValidationState::Invalid), "Invalid");
        assert_eq!(state_name(ValidationState::Valid), "Valid");
        assert_eq!(state_name(ValidationState::Trusted), "Trusted");
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
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("structurally invalid"));
    }

    #[test]
    fn validate_live_video_fails_when_segment_has_no_manifest() {
        let dir = tempfile::tempdir().unwrap();

        // A real, parseable fMP4 init that carries no C2PA manifest. §19.2.3 permits that, so
        // validation must reach the segments rather than stopping here; a synthetic `ftyp` would
        // instead fail to parse and never exercise the segment path.
        const INIT_FIXTURE: &[u8] = include_bytes!("../tests/fixtures/live_video/init.mp4");
        let init = write_temp_file(&dir, "init.mp4", INIT_FIXTURE);

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
