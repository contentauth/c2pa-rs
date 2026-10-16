# Experimental VSI manifestUri support

These APIs and CLI options require `unstable_live_video`. Remote retrieval also
requires `fetch_remote_manifests` and `verify.remote_manifest_fetch = true`.

## Emitting a reference

After `LiveVideoVsiSigner::sign_init_segment`, call
`set_manifest_uri_for_current_manifest(url)`. Subsequent VSI payloads include a
`manifestUri` containing that HTTP(S) URL, `alg: "sha256"`, and the digest of the
exact C2PA Manifest Store returned by `manifest_store()`.

Host those exact store bytes at the URL for the stream's lifetime. The SDK does
not upload them. Signing or restoring an init segment clears a previous URI, so
configure it again afterward. Resuming from a segment with a different manifest
ID also clears the old reference and exported store.

For a precomputed external reference, use `set_manifest_uri(Some(hashed_uri))`.
Although `HashedUri` permits an omitted algorithm for internal references, an
external `manifestUri` requires an explicit `sha256`, `sha384`, or `sha512` and a
matching digest length. `set_manifest_uri(None)` disables emission.

## CLI

Add `--manifest-uri https://example.com/live/init.c2pa` to an existing
`live-video-sign --method vsi --session-key ...` invocation. The command writes
the signed init's raw Manifest Store beside it, replacing the init filename's
extension with `.c2pa`. For example, `output/init.mp4` produces `output/init.c2pa`.
Upload that file to the specified URL before serving the media segments.

The option exports the store again on `--previous-segment` resume from the signed
init already in the output directory, preserving the referenced bytes and digest.

## Validation

Call `LiveVideoValidator::validate_init_segment` with the delivered init bytes.
This method now takes `&mut self`; when remote fetching is compiled in, it retains
the bytes for validation of init-bound remote manifests.

Use `validate_session_keys_from_reader` to load initial keys from a validated
reader after applying the application's trust policy. This preserves the native
CBOR tags in `signerBinding`, which the JSON-facing manifest API drops.

Validate media with `validate_verifiable_segment_info_with_context` to share the
receiver's trust configuration, network policy, and HTTP resolver. The existing
method without a context uses thread-local settings.

When the key and manifest are already known, the validator uses its cache without
fetching. Otherwise, if the segment has no embedded C2PA Manifest Box and has a
`manifestUri`, it:

1. Checks the URL, explicit algorithm, and digest length.
2. Fetches through the SDK's existing remote-manifest fetcher and context resolver.
3. Verifies the digest of the entire downloaded store before parsing it.
4. Runs full C2PA validation, including the hard binding, against the current media
   segment or the retained initialization segment.
5. Checks the active manifest ID, native session-key assertion, signer bindings,
   and presence of the requested kid. Previously published keys may have started
   before the segment where the receiver retrieves their manifest.
6. Installs the keys only after these checks pass, then verifies the VSI signature,
   sequence, validity window, and media hash as usual.

Failures leave segment continuity unchanged. Failed remote key discovery preserves
the earlier key cache. `session_key_manifest_state()` exposes the current key
manifest's validation state for reporting. Callers must inspect both the returned
result and failures recorded in `StatusTracker`.

The remote fetch feature and runtime setting control network access. An unknown
key requiring retrieval fails when fetching is disabled; an already-known key can
still validate without a request.

This change is based directly on the experimental live-video branch. The separate
session-key rotation change adds embedded key updates and retention of multiple
key-authorizing manifests; both changes need reconciliation when combined.
