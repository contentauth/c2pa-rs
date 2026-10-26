# RFC 3161 acquisition experiment

This **unpublished, branch-only experiment** extracts timestamp acquisition from
the C2PA SDK into a workspace crate using `contentauth-sans-io-core` 0.2.
The API is provisional and may change without compatibility guarantees.
Keep this crate in the workspace while evaluating the experiment; a separate
repository and publication are decisions for later.

## Boundary

The crate builds SHA-256 timestamp requests, yields HTTP POST operations to its
host, and checks HTTP status, content type, DER structure and reflected nonces.
It has no HTTP client, executor, clock, entropy source or dependency on `c2pa`.
The host supplies a fresh nonce and owns networking, redirects, authentication,
timeouts, cancellation and bounded response reads.

**Successful acquisition does not mean the timestamp is valid or trusted.**
`UnverifiedTimeStampResponse` contains original response bytes. It deliberately
does not assert CMS signature validity, a matching message imprint, certificate
validity or TSA trust. Non-granted responses and absent tokens are preserved for
the caller's verifier, matching the existing SDK transport layer.

The SDK's existing synchronous and asynchronous entry points drive the same
workflow through their configured HTTP resolvers, then run the existing
cryptographic verifier before returning. Signer/provider customization hooks,
custom request bodies, C2PA status reporting, trust policy, and COSE
`sigTst`/`sigTst2` packaging stay in the SDK.

```rust
use contentauth_rfc3161::{acquire, AcquisitionReply, AcquisitionRequest};
use contentauth_sans_io_core::{Step, Workflow};

# fn example() -> Result<(), Box<dyn std::error::Error>> {
// In an application, supply a fresh nonce from the host's entropy source.
let mut workflow = acquire("https://tsa.example/", vec![], b"message", 42)?;
assert_eq!(workflow.advance()?, Step::AwaitHost);
workflow.respond(|operation| {
    let AcquisitionRequest::HttpPost(request) = operation;
    assert_eq!(request.method(), "POST");
    // Replace this explicit failure with a bounded HTTP exchange.
    AcquisitionReply::Http(Err("HTTP is not configured".into()))
})?;
assert!(workflow.advance().is_err());
# Ok(())
# }
# example().unwrap();
```

Asynchronous hosts use `outstanding_requests` and `fulfill` instead of `respond`.
Only host operations are awaited inside the coroutine; no runtime is needed.
Protocol errors are distinct from host transport and acquisition errors.
The SDK preserves its original resolver/read errors rather than stringifying
them through the workflow vocabulary.

## Compatibility and intentional differences

- SHA-256 request encoding and eight-byte random nonces remain the SDK default;
  nonce generation is now exclusively in the SDK adapter.
- Custom DER request bodies are decoded and re-encoded as before.
- HTTP 200 and exactly `application/timestamp-reply` remain required.
- Original response bytes are preserved, including CMS signed bytes.
- Missing tokens and unsuccessful TSA statuses retain their prior acquisition
  behavior; the SDK verifier still rejects them.
- Existing legacy provider behavior that suppresses request-body failures is
  unchanged; the new crate's constructors report those failures explicitly.
- Oversized responses now produce an explicit error. Previously, reads stopped
  silently at 1,000,000 bytes. The SDK now reads at most that limit plus one
  byte to detect overflow and never allocates using untrusted Content-Length.

## Codec bridge and eventual extraction

The `asn1` module is the SDK's existing codec dependency closure, moved with
its tests rather than copied or rewritten. Its supporting CMS, attribute
certificate and PKI types are implementation dependencies, not additional
workflow features. The SDK aliases this module at its existing internal path.
The hidden `response` module similarly bridges the existing response parser.
These hidden modules are temporary integration surfaces, not stable APIs.
Public certificate fixtures used by codec tests are kept here so the crate's
tests do not depend on the SDK's filesystem layout.

The SDK intentionally has a path-only dependency on this `publish = false`
crate. **Do not release this branch:** SDK packaging/publication is not
supported in this state. No crates.io patch, release automation or independent
versioning is introduced. A successful experiment needs a separate decision
on publication/versioning and replacing these temporary codec bridges before
it can enter a release.

## Evaluation

The experiment is useful if both SDK host modes preserve timestamp verification
and customization while the acquisition crate remains independently testable,
runtime-independent and free of SDK, network-client, clock and RNG dependencies.
Recorded or fixture HTTP replies should reproduce acquisition deterministically.
Full certificate trust, OCSP and COSE extraction are outside this first slice.

Run from the workspace root:

```sh
cargo test -p contentauth-rfc3161
cargo test -p c2pa --lib crypto::time_stamp
cargo test -p c2pa --lib crypto::cose::sigtst
cargo test -p c2pa --no-default-features --features rust_native_crypto --lib crypto::time_stamp
cargo clippy -p contentauth-rfc3161 --all-targets -- -D warnings
cargo +nightly-2026-07-12 fmt --all -- --check
```

The timestamp acquisition experiment CI workflow runs on feature-branch pushes
and pull requests touching this slice, so evaluation can continue without
merging or publishing it.
