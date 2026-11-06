# Signature infrastructure extraction experiment

`contentauth-signature-infrastructure` is an **unpublished, provisional**
workspace crate. The acquisition foundation implements host-driven RFC 3161
timestamp acquisition. This second layer adds deterministic timestamp
cryptographic verification and only its private CMS/X.509 support. Certificate
profile/chain policy, trust, OCSP and COSE orchestration remain in the C2PA SDK.

The crate uses `std` but has no HTTP client, executor, ambient clock, random
number generator, SDK dependency or implicit I/O. It uses
`contentauth-sans-io-core` 0.2.0 to yield an owned HTTP request and accept an
owned response. The host supplies a fresh nonce and performs all external
effects. Native, browser WebAssembly and WASI hosts drive the same workflow.

## Current contract

The `timestamp::acquisition` module contains the timestamp acquisition API;
workflow APIs are not re-exported at the crate root. Call
`timestamp::acquisition::acquire` with a message and host-supplied nonce, or
`timestamp::acquisition::acquire_with_body`
with a customized DER request. Drive `Workflow::advance`, inspect its
`outstanding_requests`, perform the `AcquisitionRequest::HttpPost`, and call
`fulfill` with that operation's ID and an `AcquisitionReply::Http`. After
`Step::Complete`, `finish` returns `UnverifiedTimeStampResponse`. No task or
network operation starts merely by constructing a workflow.

The workflow preserves the SDK's decode/re-encode treatment of custom request
bodies, additional headers, HTTP 200 requirement, and exact
`application/timestamp-reply` content type (parameters are not accepted).
It checks reflected nonces when a granted response contains timestamp
information, including missing or unexpected nonces. Non-granted responses and
missing tokens are deliberately passed to the verifier rather
than mistaken for verified results. Original response bytes are retained;
signed CMS data is not re-encoded for return to the verifier.

Hosts **must bound response reads to 1,000,001 bytes**, never reserve memory
from an untrusted `Content-Length`, and retain typed transport/body-read errors
where their host API supports them. Acquisition rejects bodies larger than
1,000,000 bytes explicitly. This replaces the SDK's historical silent truncation.
The SDK adapter does not read error bodies, preserving HTTP-error precedence.

The host owns networking and resolver policy, credentials, clocks/time inputs,
entropy/nonces, retries, timeout, cancellation and bounded streaming reads.
The SDK retains `Settings`/`Context` interpretation and its current sync-only
retry/backoff behavior, including the browser exception. Every attempt receives
the configured timeout. Async acquisition does not introduce new retries.
Resolver errors and read errors remain typed SDK errors, not strings sent
through the generic workflow transport-error path.

Provider and signer customization APIs are unchanged. In particular, the
historical behavior that suppresses a provider request-body failure as `None`
remains host-side; it is not a new success or fallback in this crate.

## Outcomes and policy boundaries

| Outcome | Meaning in this layer |
| --- | --- |
| Parsed | ASN.1 structure decoded; no authenticity claim. Codecs are private. |
| Acquired/unverified | HTTP envelope, structure and available reflected nonce checked; original bytes returned. |
| Signature-verified | `SignatureVerifiedTimestamp`: CMS signature and signed-attribute digest checked; not yet bound to the host message. |
| Cryptographically verified | `VerifiedTimestamp`: signature plus message imprint checked. Not an accepted signing time. |
| Profile-valid | Not produced here. Existing SDK certificate/profile checks remain authoritative. |
| Trusted | Not produced here. SDK trust policy and C2PA/CAWG reporting remain authoritative. |

These are distinct claims, not interchangeable booleans. Later extraction should
accept explicit facts and policy inputs chosen by the host rather than infer
SDK policy, configure resolvers, consult settings or emit C2PA status codes.
No public verification-policy abstraction or empty subsystem scaffolding is
introduced in anticipation of that work.

## Verifying a timestamp

The public API stays under `timestamp::verification`. `ParsedTimestamp::parse`
accepts a granted RFC 3161 response or a legacy bare token and retains the received
CMS encoding for signed-attribute verification. No I/O suspension is necessary.

```rust
use contentauth_signature_infrastructure::timestamp::verification::ParsedTimestamp;

fn verify_first_signer(token: &[u8], message: &[u8])
    -> Result<(), Box<dyn std::error::Error>>
{
    let parsed = ParsedTimestamp::parse(token)?;
    let signed = parsed.verify_signatures().next().ok_or("no timestamp signer")??;

    // Host temporal policy: use the attested time, certificate bounds and
    // accuracy, not the current clock or a CMS signingTime attribute.
    let time = signed.generation_time().timestamp();
    let (start, end) = signed.signer_validity();
    let margin = signed.accuracy_seconds();
    if time < start.saturating_sub(margin) || time > end.saturating_add(margin) {
        return Err("timestamp outside signer validity".into());
    }

    let verified = signed.verify_message_imprint(message)?;
    let signer_certificate_der = verified.signature().signer_certificate();
    // Validate this certificate's TSA profile and chain against host TSA
    // anchors before treating verified.generation_time() as accepted time.
    let _ = signer_certificate_der;
    Ok(()) // Cryptographic/temporal checks only; NOT a trust verdict.
}
```

Hosts trying multiple signers iterate `verify_signatures`, retaining failures
according to their reporting policy. Certificate lookup uses the first match in
decoded certificate order, including strict SKI decoding; it does not try every
certificate sharing an identifier. Duplicate signature values are rejected even
when a SET OF decoder would collapse identical SignerInfos. RSA-PSS parameters
and SPKI restrictions remain strict PS256/384/512, with legacy PKCS#1 v1.5
compatibility. CMS SHA-1 digests remain distinct from SHA-256/384/512-only message
imprints. No supported algorithm profile is expanded by this layer.

`VerificationError` carries a typed failure kind, stage and diagnostic, without
SDK status codes. The SDK preserves signer iteration, temporal-before-imprint
failure precedence, C2PA/CAWG reporting and timestamp-only diagnostic isolation.
It still chooses profile/EKU policy, orders candidate chains, uses only TSA trust
anchors (not private/claim anchors), and decides legacy acceptance. Successful
cryptography alone never enables trusted CAWG signing-time association.

`signer_certificate_from_token` is explicitly **unverified** certificate lookup.
`token_from_response` only extracts/re-encodes a bare token for `sigTst2`; legacy
`sigTst` keeps the original response bytes. Both packaging and validation reuse
the relocated private codecs. RFC 3161 uses CMS, so verification adds no COSE
dependency or public X.509 codec API.

The independent crate defaults to `rust_native_crypto`. Hosts may instead use
`default-features = false` with `openssl`; the SDK forwards its selected backend
without enabling the independent crate's defaults. Both sync/async SDK adapters
use the same deterministic verifier. Browser verification uses Rust-native
primitives; no browser executor or clock is introduced.

## Private codecs and compatibility

The existing ASN.1 codec implementation has moved, not been copied into a
parallel production codec. Its inputs were unchanged between the old #2918
base (`9acd466c28f415088a308c5fda76603e88310401`) and this layer's main
base (`29251acf1a15e67e842fbfc2062bb618dffad190`). The earlier experiment's
documented codec visibility and feature-gating refinements were reused from
`4edfb5be5f5fd23994497a6d701c964511790938`; acquisition and SDK adapters
were reconstructed against current main. Codec test certificates travel with
this crate and do not depend on the SDK fixture directory.

`asn1` and `timestamp::response` are private. Timestamp response interpretation
lives alongside acquisition, rather than in the shared ASN.1 codec layer.
The opt-in `sdk-compat` bridge now exposes only the legacy timestamp facts and
request structures still needed by deferred SDK profile/trust/OCSP consumers
and acquisition adapters. `verified_timestamp_info` adapts a `VerifiedTimestamp`
to the existing SDK `TstInfo` contract; it does not validate trust. CMS signer/data
types, response wrappers and token/response codecs are no longer exported.
The bridge is provisional, not a supported codec API. Legacy CMS decoding is
compiled only for codec tests. Original MPL-2.0 source notices are retained
in the codec files; surrounding code uses the repository's MIT/Apache licensing.
Unsupported legacy attribute-certificate and revocation choices remain explicit
decoding errors, represented by uninhabited types rather than unreachable
placeholder data structures.

**Release blocker:** the SDK uses a path-only dependency on this unpublished
crate. SDK packaging/publication is intentionally unsupported on this branch.
No release automation, crate publication or repository move is authorized.
The crate's name, API and compatibility feature are experimental.

## Subsequent bounded layers

1. Move X.509 chain/profile mechanics with explicit host-selected role/policy
   inputs and separate verified/profile-valid/trusted outcomes. Do not silently
   redefine role-specific EKU acceptance: #3025 remains unresolved.
2. Extract OCSP parsing and verification using the shared certificate foundation,
   then host-driven acquisition. Preserve issuer-signed responses, authoritative
   status reporting and bounded reads. #3026 verification-resource budgets remain
   unresolved; this layer neither invents budgets nor claims they are solved.
3. Move COSE verification/signing orchestration atop those primitives while the
   SDK retains C2PA/CAWG mapping, settings, resolver wiring and SDK policy.

Each layer depends on the shared codec/fact boundary below it and should carry
its own focused host-independent and SDK parity regressions. C API suspension/
resumption and response-header plumbing are separate integrations, not delivered
by this foundation. `trust.allowed_list` (#2893) is outside this extraction.

## Focused checks

Run default and bridge-enabled crate tests and Clippy separately; feature
unification in SDK tests is not proof of the default private-codec boundary.
Run SDK timestamp regressions for both crypto backends, plus the SDK crypto
regressions preserving current certificate, OCSP and COSE behavior. Check the
crate on `wasm32-unknown-unknown` and `wasm32-wasip2`; check the SDK's
Rust-native browser build. Format with
`cargo +nightly-2026-07-12 fmt --all -- --check`.

No live TSA or broad workspace test run is required for these fixture-driven
contracts; broader platform and workspace validation belongs on remote CI.
