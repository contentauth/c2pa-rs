# C2PA Signing Workflow

This document describes the internal signing call chain in `c2pa-rs`, including when
network calls to a Time Stamp Authority (TSA) and OCSP responders occur.

---

## Call Chain

The signing workflow begins at the `Builder` API and descends through store, COSE, and
raw signature layers.

```
Builder::sign / sign_embeddable / sign_file   (sdk/src/builder.rs)
    │
    ├──(optional)─────────────────────────────────────────────────────────────────┐
    │  maybe_add_timestamp                                                         │
    │  Adds a c2pa.time-stamp assertion to ingredient claims.                      │
    │  Fires a TSA HTTP request (RFC 3161) when signer.time_authority_url() set.  │
    │  See: sdk/src/assertions/timestamp.rs                          [NETWORK]     │
    │                                                                              │
    └──────────────────────────────────────────────────────────────────────────────┘
    │
    └── Store::sign_claim                      (sdk/src/store.rs)
            │  Serializes the claim to CBOR bytes. Chooses V1 or V2 timestamp
            │  storage based on claim version.
            │
            └── signing_cert_valid             (sdk/src/cose_sign.rs)
                    │  Validates end-entity certificate profile.
                    │
                    └── cose_sign()            (sdk/src/cose_sign.rs
                            │                   → sdk/src/crypto/cose/sign.rs)
                            │  Builds the COSE protected header (alg + x5chain).
                            │  Computes sig_structure_data (the "tbs" bytes).
                            │
                            └── V1 or V2?      (TimeStampStorage dispatch)
                                   │                         │
                            ┌──────┘                         └──────────────┐
                            ▼                                               ▼
                    ══════════════════                         ══════════════════════
                     V1 path (sigTst)                          V2 path (sigTst2/CTT)
                    ══════════════════                         ══════════════════════
                    Claim version ≤ 1                          Claim version > 1
                            │                                               │
                    TSA HTTP request                           RawSigner::sign
                    cose_countersign_data                      Signs the tbs bytes.
                    (payload + protected hdr)  [NETWORK]                    │
                            │                                  TSA HTTP request
                    RawSigner::sign                            CBOR(signature bytes)
                    Signs the tbs bytes.                                    │   [NETWORK]
                    Embeds sigTst in                           Embeds sigTst2 in
                    unprotected header.                        unprotected header.
                            │                                               │
                    CoseSign1 output                           CoseSign1 output
                    (sigTst)                                   (sigTst2)
```

---

## V1 vs V2 Timestamp Behavior

The key difference is **what gets timestamped and when**.

| | V1 — `sigTst` | V2 — `sigTst2` / CTT |
|---|---|---|
| **Claim version** | ≤ 1 | > 1 |
| **TSA timing** | **Before** `RawSigner::sign` | **After** `RawSigner::sign` |
| **Data counter-signed by TSA** | `cose_countersign_data(claim_payload, protected_header)` | CBOR encoding of the raw **signature bytes** |
| **Stored in** | COSE unprotected header `sigTst` | COSE unprotected header `sigTst2` |
| **Token form** | Full RFC 3161 response | Stripped to bare token bytes via `timestamptoken_from_timestamprsp` |
| **Model** | Timestamps the claim | C2PA CTT (Countersigning Timestamp Token) |
| **Implementation** | `sign_v1` in `crypto/cose/sign.rs` | `sign_v2_embedded` in same file |

---

## OCSP at Sign Time

OCSP responses are **stapled**, not fetched by the signing library itself.

1. The `Signer` / `RawSigner` implementor is responsible for pre-fetching a DER OCSP
   response and providing it via `ocsp_response()` / `ocsp_val()`.
2. Inside `build_unprotected_header` (`crypto/cose/sign.rs`), the library reads that
   value and embeds it under `rVals → ocspVals` in the COSE unprotected header.

If no OCSP response is provided, the header entry is simply omitted. The default
implementations of `Signer::ocsp_val` and `RawSigner::ocsp_response` return `None`.

> **Note:** Dynamic OCSP fetching via AIA lookup (`fetch_and_check_ocsp_response` in
> `crypto/ocsp/fetch.rs`) only occurs during **validation**, controlled by
> `OcspFetchPolicy` in `settings.verify.ocsp_fetch`. The validation path is
> entirely separate from the signing path.

---

## Optional `c2pa.time-stamp` Assertion

The `c2pa.time-stamp` manifest assertion is **distinct** from the COSE `sigTst`/`sigTst2`
mechanism.

- Triggered in `Builder::maybe_add_timestamp` (before `Store::sign_claim` runs).
- Calls `TimeStamp::refresh_timestamp` → `send_timestamp_token_request` →
  `default_rfc3161_request` — the same RFC 3161 HTTP stack used by the COSE path.
- Produces a manifest-level assertion attached to ingredient claims, not a COSE header.
- Only fires when `signer.time_authority_url()` returns `Some` and the relevant
  assertion labels are configured in settings.

---

## Network Calls Summary

| Call | Source file | What is timestamped / fetched | When |
|---|---|---|---|
| TSA for `c2pa.time-stamp` assertion | `sdk/src/assertions/timestamp.rs` | Ingredient COSE signatures | Before `sign_claim` |
| TSA for `sigTst` (V1) | `sdk/src/crypto/cose/sigtst.rs` | Claim bytes (payload + protected header) | Before `RawSigner::sign` |
| TSA for `sigTst2` (V2) | `sdk/src/crypto/cose/sigtst.rs` | Raw signature bytes | After `RawSigner::sign` |
| OCSP (signing) | Caller / `Signer` impl | n/a — caller pre-fetches | Before `sign_claim` |
| OCSP (validation) | `sdk/src/crypto/ocsp/fetch.rs` | Cert status via AIA | During verification |

---

## Async vs Sync

The codebase uses the `async_generic` macro to maintain paired sync and async
implementations throughout the signing stack:

| Sync | Async counterpart |
|---|---|
| `Signer` | `AsyncSigner` |
| `RawSigner` | `AsyncRawSigner` |
| `Store::sign_claim` | `Store::sign_claim_async` |
| `cose_sign` | `cose_sign_async` |
| `sign_v1` / `sign_v2` | `sign_v1_async` / `sign_v2_async` |
| `http_resolve` | `http_resolve_async` |

`AsyncRawSignerWrapper` wraps a sync `RawSigner` and dispatches its `sign` call on
the blocking implementation inside an `async fn sign`.

> **Behavioral note:** In `Store::sign_claim`, the sync branch sets
> `verify_timestamp_trust = false` before calling `cose_sign`, while the async branch
> passes the original settings. This is a real asymmetry to be aware of when relying on
> that flag during signing.

---

## Key Files

| File | Role |
|---|---|
| `sdk/src/builder.rs` | `Builder::sign`, `maybe_add_timestamp` |
| `sdk/src/store.rs` | `sign_manifest`, `sign_claim`, `save_to_stream`, `get_ocsp_response_ders` |
| `sdk/src/cose_sign.rs` | `cose_sign()`, `SignerWrapper` / `AsyncSignerWrapper` adapters |
| `sdk/src/crypto/cose/sign.rs` | `CoseSign1` construction, `sign_v1`, `sign_v2_embedded`, `build_unprotected_header` |
| `sdk/src/crypto/cose/sigtst.rs` | `add_sigtst_header`, `add_sigtst_header_async`, TSA request hook |
| `sdk/src/crypto/time_stamp/http_request.rs` | `default_rfc3161_request` — RFC 3161 HTTP POST to TSA |
| `sdk/src/assertions/timestamp.rs` | Manifest `TimeStamp` assertion, `refresh_timestamp` |
| `sdk/src/crypto/cose/ocsp.rs` | OCSP stapling, `OcspFetchPolicy`, `check_ocsp_status` |
| `sdk/src/crypto/ocsp/fetch.rs` | `fetch_and_check_ocsp_response` — AIA OCSP HTTP |
| `sdk/src/signer.rs` | `Signer` / `AsyncSigner` traits |
| `sdk/src/crypto/raw_signature/signer.rs` | `RawSigner` / `AsyncRawSigner` traits |
