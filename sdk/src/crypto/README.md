# Cryptographic library support

`c2pa` will use different cryptography libraries depending on which platform and feature flags are used:

Signing and signature validation are provided by `c2pa_raw_crypto` 0.2.0.
Its Rust-native ECDSA backend uses `ecdsa` 0.17 and `p256`, `p384`, and `p521`
0.14 together. This includes the upstream RFC6979 fixes and P-521 private-key
zeroization support. P-521 signing now uses deterministic RFC6979, like P-256
and P-384.

## Signing

| C2PA `SigningAlg` | Default (*) | `feature = "rust_native_crypto"` (*) | WASM |
| --- | --- | --- | --- |
| `es256` | OpenSSL | `p256` | `p256` |
| `es384` | OpenSSL | `p384` | `p384` |
| `es512` | OpenSSL | `p521` | `p521` |
| `ed25519` | OpenSSL | `ed25519-dalek` | `ed25519-dalek` |
| `ps256` | OpenSSL | `rsa` | `rsa` |
| `ps384` | OpenSSL | `rsa` | `rsa` |
| `ps512` | OpenSSL | `rsa` | `rsa` |

(*) Applies to all supported platforms except WASM <br />

## Validation

| C2PA `SigningAlg` | Default (*) | `feature = "rust_native_crypto"` (*) or WASM |
| --- | --- | --- |
| `es256` | OpenSSL | `p256` |
| `es384` | OpenSSL | `p384` |
| `es512` | OpenSSL | `p521` |
| `ed25519` | OpenSSL | `ed25519-dalek` |
| `ps256` | OpenSSL | `rsa` |
| `ps384` | OpenSSL | `rsa` |
| `ps512` | OpenSSL | `rsa` |

(*) Applies to all supported platforms except WASM
