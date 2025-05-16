# Cryptographic library support

`c2pa` will use different cryptography libraries depending on which platform and feature flags are used:

## Signing

| C2PA `SigningAlg` | Default (*) | `feature = "rust_native_crypto"` (*) | WASM |
| --- | --- | --- | --- |
| `es256` | OpenSSL | `p256` | `p256` |
| `es384` | OpenSSL | `p384` | `p384` |
| `es512` | OpenSSL | OpenSSL | ❌ |
| `ed25519` | OpenSSL | `ed25519-dalek` | `ed25519-dalek` |
| `ps256` | OpenSSL | `rsa` | `rsa` |
| `ps384` | OpenSSL | `rsa` | `rsa` |
| `ps512` | OpenSSL | `rsa` | `rsa` |

(*) Applies to all supported platforms except WASM <br />
❌ = not supported

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
