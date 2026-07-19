# Signing assets with c2patool

C2PA assets may carry two independent signatures:

- **C2PA claim signature** (required to create a manifest): identifies the tool or service that created the manifest.
- **CAWG identity assertion** (optional): cryptographically binds a named identity (person or organization) to the asset.

Each signature is produced by a separate signer. Both signers are configured independently and may use different keys and certificates.

> **Private keys in settings files are for development and testing only.** In production, use a subprocess signer or a remote signing service so that private key material never passes through c2patool.

---

## Signing options

| Method | C2PA claim | CAWG identity |
|---|---|---|
| Subprocess signer | `--signer-path` | `--identity-signer-path` |
| Remote signing service | `[signer.remote]` in settings | _(not yet supported)_ |
| Settings with private key _(testing only)_ | `[signer.local]` in settings | `[cawg_x509_signer.local]` in settings |
| Manifest fields _(testing only)_ | `sign_cert` + `private_key` in manifest JSON | — |

---

## Subprocess signer protocol

A subprocess signer is any executable that implements two operations: **info** and **sign**. The same protocol applies to both `--signer-path` and `--identity-signer-path`.

### Info query (`--signer-info`)

Before signing, c2patool calls the subprocess with `--signer-info` to discover the signing certificate and algorithm. The subprocess must write a JSON object to stdout and exit 0:

```json
{
  "alg": "es256",
  "sign_cert": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n",
  "tsa_url": "https://timestamp.example.com"
}
```

| Field | Required | Description |
|---|---|---|
| `alg` | Yes | Signing algorithm. One of `ps256`, `ps384`, `ps512`, `es256`, `es384`, `es512`, `ed25519`. |
| `sign_cert` | Yes | PEM certificate chain, from end-entity certificate to intermediate CA. |
| `tsa_url` | No | URL of a timestamp authority. |
| `reserve_size` | No | Bytes to reserve in the asset for the signature. The signer knows its own maximum signature size. If absent, a default based on the certificate size is used. |

If cert and algorithm are already configured in settings (see [Settings-only signing](#settings-only-signing-testing-only) below), the info query is skipped and those values are used directly.

### Signing

When signing, c2patool writes the bytes to be signed to the subprocess's stdin. The subprocess must write the raw signature bytes to stdout and exit 0.

### Error handling

If the subprocess exits with a non-zero status, c2patool treats it as a signing failure and surfaces the subprocess's stderr output in the error message. c2patool does not retry.

If the subprocess exits 0 but writes nothing to stdout, c2patool also returns an error.

### Reserve size

c2patool must reserve space in the asset file for the signature before calling the signer. The signer declares how much space it needs by returning `reserve_size` in the `--signer-info` response. If the field is absent, c2patool uses a default based on the certificate size.

> **Deprecated:** When cert and algorithm are supplied via settings rather than `--signer-info`, c2pa tool passes `--alg` and `--reserve-size` to the subprocess for backwards compatibility. This behavior will be removed in a future release.

---

## Signing with a subprocess signer

### C2PA claim signing (`--signer-path`)

```sh
c2patool image.jpg \
    --manifest manifest.json \
    --signer-path ./my-signer \
    -o signed.jpg
```

The value of `--signer-path` is a command string: a binary path optionally followed by arguments. For example:

```sh
--signer-path "my-kms-wrapper --profile production"
```

### CAWG identity signing (`--identity-signer-path`)

```sh
c2patool image.jpg \
    --manifest manifest.json \
    --signer-path ./my-c2pa-signer \
    --identity-signer-path ./my-identity-signer \
    -o signed.jpg
```

The C2PA and CAWG signers are independent. They may be the same executable or different ones.

---

## Signing with a remote service

Configure a remote signing service in the settings file under `[signer.remote]`:

```toml
[signer.remote]
url = "https://signing.example.com/sign"
alg = "es256"
sign_cert = """-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----
"""
```

c2patool sends a POST request with the bytes to sign as the body and expects the raw signature bytes in the response.

---

## Settings-only signing (testing only)

For development and testing, you can provide the private key directly in the settings file. **Do not use this in production.**

### C2PA claim

```toml
[signer.local]
alg = "es256"
sign_cert = """-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----
"""
private_key = """-----BEGIN PRIVATE KEY-----
...
-----END PRIVATE KEY-----
"""
tsa_url = "https://timestamp.digicert.com"
```

Alternatively, put `sign_cert` and `private_key` as file paths in the manifest JSON, or set the `C2PA_SIGN_CERT` and `C2PA_PRIVATE_KEY` environment variables.

If no signer is configured at all, c2patool uses a built-in test certificate and key. This is only suitable for development.

### CAWG identity assertion

```toml
[cawg_x509_signer.local]
alg = "es256"
sign_cert = """-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----
"""
private_key = """-----BEGIN PRIVATE KEY-----
...
-----END PRIVATE KEY-----
"""
tsa_url = "https://timestamp.digicert.com"
referenced_assertions = ["c2pa.actions"]
roles = ["creator"]
```

If `[cawg_x509_signer]` is absent, no CAWG identity assertion is generated.

An example settings file is in the [c2patool repo sample folder](https://github.com/contentauth/c2pa-rs/tree/main/cli/tests/fixtures/trust/cawg_sign_settings.toml).

---

## Writing your own signer

A signer is any executable that implements the two-operation protocol described above. It does not need to be written in Rust or have any knowledge of C2PA internals.

A minimal signer in shell (for illustration only — not for production):

```sh
#!/bin/sh
if [ "$1" = "--signer-info" ]; then
    echo '{"alg":"es256","sign_cert":"-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----\n"}'
    exit 0
fi
# Read bytes from stdin, sign them, write raw signature to stdout
openssl dgst -sha256 -sign my-key.pem
```

In practice, a production signer would:

1. Implement `--signer-info` by fetching the certificate from the KMS/HSM/keychain.
2. Implement signing by sending the stdin bytes to the KMS/HSM/keychain API and writing the returned signature to stdout.
3. Handle its own authentication (API tokens, IAM roles, PIN prompts, etc.) internally — c2patool has no involvement in that.
4. Exit non-zero and write a diagnostic to stderr on failure.

The signer is responsible for all key management. c2patool only sees the public certificate (from `--signer-info`) and the resulting signature bytes.

---

## Supported algorithms

| Value | Algorithm |
|---|---|
| `ps256` | RSASSA-PSS with SHA-256 |
| `ps384` | RSASSA-PSS with SHA-384 |
| `ps512` | RSASSA-PSS with SHA-512 |
| `es256` | ECDSA with SHA-256 (default) |
| `es384` | ECDSA with SHA-384 |
| `es512` | ECDSA with SHA-512 |
| `ed25519` | EdDSA |

The algorithm must be compatible with the private key and signing certificate. For more information, see [Signing manifests](https://opensource.contentauthenticity.org/docs/signing-manifests).
