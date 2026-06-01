# Using an X.509 certificate for CAWG signing

`c2patool` supports two ways to attach a CAWG X.509 identity assertion to a signed asset:

- [Settings-only signing](#settings-only-signing) — provide the private key and certificate directly in the settings file. The tool signs the CAWG assertion internally.
- [Subprocess signing with `--identity-signer-path`](#subprocess-signing-with---identity-signer-path) — delegate CAWG signing to an external executable. Use this when the private key is not accessible on the machine running the tool (for example, when it lives in an HSM or remote signing service).

Both methods require a C2PA signer to already be configured (via the `[signer]` section of the settings file, or `--signer-path`). The CAWG identity assertion is signed independently of the C2PA claim signature.

## Settings-only signing

Add a `[cawg_x509_signer.local]` section to the settings file. The CAWG settings are entirely independent of the C2PA `[signer]` settings — each has its own certificate, private key, algorithm, and optional TSA URL.

| Field | Required | Description |
|---|---|---|
| `sign_cert` | Yes | Signing certificate in PEM format (chain from end-entity to intermediate). |
| `private_key` | Yes | Private key in PEM format. |
| `alg` | No | Signing algorithm (default: `es256`). |
| `tsa_url` | No | URL of a timestamp authority. |
| `referenced_assertions` | No | Assertion labels to include in the identity assertion. |
| `roles` | No | Named actor roles to attach to the identity assertion. |

If `sign_cert` and `private_key` are absent from `[cawg_x509_signer]`, no CAWG identity assertion is generated.

Supported algorithm values: `ps256`, `ps384`, `ps512`, `es256`, `es384`, `es512`, `ed25519`. The algorithm must be compatible with the private key and signing certificate. For more information, see [Signing manifests](https://opensource.contentauthenticity.org/docs/signing-manifests).

An example settings file is provided in the [c2patool repo sample folder](https://github.com/contentauth/c2pa-rs/tree/main/cli/tests/fixtures/trust/cawg_sign_settings.toml).

To sign an asset using this method:

```sh
$ c2patool \
    --settings (path to settings.toml file) \
    (path to source file) \
    -m (path to manifest definition file) \
    -o (path to output file)
```

## Subprocess signing with `--identity-signer-path`

Use `--identity-signer-path` to delegate signing of the CAWG identity assertion bytes to an external executable. The C2PA claim signature is still handled by the normal signer configuration.

The subprocess protocol is identical to `--signer-path`: the tool writes the bytes to be signed to the executable's `stdin`, and the executable must write the raw signature bytes to `stdout`.

The `[cawg_x509_signer.local]` settings section is **required** when using `--identity-signer-path`. It must supply `sign_cert` and `alg` so the tool can construct the identity assertion; `private_key` is not needed since the subprocess handles signing. `tsa_url` is optional.

```toml
[cawg_x509_signer.local]
alg = "es256"
sign_cert = """-----BEGIN CERTIFICATE-----
...
-----END CERTIFICATE-----
"""
# tsa_url = "https://timestamp.example.com"
```

To sign an asset using a subprocess for CAWG identity signing:

```sh
$ c2patool \
    --settings (path to settings.toml file) \
    --identity-signer-path (path to signing executable) \
    (path to source file) \
    -m (path to manifest definition file) \
    -o (path to output file)
```

If you need to reserve extra space for the signature, use `--reserve-size` (default: 20000):

```sh
$ c2patool \
    --settings (path to settings.toml file) \
    --identity-signer-path (path to signing executable) \
    --reserve-size 20248 \
    (path to source file) \
    -m (path to manifest definition file) \
    -o (path to output file)
```
