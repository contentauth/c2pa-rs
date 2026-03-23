# Using an X.509 certificate for CAWG signing

The `c2patool` uses some custom properties in the `cawg_x509_signer` section of the settings file for signing:

- `private_key`: Path to the private key file.
- `sign_cert`: Path to the signing certificate file.
- `alg`: Algorithm to use, if not the default ES256.

Both the private key and signing certificate must be in PEM (privacy-enhanced mail) format. The signing certificate must contain a PEM certificate chain starting with the end-entity certificate used to sign the claim ending with the intermediate certificate before the root CA certificate. 

If the settings file doesn't include the `cawg_x509_signer.sign_cert` and `cawg_x509_signer.private_key` properties, c2patool will not generate a CAWG identity assertion. An example settings file demonstrating how this works is provided in the [c2patool repo sample folder](https://github.com/contentauth/c2pa-rs/tree/main/cli/tests/fixtures/trust/cawg_sign_settings.toml). 

If you are using a signing algorithm other than the default `es256`, specify it in the manifest definition field `alg` with one of the following values:

- `ps256`
- `ps384`
- `ps512`
- `es256`
- `es384`
- `es512`
- `ed25519`

The specified algorithm must be compatible with the values of private key and signing certificate.  For more information, see [Signing manfiests](https://opensource.contentauthenticity.org/docs/signing-manifests).

To sign an asset using this technique, adapt the following command-line invocation:

```sh
$ c2patool \
    --settings (path to settings.toml file) \
    (path to source file) \
    -m (path to manifest definition file) \
    -o (path to output file)
```
