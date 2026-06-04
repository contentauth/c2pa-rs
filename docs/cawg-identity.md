# Using the CAWG identity assertion

The CAI Rust library includes an implementation of the [Creator Assertions Working Group (CAWG) identity assertion specification](https://cawg.io/identity/1.1-draft).

## Trusting identity claims aggregation (ICA) issuers

An identity claims aggregation credential is signed by an issuer identified by a DID (for example a `did:web` or `did:jwk`). A valid signature only proves that the credential was signed by whoever controls that DID — it does **not**, on its own, establish that the issuer is trustworthy. In particular, a self-issued `did:jwk` can be minted by anyone, so accepting it as trusted would let an attacker assert any identity.

For this reason, the library treats ICA issuers as untrusted unless they appear on an explicit allow-list. Configure the allow-list through the `cawg_trust.trusted_ica_issuers` setting, which is a list of exact DID strings (any DID method):

```json
{
  "cawg_trust": {
    "trusted_ica_issuers": [
      "did:web:issuer.example.com"
    ]
  }
}
```

The DID of the credential's `issuer` (with any fragment removed) is compared, using exact string matching, against this list.

* If the issuer is on the list, validation can proceed to the success code `cawg.ica.credential_valid`.
* If the issuer is **not** on the list, the failure code `cawg.ica.untrusted_issuer` is reported for that identity assertion and `cawg.ica.credential_valid` is withheld.

The default value is empty, meaning that **no** ICA issuer is trusted. This is a deliberate secure default; populate the list with the issuers you trust.

The `cawg.ica.untrusted_issuer` result is scoped to the individual identity assertion. Like an untrusted C2PA signing certificate, it does not by itself make the enclosing manifest's `validation_state` `Invalid`, nor does it downgrade a manifest that is otherwise `Trusted` on the basis of its own C2PA signer.

These settings are read from the [`Context`](https://docs.rs/c2pa/latest/c2pa/struct.Context.html) under which validation is performed. When using the explicit post-validation API, construct the validator with that context via `CawgValidator::new(&context)`.

## Known limitations

The library does not currently support the following optional fields from the CAWG identity assertion:
* `expected_partial_claim`
* `expected_claim_generator`
* `expected_countersigners`

## Example

The code in [`sdk/examples/cawg.rs`](https://github.com/contentauth/c2pa-rs/blob/main/sdk/examples/cawg.rs) provides a minimal example of signing and verifying a claim including a CAWG identity assertion.  Run it by entering the command:

```sh
cargo run --example cawg -- <SOURCE_FILE> <OUTPUT_FILE>
```

Where `<SOURCE_FILE>` is the relative path to the input asset file and `<OUTPUT_FILE>` is the relative path where the example saves the resulting asset file containing the CAWG identity assertion.

```sh
cargo run --example cawg -- ./sdk/tests/fixtures/CA.jpg cawg-out.jpg
```

Example assertion:

```json
...
"assertions": [
  {
    "label": "c2pa.actions",
    "data": {
      "actions": [
        {
          "action": "c2pa.opened"
        }
      ]
    }
  },
  {
    "label": "cawg.identity",
    "data": {
      "signer_payload": {
        "referenced_assertions": [
          {
            "url": "self#jumbf=c2pa.assertions/c2pa.hash.data",
            "hash": "Vw/g3K8zOlhOOEk1GZmMLgqXVZKUbaxUxRLWvm0C30s="
          }
        ],
        "sig_type": "cawg.x509.cose"
      },
      "signature_info": {
        "alg": "Ed25519",
        "issuer": "C2PA Test Signing Cert",
        "cert_serial_number": "638838410810235485828984295321338730070538954823",
        "revocation_status": true
      }
    }
  },
  ...
]
```

C2PA Tool also displays CAWG identity assertions.
