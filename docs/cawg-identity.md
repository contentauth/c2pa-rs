# Using the CAWG identity assertion

The CAI Rust library includes an implementation of the [1.1 draft of the Creator Assertions Working Group (CAWG) identity assertion specification](https://cawg.io/identity/1.1-draft).

The code in [`cawg_identity/examples/cawg.rs`](https://github.com/contentauth/c2pa-rs/blob/main/cawg_identity/examples/cawg.rs) provides a minimal example of signing and verifying a claim including a CAWG identitiy assertion.  Run it by entering the command:

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