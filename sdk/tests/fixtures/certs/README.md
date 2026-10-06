# Sample certificates

This folder contains certificates and signing keys that are used by unit tests and sample applications.  The certificates are not intended for production use.  

The certificates are organized by supported C2PA signing algorithm.  For each supported signing algorithm (ps256, ps384, ps512, es256, es384, Ees512, ed25519) there are three files.
* {alg}.pem - private signing key in PEM format
* {alg}.pub - certificate chain from signing certificate to the last certificate before the root CA, as a concatenated list of certficates
* {alg}_root.pub_key - public key of the root CA used to verify the last certificate in the certificate chain.

## Certificates with missing attributes

`es256_no_org.{pem,pub}` is an ES256 key and chain whose end-entity certificate
deliberately omits the `O=` (Organization) attribute.  Every other chain here
carries one, so this is the only fixture that exercises the missing-attribute
path in `Verifier::verify_signature`.

Unlike the chains above, these were generated locally rather than obtained from
a certificate authority.  To regenerate them:

```sh
openssl ecparam -name prime256v1 -genkey -noout -out ca.sec1.key
openssl req -new -x509 -key ca.sec1.key -days 3650 -out ca.pem \
  -subj "/C=US/ST=CA/L=Somewhere/O=C2PA Test Intermediate Root CA/OU=FOR TESTING_ONLY/CN=Intermediate CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign"

# Note the missing O= in the end-entity subject.
openssl ecparam -name prime256v1 -genkey -noout -out leaf.sec1.key
openssl req -new -key leaf.sec1.key -out leaf.csr \
  -subj "/C=US/ST=CA/L=Somewhere/OU=FOR TESTING_ONLY/CN=C2PA Signer"
openssl x509 -req -in leaf.csr -CA ca.pem -CAkey ca.sec1.key -CAcreateserial \
  -days 3650 -sha256 -out leaf.pem \
  -extfile <(printf "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n")

openssl pkcs8 -topk8 -nocrypt -in leaf.sec1.key -out es256_no_org.pem
cat leaf.pem ca.pem > es256_no_org.pub
```

## More info

For more information, see the C2PA technical specification:
-  [Digital signatures](https://c2pa.org/specifications/specifications/2.3/specs/C2PA_Specification.html#_digital_signatures)
- [Trust model](https://c2pa.org/specifications/specifications/2.3/specs/C2PA_Specification.html#_trust_model)
