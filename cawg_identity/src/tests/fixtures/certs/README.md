# Sample certificates

This folder contains certificates and signing keys that are used by unit tests and sample applications. The certificates are not intended for production use.  

The certificates are organized by supported C2PA signing algorithm. For each supported signing algorithm (ps256, ps384, ps512, es256, es384, Ees512, ed25519) there are three files.
* {alg}.pem - private signing key in PEM format
* {alg}.pub - certificate chain from signing certificate to the last certificate before the root CA, as a concatenated list of certficates
* {alg}_root.pub_key - public key of the root CA used to verify the last certificate in the certificate chain.

## More info

For more information on digital signatures and the C2PA trust model see [https://c2pa.org/specifications/specifications/1.0/specs/C2PA_Specification.html#_digital_signatures] and [https://c2pa.org/specifications/specifications/1.0/specs/C2PA_Specification.html#_credential_types]
