# Sample certificates

This folder contains certificates, private keys, and signature results that are used by unit tests. These certificates are not intended for production use.  

The certificates are organized by supported C2PA signing algorithm. For each supported signing algorithm (ps256, ps384, ps512, es256, es384, es512, ed25519), there are four files:

* {alg}.priv - private signing key in PEM format
* {alg}.pub - certificate chain from signing certificate to the last certificate before the root CA, as a concatenated list of certficates
* {alg}.pub_key - raw signature public key extracted from the certificate
* {alg}.raw_sig - raw signature value over the exact binary string "some sample content to sign"

The `legacy` folder contains additional sample files for raw signature algorithms that are supported but only for RFC 3161 time stamp services.
