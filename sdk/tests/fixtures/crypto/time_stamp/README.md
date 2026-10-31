# Sample time stamps

RFC 3161 time-stamp tokens used by unit tests. They are not issued by a real time stamping authority: each is signed with the `es256` test key and certificate in `../raw_signature`, and stamps the binary string "some sample content to sign".

* `unsorted_signed_attrs.tst` - the signed attributes are encoded in the order `messageDigest`, `contentType`, which is not the sorted order DER requires, and the signature covers that encoding.

RFC 5652 sections 5.3 and 5.4 require DER-encoded signed attributes, including canonical `SET OF` ordering. The unsorted fixture is deliberately nonconforming and tests an interoperability allowance; accepting it does not make its encoding RFC-compliant.

The unit tests also construct forged tokens by changing the `TSTInfo` message imprint and a second signer's `messageDigest` while copying the genuine signature. They assert rejection for both signer orders, for a modified signer alone, and for duplicate signatures in both unsorted and correctly DER-sorted tokens. A single correctly DER-sorted signer remains valid.
