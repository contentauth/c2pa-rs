# Sample time stamps

RFC 3161 time-stamp tokens used by unit tests. They are not issued by a real time stamping authority: each is signed with the `es256` test key and certificate in `../raw_signature`, and stamps the binary string "some sample content to sign".

* `unsorted_signed_attrs.tst` - the signed attributes are encoded in the order `messageDigest`, `contentType`, which is not the sorted order DER requires, and the signature covers that encoding.
