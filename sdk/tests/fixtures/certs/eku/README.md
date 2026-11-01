# EKU regression certificates

These certificates are **test-only**, not production credentials. Each `.pub`
chain contains an ES256 leaf followed by `root.pub`. All leaves use the existing
`../es256.pem` test signing key. The root's private key is discarded.

`document.pub`, `c2pa.pub`, and `microsoft.pub` contain only their respective
signing EKU. Their `_email.pub` counterparts also contain email protection.
`email.pub` contains only email protection. `sdk/tests/trust_settings.rs`
checks the actual certificate extensions, signs and reads each chain with
default and overridden policies, and exercises concurrent independent contexts.

The certificates are valid for ten years from generation. To regenerate from
the repository root, using Bash and OpenSSL:

```bash
tmp=$(mktemp -d)
openssl ecparam -name prime256v1 -genkey -noout -out "$tmp/root.key"
openssl req -new -x509 -key "$tmp/root.key" -days 3650 -sha256 \
  -out sdk/tests/fixtures/certs/eku/root.pub \
  -subj '/O=C2PA TEST ONLY/CN=EKU Test Root' \
  -addext 'basicConstraints=critical,CA:TRUE' \
  -addext 'keyUsage=critical,keyCertSign,cRLSign'
openssl req -new -key sdk/tests/fixtures/certs/es256.pem \
  -out "$tmp/leaf.csr" -subj '/O=C2PA TEST ONLY/CN=EKU Test Signer'
for entry in \
  'document 1.3.6.1.5.5.7.3.36' \
  'c2pa 1.3.6.1.4.1.62558.2.1' \
  'microsoft 1.3.6.1.4.1.311.76.59.1.9' \
  'email 1.3.6.1.5.5.7.3.4'; do
  read -r name oid <<< "$entry"
  for suffix in '' '_email'; do
    if [ "$name" = email ] && [ -n "$suffix" ]; then continue; fi
    eku="$oid"
    if [ -n "$suffix" ]; then eku="$eku,1.3.6.1.5.5.7.3.4"; fi
    openssl x509 -req -in "$tmp/leaf.csr" \
      -CA sdk/tests/fixtures/certs/eku/root.pub -CAkey "$tmp/root.key" \
      -set_serial "0x$(openssl rand -hex 8)" -days 3650 -sha256 \
      -out "$tmp/leaf.pub" \
      -extfile <(printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=%s\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n' "$eku")
    cat "$tmp/leaf.pub" sdk/tests/fixtures/certs/eku/root.pub \
      > "sdk/tests/fixtures/certs/eku/$name$suffix.pub"
  done
done
rm "$tmp/root.key" "$tmp/leaf.csr" "$tmp/leaf.pub"
rmdir "$tmp"
```
