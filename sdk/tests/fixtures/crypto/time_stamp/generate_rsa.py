#!/usr/bin/env python3
# Copyright 2026 Adobe. All rights reserved.
# This file is licensed under the terms of the MIT license or Apache License 2.0.
# You may obtain a copy of the license at https://opensource.org/licenses/MIT
# or https://www.apache.org/licenses/LICENSE-2.0.

"""Generate synthetic offline RSA timestamp fixtures with OpenSSL 3."""

from datetime import datetime, timezone
import hashlib
from pathlib import Path
import subprocess
import tempfile


def run(*args):
    subprocess.run(["openssl", *map(str, args)], check=True)


def tlv(tag, body):
    length = len(body)
    encoded = length.to_bytes(max(1, (length.bit_length() + 7) // 8), "big")
    prefix = bytes([length]) if length < 128 else bytes([128 + len(encoded)]) + encoded
    return bytes([tag]) + prefix + body


def oid(value):
    components = list(map(int, value.split(".")))
    body = bytes([40 * components[0] + components[1]])
    for component in components[2:]:
        encoded = [component & 127]
        component >>= 7
        while component:
            encoded.insert(0, 128 | (component & 127))
            component >>= 7
        body += bytes(encoded)
    return tlv(6, body)


def main():
    output = Path(__file__).resolve().parent
    data = b"RSA timestamp regression"
    with tempfile.TemporaryDirectory() as directory:
        scratch = Path(directory)
        key = scratch / "tsa.key"
        cert = scratch / "tsa.crt"
        run(
            "req", "-x509", "-newkey", "rsa:2048", "-noenc", "-keyout", key,
            "-out", cert, "-days", "3650", "-set_serial", "1",
            "-subj", "/CN=Synthetic RSA timestamp regression",
            "-addext", "basicConstraints=critical,CA:FALSE",
            "-addext", "keyUsage=critical,digitalSignature",
            "-addext", "extendedKeyUsage=critical,timeStamping",
            "-addext", "subjectKeyIdentifier=hash",
        )
        gen_time = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%SZ").encode()
        integer_one = tlv(2, b"\x01")
        imprint = tlv(0x30, tlv(0x30, oid("2.16.840.1.101.3.4.2.1") + b"\x05\x00")
                      + tlv(4, hashlib.sha256(data).digest()))
        tst = tlv(0x30, integer_one + oid("1.2.3.4") + imprint
                  + integer_one + tlv(0x18, gen_time))
        content = scratch / "tst.der"
        content.write_bytes(tst)
        for name, digest, salt in [
            ("ps256", "sha256", "digest"),
            ("ps384", "sha384", "digest"),
            ("ps512", "sha512", "digest"),
            ("ps256-salt0", "sha256", "0"),
            ("ps256-saltmax", "sha256", "max"),
            ("rsa-pkcs1", "sha256", None),
        ]:
            token = output / f"{name}.tst"
            options = [] if salt is None else [
                "-keyopt", "rsa_padding_mode:pss",
                "-keyopt", f"rsa_pss_saltlen:{salt}",
                "-keyopt", f"rsa_mgf1_md:{digest}",
            ]
            run("cms", "-sign", "-binary", "-nodetach", "-nosmimecap",
                "-in", content, "-signer", cert, "-inkey", key, "-md", digest,
                "-econtent_type", "1.2.840.113549.1.9.16.1.4",
                "-outform", "DER", "-out", token, *options)
            run("cms", "-verify", "-binary", "-inform", "DER", "-in", token,
                "-noverify", "-out", scratch / "verified.der")
            assert (scratch / "verified.der").read_bytes() == tst


if __name__ == "__main__":
    main()
