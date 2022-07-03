# Copyright 2022 Adobe. All rights reserved.
# This file is licensed to you under the Apache License,
# Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
# or the MIT license (http://opensource.org/licenses/MIT),
# at your option.

# Unless required by applicable law or agreed to in writing,
# this software is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR REPRESENTATIONS OF ANY KIND, either express or
# implied. See the LICENSE-MIT and LICENSE-APACHE files for the
# specific language governing permissions and limitations under
# each license.

import subprocess
import os

def get_fixtures_directory():
    file_directory = os.path.dirname(os.path.realpath(__file__))
    root_directory = subprocess.Popen(["git", "rev-parse", "--show-toplevel"], stdout=subprocess.PIPE, cwd=file_directory).communicate()[0].rstrip().decode("utf-8")
    path_to_fixtures = os.path.join(*["sdk", "tests", "fixtures", "rustls"])
    return os.path.join(root_directory, path_to_fixtures)

FIXTURES_SPECIFICS = {
    "rs256": {
        "sha": "-sha256",
        "algorithm": "RSA",
    },
    "rs384": {
        "sha": "-sha384",
        "algorithm": "RSA",
    },
    "rs512": {
        "sha": "-sha512",
        "algorithm": "RSA",
    },
    "ps256": {
        "sha": "-sha256",
        "algorithm": "RSA-PSS",
    },
    "ps384": {
        "sha": "-sha384",
        "algorithm": "RSA-PSS",
    },
    "ps512": {
        "sha": "-sha512",
        "algorithm": "RSA-PSS",
    },
    "es256": {
        "sha": "-sha256",
        "algorithm": "EC -pkeyopt ec_paramgen_curve:P-256", # TODO: leave stone age.
    },
    "es384": {
        "sha": "-sha384",
        "algorithm": "EC -pkeyopt ec_paramgen_curve:P-384",
    },
    # "ed25519": {
    #     "sha": "-sha512",
    #     "algorithm": "ED25519",
    # },
}

def get_fixture_data(test_id):
    fixtures_dir = get_fixtures_directory()

    return {**{
        "private_key": os.path.join(fixtures_dir, "%s_private_key.pem" % test_id),
        "public_key": os.path.join(fixtures_dir, "%s_public_key.pem" % test_id),
        "public_key_der": os.path.join(fixtures_dir, "%s_public_key.der" % test_id),
        "signed_data": os.path.join(fixtures_dir, "%s_signed_data.sign" % test_id),
        "fixtures_data": os.path.join(fixtures_dir, "../data.data"),
    }, **FIXTURES_SPECIFICS[test_id]}

def generate_fixtures_rsa(data):
    cmds = [
        "openssl genpkey -algorithm {algorithm} -out {private_key}".format(**data), # generate private key
        "openssl rsa -in {private_key} -pubout -out {public_key}".format(**data), # extract public key
        "openssl rsa -pubin -in {public_key} -inform PEM -outform DER -out {public_key_der}".format(**data), # public key as der
        "openssl dgst {sha} -sign {private_key} -out {signed_data} {fixtures_data}".format(**data), # sign data
        "openssl dgst {sha} -verify {public_key} -signature {signed_data} {fixtures_data}".format(**data), # verify signature
    ]

    for cmd in cmds:
        proc = subprocess.Popen([it for it in cmd.split(" ") if it])
        print(cmd)
        proc.wait()

def generate_fixtures_rsa_pss(data):
    # https://lwn.net/Articles/851981/
    cmds = [
        "openssl genpkey -algorithm {algorithm} -out {private_key}".format(**data), # generate private key
        "openssl pkey -in {private_key} -pubout -out {public_key}".format(**data), # extract public key
        "openssl rsa -pubin -in {public_key} -inform PEM -outform DER -out {public_key_der}".format(**data), # public key as der
        "openssl dgst {sha} -sign {private_key} -sigopt rsa_pss_saltlen:-1 -out {signed_data} {fixtures_data}".format(**data), # sign data
        "openssl dgst {sha} -verify {public_key} -sigopt rsa_padding_mode:pss -signature {signed_data} {fixtures_data}".format(**data), # verify signature
    ]

    for cmd in cmds:
        proc = subprocess.Popen([it for it in cmd.split(" ") if it])
        print(cmd)
        proc.wait()

def generate_fixtures_ecdsa(data):
    cmds = [
        "openssl genpkey -algorithm {algorithm} -out {private_key}".format(**data), # generate private key
        "openssl ec -in {private_key} -pubout -out {public_key}".format(**data), # extract public key
        "openssl ec -pubin -in {public_key} -inform PEM -outform DER -out {public_key_der}".format(**data), # public key as der
        "openssl dgst {sha} -sign {private_key} -out {signed_data} {fixtures_data}".format(**data), # sign data
        "openssl dgst {sha} -verify {public_key} -signature {signed_data} {fixtures_data}".format(**data), # verify signature
    ]

    for cmd in cmds:
        proc = subprocess.Popen([it for it in cmd.split(" ") if it])
        print(cmd)
        proc.wait()


if __name__ == "__main__":
    # RSA_PKCS1_2048_8192_SHA256
    # RSA keys of 2048-8192
    # PKCS#1.5 padding
    # SHA-256
    generate_fixtures_rsa(get_fixture_data("rs256"))

    # RSA_PKCS1_2048_8192_SHA256
    # RSA keys of 2048-8192
    # PKCS#1.5 padding
    # SHA-384
    generate_fixtures_rsa(get_fixture_data("rs384"))

    # RSA_PKCS1_2048_8192_SHA256
    # RSA keys of 2048-8192
    # PKCS#1.5 padding
    # SHA-512
    generate_fixtures_rsa(get_fixture_data("rs512"))

    # RSA_PSS_2048_8192_SHA256
    # RSA keys of 2048-8192
    # PSS padding
    # SHA-256
    generate_fixtures_rsa_pss(get_fixture_data("ps256"))

    # RSA_PSS_2048_8192_SHA256
    # RSA keys of 2048-8192
    # PSS padding
    # SHA-384
    generate_fixtures_rsa_pss(get_fixture_data("ps384"))

    # RSA_PSS_2048_8192_SHA256
    # RSA keys of 2048-8192
    # PSS padding
    # SHA-512
    generate_fixtures_rsa_pss(get_fixture_data("ps512"))

    # ECDSA_P256_SHA256_ASN1
    # ASN.1 DER-encoded ECDSA
    # P-256
    # SHA-256
    generate_fixtures_ecdsa(get_fixture_data("es256"))

    # ECDSA_P384_SHA384_ASN1
    # ASN.1 DER-encoded ECDSA
    # P-384
    # SHA-384
    generate_fixtures_ecdsa(get_fixture_data("es384"))

    # ED25519
    # SHA-512
    # generate_fixtures(get_fixture_data("ed25519"))
