# c2patool - C2PA command line tool

c2patool is a command line tool for working with C2PA [manifests](https://c2pa.org/specifications/specifications/1.0/specs/C2PA_Specification.html#_manifests). Currently, the tool supports:

- Reading a JSON report of C2PA manifests in [supported file formats](#supported-file-formats)
- Reading a low-level report of C2PA manifest data in [supported file formats](#supported-file-formats)
- Previewing manifest data from a [manifest definition](#manifest-definition-format)
- Adding a C2PA manifest to [supported file formats](#supported-file-formats)

## Supported file formats

- `image/jpeg`
- `image/png`

## Installation

### via Homebrew

You can install c2patool on Mac and Linux via [Homebrew](https://brew.sh/):

```shell
brew tap contentauth/tools
brew install c2patool
```

### Building from source

If you have Rust installed, you can build c2patool from source:

```shell
git clone git@github.com:contentauth/c2patool.git
cargo build
```

## Optional prerequisites

### Manifest definition format

Writing or previewing a manifest requires you to provide a manifest definition, which is a JSON data structure
that describes the manifest data. The JSON schema for this file is available at [`schemas/manifest-definition.json`](./schemas/manifest-definition.json).

**Note:** Any file references specified will be relative to the location of the manifest definition file.

### Creating certificates

You should be able to test creating your own manifests using pre-built certificates supplied with this tool. However, if
you want to create your own official certificates, please reference the section titled ["Creating and using an X.509 certificate"](#creating-and-using-an-x509-certificate).

## Usage

**Note:** You can check out this repository locally to run the example code below.

### Displaying manifest data

Invoking the tool with a path to an asset will output a JSON report of the manifests contained in the file.

```shell
c2patool image.jpg
```

### Detailed manifest report

The `-d` option will output a detailed JSON report of the internal C2PA structure.

```shell
c2patool image.jpg -d
```

### Previewing a manifest

If a path to a JSON manifest definition file is given, the tool will generate a new manifest using the values given in the definition. This will print the report to stdout.

```shell
# output to screen
c2patool sample/test.json

# redirect to file
c2patool sample/test.json > report.json
```

The [manifest definition](#manifest-definition-format) can also be passed on the command line as a string using the `-c` or `--config` option:

```shell
c2patool -c '{"assertions": [{"label": "org.contentauth.test", "data": {"name": "Jane Doe"}}]}'
```
 
### Adding a manifest to a file

#### Writing the manifest

You can add C2PA data to a file by passing a [manifest definition](#manifest-definition-format) JSON file together with a path to a supported file extension (e.g. PNG) specified by the output (`-o`) flag.

If the output file already exists, any C2PA data in that file will be replaced and the asset maintained. If the output doesn't exist and a parent file is available, the parent will be copied to the output and the C2PA data will be added.

#### Overriding the parent file

When using a JSON file, the parent file can be specified by passing `-p` or `--parent` with the path to the file. This allows using the same manifest definition with different parent assets.

#### Usage notes

If you are not changing an asset and just adding C2PA data, use an existing output file and no parent. _Note that this will replace any existing C2PA data in the existing output file._ For instance:

```shell
c2patool sample/test.json -o existing.jpg
```

If you have edited an asset and want to add C2PA data to it, pass the original as the parent and put the edited file at the output location to have the C2PA data added.

```shell
c2patool sample/test.json -p original.jpg -o image-with-c2pa.jpg
```

## Appendix

### Creating and using an X.509 certificate

Before you can add a manifest, you need to create an X.509 certificate. You can specify the path to the cert files in the following configuration fields:

- `private_key`
- `sign_cert`

If you are using a signing algorithm other than the default `ps256`, you will need to specify it in `alg`, which can be set to one of the following:

- `ps256`
- `ps384`
- `ps512`
- `es256`
- `es384`
- `es512`
- `ed25519`

The specified algorithm must be compatible with values of `private_key` and `sign_cert`.

The key and cert can also be placed in the environment variables `C2PA_PRIVATE_KEY` and `C2PA_PUB_CERT`. These two variables are used to set the private key and public certificates. For example, to sign with es256 signatures using the content of a private key file and certificate file, you would run:

```shell
set C2PA_PRIVATE_KEY=$(cat my_es256_private_key)
set C2PA_PUB_CERT=$(cat my_es256_certs)
```

Both the `private_key` and `sign_cert` should be in PEM format. The `sign_cert` should contain a PEM certificate chain starting for the end-entity certificate used to sign the claim ending with the intermediate certificate before the root CA certificate. See the ["sample" folder](https://github.com/contentauth/c2patool/tree/main/sample) for example certificates.

To create your own temporary files for testing, you can execute the following command:

```shell
openssl req -new -newkey rsa:4096 
   -sigopt rsa_padding_mode:pss \ 
   -days 180 \
   -extensions v3_ca \
   -addext "keyUsage = digitalSignature" \
   -addext "extendedKeyUsage = emailProtection" \
   -nodes -x509 -keyout private.key -out certs.pem -sha256
```	

Note: You may have need to update your `openssl` version if the above command does not work. You will likely need version 3.0 or later. You can check the version that is installed by typing `openssl version`.

c2patool can also timestamp the signature data that is embedded.  This is useful for validating an asset when the embedded 
certificates have expired.  If the config has a ta_url set, c2patool will attempt to timestamp the signature using the TA service at the provided URL.  The TA must be RFC3161 compliant.  Example TA setting:

```ta_url=http://timestamp.digicert.com```

## Configuration file format

The Configuration file is a JSON formatted file with a .json extension:

The schema for this type is as follows:
```json
{
	"$schema": "http://json-schema.org/draft-07/schema",
	"$id": "http://ns.adobe.com/cai/claim-definition/v1",
	"type": "object",
	"description": "Definition format for claim created with c2patool",
	"examples": [
		{
            "vendor": "myvendor",
            "claim_generator": "MyApp/0.1",
            "parent": "image.jpg",  
            "ingredients": [],
            "assertions": [
				{
					"label": "my.assertion",
					"data": {
						"any_tag": "whatever I want"
					}
				}
			],
            "alg": "es256",
            "private_key": "es256_private.key",
            "sign_cert": "es256_certs.pem",
            "ta_url": "http://timestamp.digicert.com"
		}
    ],
	"required": [
		"assertions",
	],
	"properties": {
		"vendor": {
			"type": "string",
			"description": "Typically an Internet domain name (without the TLD) for the vendor (i.e. `adobe`, `nytimes`)"
		},
		"claim_generator": {
			"type": "string",
			"description": "A UserAgent string that will let a user know what software/hardware/system produced this Manifest - names should not contain spaces (defaults to c2patool)"
		},
		"title": {
			"type": "string",
			"description": "A human-readable string to be displayed as the tile for this Manifest (defaults to embedded file name)"
		},
		"credentials": {
			"type": "object",
			"description": "An array of W3C verifiable credentials objects defined in the c2pa assertion specification. Section 7"
		},
		"parent": {
			"type": "string",
			"format": "Local file system path",
			"description": "A file path to the source image that was modified by this Manifest (if any)"
		},
        "Ingredients": {
			"type": "array of string",
			"format": "Array of local file system paths",
			"description": "File paths to images that were used to modify the image referenced by this Manifest (if any)"
		},
		"assertions": {
			"type": "object",
			"description": "Objects with label, and data - standard c2pa labels must match values as defined in the c2pa assertion specification"
		},
		"alg": {
			"type": "string",
			"format": "Local file system path",
			"description": "Signing algorithm: one of [ ps256 | ps384 | ps512 | es256 | es384 | es512 | ed25519]"
		},
		"ta_url": {
			"type": "string",
			"format": "http URL",
			"description": "A URL to an RFC3161 compliant Time Stamp Authority"
		},
		"private_key": {
			"type": "string",
			"format": "Local file system path",
			"description": "File path to a private key file"
		},
		"sign_cert": {
			"type": "string",
			"format": "Local file system path",
			"description": "File path to signing cert file"
		},
		"base_path": {
			"type": "string",
			"format": "Local file system path",
			"description": "File path to a folder to use as the base for relative paths in config"
		},
	},
	"additionalProperties": false
}
```
