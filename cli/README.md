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

If you have [Rust](https://www.rust-lang.org/tools/install) installed, you can install c2patool using:

```shell
cargo install c2patool
```

Or you can clone the repo and build:

```shell
git clone git@github.com:contentauth/c2patool.git
cargo build
```

Or you can use [Homebrew](https://brew.sh/) on MacOS or Linux to install everything you need:

```shell
brew tap contentauth/tools
brew install c2patool
```

## Usage

### Displaying manifest data

Invoking the tool with a path to an asset will print a report describing the manifests contained in the file in JSON format to stdout.

```shell
c2patool image.jpg
```

### Detailed manifest report

The `-d` option will print a detailed report describing the internal C2PA format of manifests contained in the file in JSON format to stdout.
```shell
c2patool image.jpg -d
```


### Adding a manifest to a file

You can add C2PA data to a file by passing a [manifest definition](#manifest-definition-format) JSON file instead of an image. The tool will generate a new manifest using the values given in the definition. 

A parent file and and output file should be specified. The parent file represents the state of the image before any edits were made. The parent file path can be set in the parent field of the manifest definition or on the command line via the -p/parent flag.

The output file is specified on the command line via the -o/output flag. The output file will be updated to contain a new manifest store bound to the output image, replacing any existing manifest data in that file. If you have any previous manifest data, it should be passed via the parent. 

The generated manifest store will also be reported in JSON format to stdout.

```shell
c2patool sample/test.json -p original.jpg -o edited_image.jpg
```

#### Manifest preview feature

If the output file is not specified, the tool will generate a preview of the generated manifest. This can be used to make sure you have formatted the manifest definition correctly.

```shell
c2patool sample/test.json
```
#### Shortcut feature

If the output file does not exist, and a parent exists, the parent file will be copied to the output location and then updated.

```shell
c2patool sample/test.json -p original.jpg -o copy_of_original.jpg
```

#### No parent feature

If the output file exists and no parent is specified, the output file will be updated with a manifest created from the manifest definition only. Note that in this case, any previous manifest data in the output file will be replaced.

```shell
c2patool sample/test.json -o new_manifest.jpg
```

#### Example of a manifest definition file

Here's an example of a manifest definition that inserts a CreativeWork author assertion. If you copy this into a JSON file, you can use it as a test manifest definition.

```json
{
    "ta": "http://timestamp.digicert.com",
    
    "claim_generator": "TestApp",
    "assertions": [
        {
            "label": "stds.schema-org.CreativeWork",
            "data": {
                "@context": "https://schema.org",
                "@type": "CreativeWork",
                "author": [
                    {
                        "@type": "Person",
                        "name": "Joe Bloggs"
                    }
                ]
            }
        }
    ]
}
```
### Manifest definition on command line

The [manifest definition](#manifest-definition-format) can also be passed on the command line as a string using the `-c` or `--config` option.

In this example we are adding a custom assertion called "org.contentauth.test".

```shell
c2patool -c '{"assertions": [{"label": "org.contentauth.test", "data": {"my_key": "whatever I want"}}]}'
```

### Manifest definition format

The manifest definition file is a JSON formatted file with a .json extension. 
Any relative file paths will be treated as relative to the location of the definition file unless a `base_path` field is specified.

The schema for this type is as follows:
```json
{
	"$schema": "http://json-schema.org/draft-07/schema",
	"$id": "http://ns.adobe.com/c2patool/claim-definition/v1",
	"type": "object",
	"description": "Definition format for claim created with c2patool",
	"examples": [
		{
            "alg": "es256",
            "private_key": "es256_private.key",
            "sign_cert": "es256_certs.pem",
            "ta_url": "http://timestamp.digicert.com",
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
		}
    ],
	"required": [
		"assertions",
	],
	"properties": {
		"vendor": {
			"type": "string",
			"description": "Typically an Internet domain name (without the TLD) for the vendor (i.e. `adobe`, `nytimes`). If provided this will be used as a prefix on generated manifest labels."
		},
		"claim_generator": {
			"type": "string",
			"description": "A UserAgent string that will let a user know what software/hardware/system produced this Manifest - names should not contain spaces (defaults to c2patool)."
		},
		"title": {
			"type": "string",
			"description": "A human-readable string to be displayed as the title for this Manifest (defaults to the name of the file this manifest was embedded in)."
		},
		"credentials": {
			"type": "object",
			"description": "An array of W3C verifiable credentials objects defined in the c2pa assertion specification. Section 7."
		},
		"parent": {
			"type": "string",
			"format": "Local file system path",
			"description": "A file path to the source image that was modified by this Manifest (if any)."
		},
        "Ingredients": {
			"type": "array of string",
			"format": "Array of local file system paths",
			"description": "File paths to images that were used to modify the image referenced by this Manifest (if any)."
		},
		"assertions": {
			"type": "object",
			"description": "Objects with label, and data - standard c2pa labels must match values as defined in the c2pa assertion specification."
		},
		"alg": {
			"type": "string",
			"format": "Local file system path",
			"description": "Signing algorithm: one of [ ps256 | ps384 | ps512 | es256 | es384 | es512 | ed25519]. Defaults to ps256."
		},
		"ta_url": {
			"type": "string",
			"format": "http URL",
			"description": "A URL to an RFC3161 compliant Time Stamp Authority. If missing there will no secure timestamp."
		},
		"private_key": {
			"type": "string",
			"format": "Local file system path",
			"description": "File path to a private key file."
		},
		"sign_cert": {
			"type": "string",
			"format": "Local file system path",
			"description": "File path to signing cert file."
		},
		"base_path": {
			"type": "string",
			"format": "Local file system path",
			"description": "File path to a folder to use as the base for relative paths in this file."
		},
	},
	"additionalProperties": false
}
```

## Appendix

### Creating and using an X.509 certificate

You should be able to test creating your own manifests using pre-built certificates supplied with this tool. However, if
you want to use your own generated certificates, you can specify the path to the cert files in the following configuration fields:

- `private_key`
- `sign_cert`

If you are using a signing algorithm other than the default `ps256`, you will need to specify it in the manfifest defnition field `alg`, which can be set to one of the following:

- `ps256`
- `ps384`
- `ps512`
- `es256`
- `es384`
- `es512`
- `ed25519`

The specified algorithm must be compatible with values of `private_key` and `sign_cert`.

The key and cert can also be placed directly in the environment variables `C2PA_PRIVATE_KEY` and `C2PA_PUB_CERT`. These two variables are used to set the private key and public certificates. For example, to sign with es256 signatures using the content of a private key file and certificate file, you would run:

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

Note: You may need to update your `openssl` version if the above command does not work. You will likely need version 3.0 or later. You can check the version that is installed by typing `openssl version`.


