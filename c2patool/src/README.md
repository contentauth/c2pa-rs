# c2patool

Command line tool for displaying and adding C2PA manifests  
A file path to an image or a claim definition JSON file must be provided  
If an image path is given, this will generate a summary report of any manifests in that file  
If a manifest definition JSON file is specified, the manifest will be created and displayed in a JSON report

## Displaying Manifest data

Invoking the tool with a path to an image file will output a JSON report of the manifests in the file
File formats supported are jpeg and png. 

```c2patool image.jpg```

## Displaying detailed manifest data

The -d option will output a detailed JSON report of the internal C2PA structure

```c2patool image.jpg  -d```

## Previewing a manifest

If a path to a json config file is given,
the tool will generate a new manifest using the values given in the definition
this will display the results but not save anything unless an output (-o) is specified

```c2patool sample/config.json```

The config json can also be passed on the command line as string using the -c --config option

```shell
c2patool -c '{"assertions": [{"label": "org.contentauth.test", "data": {"name": "Jane Doe"}}]}'
```
 
## Creating a new output image

A file path for creating an output file with any added claim data  
If the output file already exists, any C2PA data in that file will be replaced and the image maintained  
If the output file doesn't exist, a parent file must be available for a source image  
If you are not changing an image and just adding C2PA data, use an existing output file and no parent  
If you have edited an image and want to add C2PA data to it, pass the original as the parent
and put the edited file at the output location to have the C2PA data added.

```c2patool sample/config.json -o output.jpg```
## Overriding the parent file

When using a json file, the parent file can be specified by passing -p or --parent with the path to the file
This allows adding the same manifest data to different source images

## Working with .c2pa manifest files

If the extension of the output file is '.c2pa' a standalone manifest store will be written 

```c2patool claim_image.jpg -o manifest.c2pa```

These .c2pa manifest files can be read by claim tool and will generate reports.

```c2patool manifest.c2pa```

## Setup

Before you can add a manifest, you need to create an X.509 certificate  
You can specify the path to the cert files in the configuration fields
```
private_key
sign_cert
```
If you are using a signing algorithm other than the default ps256, you will need to specify it in
```alg```
Which can be set to one of [ ps256 | ps384 | ps512 | es256 | es384 | es512 | ed25519] and
must be compatible with values of private key  and sign cert.

The key and cert can also be placed in the environment variables C2PA_PRIVATE_KEY and C2PA_PUB_CERT  
These two variable are used to set the private key and public certificates.  For example to sign with es256 signatures
using the content of a private key file and certificate file:

```set C2PA_PRIVATE_KEY=$(cat my_es256_private_key)```
```set C2PA_PUB_CERT=$(cat my_es256_certs)```

Both the private key and sign cert should be in PEM format.  The sign cert should contain a certificate
chain PEMs starting for the end-entity certificate used to sign the claim ending with intermediate certificate
before the root CA certificate.  See ```sample`` folder for example certificates.

To create your own temporary files for testing you can execute the following command

```shell
sudo openssl req -new -newkey rsa:4096 -sigopt rsa_padding_mode:pss -days 180 -extensions v3_ca -addext "keyUsage = digitalSignature" -addext "extendedKeyUsage = emailProtection" -nodes -x509 -keyout private.key -out certs.pem -sha256
```	

Note: you may have need to update your openssl version if the above command does not work.

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
