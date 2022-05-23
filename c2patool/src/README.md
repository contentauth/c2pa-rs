# c2paTool

Command line tool for displaying and adding C2PA manifests  
A file path to a JPEG or a claim definition JSON file must be provided  
If a JPEG path is given, this will generate a summary report of any manifests in that file  
If a manifest definition JSON file is specified, the manifest will be created and displayed in a JSON report

## Displaying Manifest data

Invoking the tool with a path to an image file will output a JSON report of the Manifests in the file
File formats supported are jpeg and png. 

```c2patool image.jpg```

## Displaying detailed Manifest data

The -d option will output a detailed JSON report of the internal C2PA structure

```c2patool image.jpg  -d```

## Previewing a Manifest

If a path to a manifest def json file is given,
the tool will generate a new manifest using the values given in definition
this will display the results but not save anything unless an output (-o) is specified

```c2patool claim.json```

The manifest definition json can also be passed on the command line as string using the -c --create option

```c2patool -c '{"vendor": "myvendor", "claim_generator": "MyApplication", "assertions": [{"label": "myvendor.assertion", "data": {"name": "Jane Doe"}}]}'```
 
## Creating a new output image

A file path for creating an output file with any added claim data  
If the output file already exists, any C2PA data in that file will be replaced and the image maintained  
If the output file doesn't exist, a parent file must be available for a source image  
If you are not changing an image and just adding C2PA data, use an existing output file and no parent  
If you have edited an image and want to add C2PA data to it, pass the original as the parent
and put the edited file at the output location to have the C2PA data added.

```c2patool claim.json -o output.jpg```
## Overriding the parent file

When using a json file, the parent file can be specified by passing -p or --parent with the path to the file
This allows adding the same manifest data to different source images

## Working with .c2pa manifest files

If the extension of the output file is '.c2pa' a standalone manifest store will be written 

```c2patool claim_image.jpg -o manifest.c2pa```

These .c2pa manifest files can be read by claim tool and will generate reports.

```c2patool manifest.c2pa```
## Setup

Before you can add a manifest, you need to create an SSL certificate  
By default, c2patool expects to find temp_key.pem and temp_key in the user's ".cai" folder.  
The location of this folder can be changed by setting the CAI_KEY_PATH environment variable.  
This expects RSA/RSA_PSS certificates and private key.  It will create signatures as PS256. 

```set CAI_KEY_PATH="~/mykeys"```

The key and cert can also be placed in the environment variables CAI_PRIVATE_KEY and CAI_PUB_CERT  
These two variable are used to set the private key and public certificates.  When using these variables
the CAI_SIGNING_ALGORITHM must also be set to one of [ ps256 | ps384 | ps512 | es256 | es384 | es512 | ed25519] and
must be compatible with values of CAI_PRIVATE_KEY and CAI_PUB_CERT. For example to sign with es256 signatures
using the content of a private key file and certificate file:

```set CAI_SIGNING_ALGORITHM=es256```
```set CAI_PRIVATE_KEY=$(cat my_es256_private_key)```
```set CAI_PUB_CERT=$(cat my_es256_certs)```

The both CAI_PRIVATE_KEY and CAI_PUB_CERT should be in PEM format.  CAI_PUB_CERT should contain a certificate
chain PEMs starting for the end-entity certificate used to sign the claim ending with intermediate certificate
before the root CA certificate.  See ```sample`` folder for example certificates.

To create temporary files for testing you can execute the following command

```
mkdir -p ~/.cai ; sudo openssl req -new -newkey rsa:4096 -sigopt rsa_padding_mode:pss -days 180 -extensions v3_ca -addext "keyUsage = digitalSignature" -addext "extendedKeyUsage = emailProtection" -nodes -x509 -keyout ~/.cai/temp_key.pem -out ~/.cai/temp_key.pub -sha256 ; sudo chmod 644 ~/.cai/temp_key.pem
```	

Note you may have need to update your openssl version if the above command does not work.

c2patool can also timestamp the signature data that is embedded.  This is useful for validating an asset when the embedded 
certificates have expired.  If c2patool finds the CAI_TA_URL environment variable set, c2patool will attempt to timestamp the signature using the TA service at the provided URL.  The TA must be RFC3161 compliant.  Example TSA setting:

```set CAI_TA_URL=http://timestamp.digicert.com```

## Manifest definition file format

The manifest definition file is a JSON formatted file with a .json extension:

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
            "claim_generator": "My Application",
            "title" : "My Title",
            "parent": "image.jpg",  
            "ingredients": [],
            "assertions": [
				{
					"label": "my.assertion",
					"data": {
						"any_tag": "whatever I want"
					}
				}
			]
        }    
	],
	"required": [
		"vendor",
		"claim_generator",
		"assertions",
	],
	"properties": {
		"vendor": {
			"type": "string",
			"description": "typically Internet domain name (without the TLD) for the vendor (i.e. `adobe`, `nytimes`)"
		},
		"claim_generator": {
			"type": "string",
			"description": "a UserAgent string that will let a user know what software/hardware/system produced this Manifest - names should not contain spaces"
		},
		"title": {
			"type": "string",
			"description": "a human-readable string to be displayed as the tile for this Manifest (defaults to embedded file name)"
		},
		"credentials": {
			"type": "object",
			"description": "array of W3C verifiable credentials objects defined in the c2pa assertion specification. Section 7"
		},
		"parent": {
			"type": "string",
			"format": "local file system path",
			"description": "a file path to the source image that was modified by this Manifest (if any)"
		},
        "Ingredients": {
			"type": "array of string",
			"format": "array of local file system paths",
			"description": "file paths to images that were used to modify the image referenced by this Manifest (if any)"
		},
		"assertions": {
			"type": "object",
			"description": "object with label, and data - an object with any value as defined in the c2pa assertion specification"
		},
	},
	"additionalProperties": false
}
```
