# c2patool - C2PA command line tool

c2patool is a command line tool for working with C2PA [manifests](https://c2pa.org/specifications/specifications/1.0/specs/C2PA_Specification.html#_manifests). Currently, the tool supports:

- Reading a JSON report of C2PA manifests in [supported file formats](#supported-file-formats)
- Reading a low-level report of C2PA manifest data in [supported file formats](#supported-file-formats)
- Previewing manifest data from a [manifest definition](#manifest-definition-format)
- Adding a C2PA manifest to [supported file formats](#supported-file-formats)

## Supported file formats
| MIME type         | extensions  | read only |
| ----------------- | ----------- | --------- |
| `image/jpeg`      | `jpg, jpeg` |           |
| `image/png`       | `png`       |           |
| `image/avif`      | `avif`      |    X      |
| `image/heic`      | `heic`      |    X      |
| `image/heif`      | `heif`      |    X      |
| `video/mp4`       | `mp4`       |           |
| `application/mp4` | `mp4`       |           |
| `audio/mp4`       | `m4a`       |           |
| `application/c2pa`| `c2pa`      |    X      |
| `video/quicktime` | `mov`       |           |

## Installation

If you have [Rust](https://www.rust-lang.org/tools/install) installed, you can install or update c2patool using:

```shell
cargo install c2patool
```

## Usage

### Displaying manifest data

Invoking the tool with a path to an asset will print a report describing the manifests contained in the file in JSON format to stdout.

```shell
c2patool sample/C.jpg
```

### Detailed manifest report

The `-d` or `--detailed` option will print a detailed report describing the internal C2PA format of manifests contained in the file in JSON format to stdout.
```shell
c2patool sample/C.jpg -d
```

### Adding a manifest to a file

To add C2PA data to a file, use the `-m` or `--manifest` option and provide a manifest definition JSON file as the argument. The tool generates a new manifest using the values given in the file.

The file path must reference the asset to be signed. 

The output file is specified on the command line via the `-o` or `--output` flag.  If the output is the same as the source, it will be overwritten. Use this with caution. If no output is given you can preview the generated manifest but nothing is written.

The generated manifest store will also be reported in JSON format to stdout.

```shell
c2patool sample/image.jpg -m sample/test.json -o signed_image.jpg
```

A parent file can be specified with the `-p` or `--parent` option or in the manifest definition. The parent file represents the state of the asset before any edits were made. 

```shell
c2patool sample/image.jpg -m sample/test.json -p sample/c.jpg -o signed_image.jpg
```

#### Forced overwrite
The tool will return an error if the output file already exists. The `-f` or `--force` flag may be used to override this behavior. Use this with caution.

```shell
c2patool image.jpg -m sample/test.json -f -o signed_image.jpg
```

#### Manifest preview feature

If the output file is not specified, the tool will generate a preview of the generated manifest. This can be used to make sure you have formatted the manifest definition correctly.

```shell
c2patool image.jpg -m sample/test.json
```

### Generating an external manifest

The `-s` or `--sidecar` option puts the manifest in an external sidecar file in the same location as the output file. The manifest will have the same output filename but with a ".c2pa" extension. The output file will be copied but untouched. 

```shell
c2patool image.jpg -s -m sample/test.json -o signed_image.jpg
```
### Generating a remote manifest

The `-r` or `--remote` option places an http reference to manifest in the output file. The manifest is returned as an external sidecar file in the same location as the output file. The manifest will have the same output filename but with a ".c2pa" extension. The manifest should then be placed at the location specified by the `-r` option. When using remote manifests the remote URL should be publicly accessible to be most useful to users. When verifying an asset, remote manifests are automatically fetched. 

```shell
c2patool sample/image.jpg -r http://my_server/myasset.c2pa -m sample/test.json -o signed_image.jpg
```

In the example above c2patool will try to fetch the manifest for new_manifest.jpg from http://my_server/myasset.c2pa during validation.

Note: It is possible to combine the `-s` and `-r` options. When used together a manifest will be embedded in the output files and the remote reference will also be added. 

#### Example of a manifest definition file

Here's an example of a manifest definition that inserts a CreativeWork author assertion. If you copy this into a JSON file, you can use it as a test manifest definition.

```json
{
    "ta_url": "http://timestamp.digicert.com",
    
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
c2patool sample/image.json -c '{"assertions": [{"label": "org.contentauth.test", "data": {"my_key": "whatever I want"}}]}'
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
			"description": "A file path to the state of the asset prior to any changes declared in the manifest definition."
		},
        "Ingredients": {
			"type": "array of string",
			"format": "Array of local file system paths",
			"description": "File paths to assets that were used to modify the asset referenced by this Manifest (if any)."
		},
		"assertions": {
			"type": "object",
			"description": "Objects with label, and data - standard c2pa labels must match values as defined in the c2pa assertion specification."
		},
		"alg": {
			"type": "string",
			"format": "Local file system path",
			"description": "Signing algorithm: one of [ ps256 | ps384 | ps512 | es256 | es384 | es512 | ed25519]. Defaults to es256."
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


