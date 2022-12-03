# c2patool - C2PA command line tool

`c2patool` is a command line tool for working with C2PA [manifests](https://c2pa.org/specifications/specifications/1.0/specs/C2PA_Specification.html#_manifests) and media assets (image or video files). 

Use the tool to:

- Read a JSON report of C2PA manifests in [supported file formats](#supported-file-formats).
- Read a low-level report of C2PA manifest data in [supported file formats](#supported-file-formats).
- Preview manifest data from a [manifest definition](#manifest-definition-file).
- Add a C2PA manifest to [supported file formats](#supported-file-formats).

## Installation

PREREQUISITE: Install [Rust](https://www.rust-lang.org/tools/install). 

Enter this command to install or update the tool:

```shell
cargo install c2patool
```

### Updating 

To ensure you have the latest version, enter this command:

```
c2patool -V 
```

The tool will display the version installed. Compare the version number displayed with the latest release version shown in the [repository releases page](https://github.com/contentauth/c2patool/releases). To update to the latest version, use the installation command shown above.


## Supported file formats

The tool works with the following types of asset files (also referred to as _assets_).

| MIME type                           | extensions  | read only |
| ----------------------------------- | ----------- | --------- |
| `image/jpeg`                        | `jpg, jpeg` |           |
| `image/png`                         | `png`       |           |
| `image/avif`                        | `avif`      |    X      |
| `image/heic`                        | `heic`      |    X      |
| `image/heif`                        | `heif`      |    X      |
| `video/mp4`                         | `mp4`       |           |
| `application/mp4`                   | `mp4`       |           |
| `audio/mp4`                         | `m4a`       |           |
| `video/quicktime`                   |  `mov`      |           |
| `application/x-c2pa-manifest-store` | `c2pa`      |           |

NOTE: Quicktime (`.mov`) format is not yet fully supported.

## Usage

The tool's command-line syntax is:

```
c2patool [OPTIONS] [path]
```

Where `<path>`  is the path to the asset to read or embed a manifest into.

The following table describes the command-line options.

| CLI&nbsp;option&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; | Short version | Argument | Description |
|-----|----|----|----|
| `--config` | `-c` | `<config>` | Specifies a manifest definition as a JSON string. See [Providing a manifest definition on the command line](#providing-a-manifest-definition-on-the-command-line). |
| `--detailed` | `-d` | N/A | Display detailed C2PA-formatted manifest data. See [Displaying a detailed manifest report](#displaying-a-detailed-manifest-report). |
| `--force` | `-f` | N/A | Force overwriting output file. See [Forced overwrite](#forced-overwrite). |
| `--help` | `-h` | N/A | Display CLI help information. |
| `--info` |  | N/A | Display brief information about the file. |
| `--output` | `-o` | `<output_file>` | Specifies path to output file. See [Adding a manifest to an asset file](#adding-a-manifest-to-an-asset-file). |
| `--manifest` | `-m` | `<manifest_file>` | Specifies a manifest file to add to an asset file. See [Adding a manifest to an asset file](#adding-a-manifest-to-an-asset-file).
| `--parent` | `-p` | `<parent_file>` | Specifies path to parent file. See [Specifying a parent file](#specifying-a-parent-file). |
| `--remote` | `-r` | `<manifest_url>` | Specify URL for remote manifest available over HTTP. See [Generating a remote manifest](#generating-a-remote-manifest)|
| `--sidecar` | `-s` | N/A | Put manifest in external "sidecar" file with `.c2pa` extension. See [Generating an external manifest](#generating-an-external-manifest). |
| `--version` | `-V` | N/A | Display version information. |

### Displaying manifest data

To display the manifest associated with an asset file, provide the path to the file as the argument; for example:

```shell
c2patool sample/C.jpg
```

The tool displays the manifest JSON to standard output (stdout).

You may include an `--output` argument to write the contents of the manifest, including the manifest's assertion and ingredient thumbnails, to the provided `output` directory.

```shell
c2patool sample/C.jpg --output ./report
```

### Detailed manifest report

To display a detailed report describing the internal C2PA format of manifests contained in the asset, use the `-d` option; for example, using one of the example images in the `sample` directory:

```shell
c2patool -d sample/C.jpg
```

The tool displays the detailed report to standard output (stdout).

### Displaying an information report

Use the `--info` option to print a high-level report about the asset file and related C2PA data. 
For a cloud manifest the tool displays the URL to the manifest.
For embedded manifests, the tool displays the size of the manifest store and number of manifests. It will also report if the manifest validated or any errors were encountered in validation.


```shell
c2patool sample/C.jpg --info
```

The tool displays the report to standard output (stdout).

### Adding a manifest to an asset file

To add C2PA manifest data to a file, use the `--manifest` / `-m` option with a manifest JSON file as the option argument and the path to the asset file to be signed. Specify the output file as the argument to the `--output` / `-o` option. For example:

```shell
c2patool sample/image.jpg -m sample/test.json -o signed_image.jpg
```

The tool generates a new manifest using the values given in the file and displays the manifest store to standard output (stdout).

CAUTION: If the output file is the same as the source file, the tool will overwrite the source file. 

If you do not use the `--output` / `-o` option, then the tool will display the generated manifest but will not save it to a file.

#### Specifying a parent file

A _parent file_ represents the state of the image before the current edits were made. 

Specify a parent file as the argument to the `--parent` / `-p` option; for example:

```shell
c2patool sample/image.jpg -m sample/test.json -p sample/c.jpg -o signed_image.jpg
```

You can also specify a parent file in the manifest definition.

#### Forced overwrite

The tool will return an error if the output file already exists. Use the `--force` / `-f` option to force overwriting the output file. For example:

```shell
c2patool sample/image.jpg -m sample/test.json -f -o signed_image.jpg
```

### Previewing a manifest

To display a preview of the generated manifest and ensure you've formatted the manifest definition correctly, provide the path to a manifest file as the argument with no other options or flags; for example:

```shell
c2patool sample/image.jpg -m sample/test.json
```

### Generating an external manifest

Use the `--sidecar` / `-s` option to put the manifest in an external sidecar file in the same location as the output file. The manifest will have the same output filename but with a `.c2pa` extension. The tool will copy the output file but the original will be untouched. 

```shell
c2patool image.jpg -s -m sample/test.json -o signed_image.jpg
```
### Generating a remote manifest

Use the `--remote` / `-r` option to place an HTTP reference to the manifest in the output file. The manifest is returned as an external sidecar file in the same location as the output file with the same filename but with a `.c2pa` extension. Place the manifest at the location specified by the `-r` option. When using remote manifests the remote URL should be publicly accessible to be most useful to users. When verifying an asset, remote manifests are automatically fetched. 

```shell
c2patool sample/image.jpg -r http://my_server/myasset.c2pa -m sample/test.json -o signed_image.jpg
```

In the example above, the tool will embed the URL http://my_server/myasset.c2pa in `signed_image.jpg` then fetch the manifest from that URL and save it to `signed_image.c2pa`.

If you use both the `-s` and `-r` options, the tool embeds a manifest in the output file and also adds the remote reference.

### Providing a manifest definition on the command line

To provide the [manifest definition](#manifest-definition-file) in a command line argument instead of a file, use the `--config` / `-c` option.

For example, the following command adds a custom assertion called "org.contentauth.test".

```shell
c2patool sample/image.json -c '{"assertions": [{"label": "org.contentauth.test", "data": {"my_key": "whatever I want"}}]}'
```

## Manifest definition file 

The manifest definition file is a JSON formatted file with a `.json` extension. 
Relative file paths are interpreted as relative to the location of the definition file unless you specify a `base_path` field.

### Schema 

The schema for the manifest definition file is shown below.

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

### Example manifest definition file

Here's an example of a manifest definition that inserts a CreativeWork author assertion. Copy this JSON int a file to use as a test manifest. 

It is important to provide a value for the Time Authority URL (the `ta_url` property) to have a valid timestamp on the claim. 

The default certificates in the [sample folder](https://github.com/contentauth/c2patool/tree/main/sample) are built into the c2patool binary. This example uses the default testing certs. You will see a warning message when using them, since they are meant for development purposes only. 

**NOTE**: Use the default private key and signing certificate only for development.
For actual use, provide a permanent key and cert in the manifest definition or environment variables (see [Appendix](#appendix-creating-and-using-an-x509-certificate)).

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

## Appendix: Creating and using an X.509 certificate

You can test creating your own manifests using the pre-built certificates in the [sample folder](https://github.com/contentauth/c2patool/tree/main/sample). To use your own generated certificates, specify the path to the cert files in the following manifest fields:

- `private_key`
- `sign_cert`

If you are using a signing algorithm other than the default `es256`, specify it in the manifest definition field `alg` with one of the following values:

- `ps256`
- `ps384`
- `ps512`
- `es256`
- `es384`
- `es512`
- `ed25519`

The specified algorithm must be compatible with the values of `private_key` and `sign_cert`.

You can put the values of the key and cert chain in two environment variables: `C2PA_PRIVATE_KEY` (for the private key) and `C2PA_SIGN_CERT` (for the public certificates). For example, to sign with ES256 signatures using the content of a private key file and certificate file:

```shell
set C2PA_PRIVATE_KEY=$(cat my_es256_private_key)
set C2PA_SIGN_CERT=$(cat my_es256_certs)
```

Both the `private_key` and `sign_cert` must be in PEM format. The `sign_cert` must contain a PEM certificate chain starting with the end-entity certificate used to sign the claim ending with the intermediate certificate before the root CA certificate. See the [sample folder](https://github.com/contentauth/c2patool/tree/main/sample) for example certificates.
