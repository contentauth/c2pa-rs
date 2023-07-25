# c2patool - C2PA command line tool

`c2patool` is a command line tool for working with C2PA [manifests](https://c2pa.org/specifications/specifications/1.0/specs/C2PA_Specification.html#_manifests) and media assets (audio, image or video files). 

Use the tool to:

- Read a JSON report of C2PA manifests in [supported file formats](#supported-file-formats).
- Read a low-level report of C2PA manifest data in [supported file formats](#supported-file-formats).
- Add a C2PA manifest to [supported file formats](#supported-file-formats).

For a simple example of calling c2patool from a server-based application, see the [c2pa-service-example](https://github.com/contentauth/c2pa-service-example) repository.

## Installation

Prebuilt versions of the tool are available for [download](https://github.com/contentauth/c2patool/tags).

PREREQUISITE: Install [Rust](https://www.rust-lang.org/tools/install). 

Enter this command to install or update the tool:

```shell
cargo install c2patool
```

If you are producing a build on a Windows machine, you will need the [7zip](https://www.7-zip.org/) tool to successfully build.

### Updating 

To ensure you have the latest version, enter this command:

```
c2patool -V 
```

The tool will display the version installed. Compare the version number displayed with the latest release version shown in the [repository releases page](https://github.com/contentauth/c2patool/releases). To update to the latest version, use the installation command shown above.


## Supported file formats

 | Extensions    | MIME type                                           | 
 |---------------| --------------------------------------------------- | 
 | `avi`         | `video/msvideo`, `video/avi`, `application-msvideo` |
 | `avif`        | `image/avif`                                        | 
 | `c2pa`        | `application/x-c2pa-manifest-store`                 |
 | `dng`         | `image/x-adobe-dng`                                 | 
 | `heic`        | `image/heic`                                        | 
 | `heif`        | `image/heif`                                        | 
 | `jpg`, `jpeg` | `image/jpeg`                                        | 
 | `m4a`         | `audio/mp4`                                         | 
 | `mp4`         | `video/mp4`, `application/mp4` <sup>*</sup>         | 
 | `mov`         | `video/quicktime`                                   |
 | `png`         | `image/png`                                         | 
 | `svg`         | `image/svg+xml`                                     | 
 | `tif`,`tiff`  | `image/tiff`                                        | 
 | `wav`         | `audio/x-wav`                                       | 
 | `webp`        | `image/webp`                                        | 
 
<sup>*</sup> Fragmented mp4 is not yet supported.

## Usage

The tool's command-line syntax is:

```
c2patool [OPTIONS] [path]
```

Where `<path>`  is the path to the asset to read or embed a manifest into.

The following table describes the command-line options.

| CLI&nbsp;option&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; | Short version | Argument | Description |
|-----|----|----|----|
| `--certs` | | N/A | Extract a certificate chain to stdout. |
| `--config` | `-c` | `<config>` | Specifies a manifest definition as a JSON string. See [Providing a manifest definition on the command line](#providing-a-manifest-definition-on-the-command-line). |
| `--detailed` | `-d` | N/A | Display detailed C2PA-formatted manifest data. See [Displaying a detailed manifest report](#displaying-a-detailed-manifest-report). |
| `--force` | `-f` | N/A | Force overwriting output file. See [Forced overwrite](#forced-overwrite). |
| `--help` | `-h` | N/A | Display CLI help information. |
| `--info` |  | N/A | Display brief information about the file. |
| `--ingredient` | `-i` | N/A | Creates an Ingredient definition in --output folder. |
| `--output` | `-o` | `<output_file>` | Specifies path to output folder or file. See [Adding a manifest to an asset file](#adding-a-manifest-to-an-asset-file). |
| `--manifest` | `-m` | `<manifest_file>` | Specifies a manifest file to add to an asset file. See [Adding a manifest to an asset file](#adding-a-manifest-to-an-asset-file).
| `--parent` | `-p` | `<parent_file>` | Specifies path to parent file. See [Specifying a parent file](#specifying-a-parent-file). |
| `--remote` | `-r` | `<manifest_url>` | Specify URL for remote manifest available over HTTP. See [Generating a remote manifest](#generating-a-remote-manifest)|
| `--sidecar` | `-s` | N/A | Put manifest in external "sidecar" file with `.c2pa` extension. See [Generating an external manifest](#generating-an-external-manifest). |
| `--tree` | | N/A | Create a tree diagram of the manifest store. |
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

The tool displays the detailed report to standard output (stdout) or will add a detailed.json if an output folder is supplied.

### Displaying an information report

Use the `--info` option to print a high-level report about the asset file and related C2PA data. 
For a cloud manifest the tool displays the URL to the manifest.
Displays the size of the manifest store and number of manifests.
It will report if the manifest validated or show any errors encountered in validation.


```shell
c2patool sample/C.jpg --info
```

The tool displays the report to standard output (stdout).


### Creating an ingredient from a file

The `--ingredient` option will create an ingredient report.  When used with the `--output` folder, it will extract or create a thumbnail image and a binary .c2pa manifest store containing the c2pa data from the file. The JSON ingredient this produces can be added to a manifest definition to carry the full history and validation record of that asset into a newly created manifest.
Provide the path to the file as the argument; for example:

```shell
c2patool sample/C.jpg --ingredient --output ./ingredient
```

### Adding a manifest to an asset file

To add C2PA manifest data to a file, use the `--manifest` / `-m` option with a manifest JSON file as the option argument and the path to the asset file to be signed. Specify the output file as the argument to the `--output` / `-o` option. The output extension type must match the source. The tool will not convert between file types. For example:

```shell
c2patool sample/image.jpg -m sample/test.json -o signed_image.jpg
```

The tool generates a new manifest using the values given in the file and displays the manifest store to standard output (stdout).

CAUTION: If the output file is the same as the source file, the tool will overwrite the source file. 

#### Specifying a parent file

A _parent file_ represents the state of the image before the current edits were made. 

Specify a parent file as the argument to the `--parent` / `-p` option; for example:

```shell
c2patool sample/image.jpg -m sample/test.json -p sample/c.jpg -o signed_image.jpg
```

You can pass an ingredient generated with the --ingredient option by giving the folder or ingredient.json file.

```shell
c2patool sample/C.jpg --ingredient --output ./ingredient

c2patool sample/image.jpg -m sample/test.json -p ./ingredient -o signed_image.jpg
```

#### Forced overwrite

The tool will return an error if the output file already exists. Use the `--force` / `-f` option to force overwriting the output file. For example:

```shell
c2patool sample/image.jpg -m sample/test.json -f -o signed_image.jpg
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
c2patool sample/image.jpg -c '{"assertions": [{"label": "org.contentauth.test", "data": {"my_key": "whatever I want"}}]}'
```

## Manifest definition file 

The manifest definition file is a JSON formatted file with a `.json` extension. 
Relative file paths are interpreted as relative to the location of the definition file unless you specify a `base_path` field.

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

## JSON schemas

* [Schema for the Manifest Definition](https://github.com/contentauth/c2patool/blob/main/schemas/manifest-definition.json)

* [Schema for Ingredient](https://github.com/contentauth/c2patool/blob/main/schemas/ingredient.json)

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


## Release notes

This section gives a highlight of noteworthy changes 

Refer to the [CHANGELOG](https://github.com/contentauth/c2patool/blob/main/CHANGELOG.md) for detailed Git changes

# 0.6.0
* Validates 1.3 signatures but will not generate them.
* Supports other 1.3 features such as actions v2 and ingredients v2
* Supports adding claim_generator_info to a manifest.
* icons for claim_generator_info can be added as resource references
* the sdk will create v2 actions or ingredients if required, but defaults to v1
# 0.5.4
* This introduced a 1.3 required change in signature format that is not compatible with previous verify code.
* We want to give some time for developers to integrate 1.3 validation before using 1.3 signatures
* Please avoid using 0.5.4 and update to 0.6.0 which can validate the new format but does not create it.

# 0.5.3
* fix bug where ingredient thumbnails were not generated
* an ingredient.json file or folder can now be passed on the command line --parent option.
* if a folder is passed as an ingredient, the tool will look for an ingredient.json fle in that folder.
* fix --parent is no longer relative to the --manifest path
# 0.5.2
* remove manifest preview feature
* test for similar extensions
* Add svg support
# 0.5.1
* Updated the sample certs which had expired
* Updates to the Readme, for 0.5.0 changes

## 0.5.0
_27 March 2023_

* Added support for many new file formats, see [supported file formats](#supported-file-formats).
* Manifests and Ingredients can read and write thumbnail and c2pa resource files.
* Added `-i/--ingredient` option to generate an ingredient report or folder.
* Changes to Manifest Definition:
    * `ingredients` now requires JSON Ingredient definitions.
	* `ingredient_paths` accepts file paths, including JSON Ingredient definitions.
    * `base_path` no longer supported. File paths are relative to the containing JSON file.
