# c2patool - C2PA command line tool

`c2patool` is a command line tool for working with C2PA [manifests](https://c2pa.org/specifications/specifications/1.3/specs/C2PA_Specification.html#_manifests) and media assets (audio, image or video files).

Use the tool on a file in one of the [supported file formats](#supported-file-formats) to:

- Read a summary JSON report of C2PA manifests.
- Read a low-level report of C2PA manifest data.
- Add a C2PA manifest to the file.

For a simple example of calling c2patool from a Node.js server application, see the [c2pa-service-example](https://github.com/contentauth/c2patool-service-example) repository.

<div style={{display: 'none'}}>

**Contents**:
- [Installation](#installation)
- [Supported file formats](#supported-file-formats)
- [Usage](#usage)
- [Configuring trust support](#configuring-trust-support)

**Additional documentation**:

- [Manifest definition file](./docs/manifest.md)
- [Creating and using an X.509 certificate](./docs/x_509.md)
- [Release notes](./docs/release-notes.md)

</div>

## Installation

There are two ways to install C2PA Tool:
- Using a pre-built binary executable: This is the quickest way to install the tool.  If you just want to try C2PA Tool quickly, use this method.
- Using Cargo [Binstall](#using-cargo-binstall), a low-complexity way to install Rust binaries.  This method is preferable for long-term use. If you know you want to use C2PA Tool for development, use this method.  

### Installing a pre-built binary

The quickest way to install the tool is to use the binary executable builds.  If you just want to try C2PA Tool quickly:

1. Go to the [c2patool repository releases page](https://github.com/contentauth/c2patool/releases). 
1. Under the latest release, click **Assets**.
1. Download the archive for your operating system (Linux, macOS, or Windows).
1. Copy the executable file to a location on your `PATH`.

Confirm that you can run the tool by entering a command such as:
```
c2patool -h
```

NOTE: You also may want to get some of the example files provided in the repository `sample` directory.   To do so, clone the repository with `git clone https://github.com/contentauth/c2patool.git`.

### Using Cargo Binstall

Installing C2PA Tool using Cargo [Binstall](https://github.com/cargo-bins/cargo-binstall?tab=readme-ov-file) is recommended because it makes it easier to:
- Automatically select the correct installation package for your platform/architecture.
- Update the tool when a new version is released.
- Maintain, since you don't have to manually keep track of random binaries on your system.
- Integrate into CI or other scripting environments.

Additionally, using Binstall enables you to automate code signing to ensure package integrity.

#### Process

**PREREQUISITE:** Install [Rust](https://www.rust-lang.org/tools/install).

To install by using Binstall:

1. Install `cargo-binstall` by following the [quick install method](https://github.com/cargo-bins/cargo-binstall?tab=readme-ov-file#quickly) for your OS, or by building from source by running `cargo install cargo-binstall`
2. Run `cargo binstall c2patool`.

#### Upgrading

To ensure you have the latest version, enter this command:

```
c2patool -V
```

The tool will display the version installed. Compare the version number displayed with the latest release version shown in the [repository releases page](https://github.com/contentauth/c2patool/releases). 

If you need to upgrade, simply run `cargo binstall c2patool` again, or use [cargo-update](https://github.com/nabijaczleweli/cargo-update).

### Building from source

**NOTE:** Please use one of the installation methods described above unless you are doing active development work on C2PA Tool, or if a pre-built binary is not available for your system.

```shell
cargo install c2patool
```

To build the tool on a Windows machine, you need to install the [7zip](https://www.7-zip.org/) tool.

NOTE: If you encounter errors installing, you may need to update your Rust installation by entering this command:

```
rustup update
```

## Supported file formats

 | Extensions    | MIME type                                           |
 | ------------- | --------------------------------------------------- |
 | `avi`         | `video/msvideo`, `video/avi`, `application-msvideo` |
 | `avif`        | `image/avif`                                        |
 | `c2pa`        | `application/x-c2pa-manifest-store`                 |
 | `dng`         | `image/x-adobe-dng`                                 |
 | `heic`        | `image/heic`                                        |
 | `heif`        | `image/heif`                                        |
 | `jpg`, `jpeg` | `image/jpeg`                                        |
 | `m4a`         | `audio/mp4`                                         |
 | `mp3`         | `"audio/mpeg"`                                      |
 | `mp4`         | `video/mp4`, `application/mp4` <sup>*</sup>         |
 | `mov`         | `video/quicktime`                                   |
 | `pdf`         | `application/pdf` <sup>**</sup>                     |
 | `png`         | `image/png`                                         |
 | `svg`         | `image/svg+xml`                                     |
 | `tif`,`tiff`  | `image/tiff`                                        |
 | `wav`         | `audio/x-wav`                                       |
 | `webp`        | `image/webp`                                        |

<sup>*</sup> Fragmented MP4 is not yet supported.

<sup>**</sup> Read-only

## Usage

The tool's command-line syntax is:

```
c2patool [trust] [PATH] [OPTIONS]
```

Where `PATH` is the (relative or absolute) file path to the asset to read or embed a manifest into.

The following table describes the command-line options.

| CLI&nbsp;option&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; | Short version | Argument | Description |
|-----|----|----|----|
| `--certs` | | N/A | Extract a certificate chain to stdout. |
| `--config` | `-c` | `<config>` | Specifies a manifest definition as a JSON string. See [Providing a manifest definition on the command line](#providing-a-manifest-definition-on-the-command-line). |
| `--detailed` | `-d` | N/A | Display detailed C2PA-formatted manifest data. See [Displaying a detailed manifest report](#detailed-manifest-report). |
| `--force` | `-f` | N/A | Force overwriting output file. See [Forced overwrite](#forced-overwrite). |
| `--help` | `-h` | N/A | Display CLI help information. |
| `--info` |  | N/A | Display brief information about the file. |
| `--batch` |  | N/A | Perform command for all children of directory (suppports signing). |
| `--ingredient` | `-i` | N/A | Creates an Ingredient definition in --output folder. |
| `--output` | `-o` | `<output_file>` | Specifies path to output folder or file. See [Adding a manifest to an asset file](#adding-a-manifest-to-an-asset-file). |
| `--manifest` | `-m` | `<manifest_file>` | Specifies a manifest file to add to an asset file. See [Adding a manifest to an asset file](#adding-a-manifest-to-an-asset-file).
| `--no_signing_verify` | None | N/A |  Does not validate the signature after signing an asset, which speeds up signing. See [Speeding up signing](#speeding-up-signing) |
| `--parent` | `-p` | `<parent_file>` | Specifies path to parent file. See [Specifying a parent file](#specifying-a-parent-file). |
| `--remote` | `-r` | `<manifest_url>` | Specify URL for remote manifest available over HTTP. See [Generating a remote manifest](#generating-a-remote-manifest)| N/A? |
| `--sidecar` | `-s` | N/A | Put manifest in external "sidecar" file with `.c2pa` extension. See [Generating an external manifest](#generating-an-external-manifest). |
| `--tree` | | N/A | Create a tree diagram of the manifest store. |
| `--version` | `-V` | N/A | Display version information. |

Use the optional `trust` sub-command to enable and configure trust support.  When you use this sub-command, several other options are available; see [Configuring trust support](#configuring-trust-support) for details.

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

#### Detailed manifest report

To display a detailed report describing the internal C2PA format of manifests contained in the asset, use the `-d` option; for example, using one of the example images in the `sample` directory:

```shell
c2patool sample/C.jpg -d
```

The tool displays the detailed report to standard output (stdout) or will add a detailed.json if an output folder is supplied.

#### Displaying an information report

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

In the example above, the tool will embed the URL `http://my_server/myasset.c2pa` in `signed_image.jpg` then fetch the manifest from that URL and save it to `signed_image.c2pa`.

If you use both the `-s` and `-r` options, the tool embeds a manifest in the output file and also adds the remote reference.

### Signing claim bytes with your own signer

You may be unable to provide `c2patool` with a private key when generating a manifest because the private key is not accessible on the system on which you are executing `c2patool`. We provide the `--signer-path` argument for this case. `--signer-path` takes a path to a command-line executable. This executable will receive the claim bytes (the bytes to be signed) via `stdin`, along with a few CLI arguments, and should output, via `stdout` the signature bytes. For example, the following command will use an external signer to sign the asset's claim bytes:

```shell
c2patool sample/image.jpg            \
    --manifest sample/test.json      \
    --output sample/signed-image.jpg \
    --signer-path ./custom-signer    \
    --reserve-size 20248             \
    -f
```

You can see an example external signer here: [signer-path-success.rs](./src/bin/signer-path-success.rs).

Please see `c2patool --help` for how to calculate the `--reserve-size` argument.

### Providing a manifest definition on the command line

To provide the manifest definition in a command line argument instead of a file, use the `--config` / `-c` option.

For example, the following command adds a custom assertion called "org.contentauth.test".

```shell
c2patool sample/image.jpg \
  -c '{"assertions": \
    [{"label": "org.contentauth.test", \
      "data": {"my_key": "whatever I want"}}]}'
```

### Speeding up signing

By default, `c2patool` validates the signature immediately after signing a manifest. To disable this and speed up the validation process, use the `--no_signing_verify` option.

## Configuring trust support

Enable trust support by using the `trust` subcommand, as follows:

```
c2patool [path] trust [OPTIONS]
```

The following additional CLI options are available with the `trust` sub-command:

| Option | Environment variable | Description | Example |
| ------ | --------------- | ----------- | ------- |
| `--trust_anchors` | `C2PATOOL_TRUST_ANCHORS` | Specifies a list of trust anchors (in PEM format) used to validate the manifest certificate chain. To be valid, the manifest certificate chain must lead to a certificate on the trust list. All certificates in the trust anchor list must have the [Basic Constraints extension](https://docs.digicert.com/en/iot-trust-manager/certificate-templates/create-json-formatted-certificate-templates/extensions/basic-constraints.html) and the CA attribute of this extension must be `True`. | `sample/trust_anchors.pem` `https://server.com/anchors.pem` |
| `--allowed_list` | `C2PATOOL_ALLOWED_LIST` | Supersedes the `trust_anchors` check and specifies a list of end-entity certificates (in PEM format) to trust. These certificates are used to sign the manifest. The allowed list must NOT contain certificates with the [Basic Constraints extension](https://docs.digicert.com/en/iot-trust-manager/certificate-templates/create-json-formatted-certificate-templates/extensions/basic-constraints.html) with the CA attribute `True`. | `sample/allowed_list.pem` `https://server.com/allowed.pem` |
| `--trust_config` | `C2PATOOL_TRUST_CONFIG` | Specifies a set of custom certificate extended key usages (EKUs) to allow. Format is a list with object identifiers in [OID dot notation](http://www.oid-info.com/#oid) format. | `sample/store.cfg` `https://server.com/store.cfg` |

For example:

```shell
c2patool sample/C.jpg trust \
  --allowed_list sample/allowed_list.pem \
  --trust_config sample/store.cfg
```

### Using the temporary contentcredentials.org / Verify trust settings

**IMPORTANT:** The C2PA intends to publish an official C2PA Public Trust List. Until that time, temporary known certificate lists used by https://contentcredentials.org/verify have been published. These lists are subject to change, and will be deprecated.

You can configure your client to use the temporary trust settings used by contentcredentials.org / Verify by setting the following environment variables on your system:

```shell
export C2PATOOL_TRUST_ANCHORS='https://contentcredentials.org/trust/anchors.pem'
export C2PATOOL_ALLOWED_LIST='https://contentcredentials.org/trust/allowed.sha256.txt'
export C2PATOOL_TRUST_CONFIG='https://contentcredentials.org/trust/store.cfg'
```

**Note:** Setting these variables will make several HTTP requests each time `c2patool` is called. As these lists may change without notice (with the allowed list changing quite frequently) this may be desired to stay in sync with what is displayed on the Verify site. However, if working with bulk operations, you may want to locally cache these files to avoid an abundance of network calls.

You can then run:

```shell
c2patool sample/C.jpg trust
```

**Note:** This sample image should show a `signingCredential.untrusted` validation status since the test signing certificate used to sign them is not contained on the trust lists above.

Additionally, if you do not want to use environment variables, you can pass these values as arguments instead:

```shell
c2patool sample/C.jpg trust \
  --trust_anchors='https://contentcredentials.org/trust/anchors.pem' \
  --allowed_list='https://contentcredentials.org/trust/allowed.sha256.txt' \
  --trust_config='https://contentcredentials.org/trust/store.cfg'
```

## Nightly builds

Interim binaries are generated every day around 05:30 UTC (overnight for our US-based team) and are available for roughly two weeks thereafter. These can be helpful for testing purposes. For more information, see the documentation on [nightly builds](https://github.com/contentauth/c2patool/tree/main/docs/nightly-builds/README.md).
