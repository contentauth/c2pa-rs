# Using C2PA Tool

C2PA Tool's command-line syntax is:

```
c2patool [OPTIONS] <PATH> [COMMAND]
```

Where:
- `OPTIONS` is one or more of the command-line options described in following table.
- `<PATH>` is the (relative or absolute) file path to the asset to read or embed a manifest into.
- `[COMMAND]` is one of the optional subcommands: `trust`, `fragment`, or `help`.

By default, c2patool writes a JSON representation of C2PA manifests found in the asset to the standard output. 

## Subcommands

The tool supports the following subcommands:
- `trust` [configures trust support](#configuring-trust-support) for certificates on a "known certificate list." With this subcommand, several additional options are available.
- `fragment` [adds a manifest to fragmented BMFF content](#adding-a-manifest-to-fragmented-bmff-content).  With this subcommand, one additional option is available.
- `help` displays command line help information.

## Options

The following options are available with any (or no) subcommand.  Additional options are available with each subcommand.

| CLI&nbsp;option&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; | Short version | Argument | Description |
|-----|----|----|----|
| `--certs` | | N/A | Extract a certificate chain to standard output (stdout). |
| `--config` | `-c` | `<config>` | Specify a manifest definition as a JSON string. See [Providing a manifest definition on the command line](#providing-a-manifest-definition-on-the-command-line). |
| `--detailed` | `-d` | N/A | Display detailed C2PA-formatted manifest data. See [Displaying a detailed manifest report](#detailed-manifest-report). |
| `--force` | `-f` | N/A | Force overwriting output file. See [Forced overwrite](#forced-overwrite). |
| `--help` | `-h` | N/A | Display CLI help information. |
| `--info` |  | N/A | Display brief information about the file. |
| `--ingredient` | `-i` | N/A | Create an Ingredient definition in --output folder. |
| `--output` | `-o` | `<output_file>` | Path to output folder or file. See [Adding a manifest to an asset file](#adding-a-manifest-to-an-asset-file). |
| `--manifest` | `-m` | `<manifest_file>` | Specify a manifest file to add to an asset file. See [Adding a manifest to an asset file](#adding-a-manifest-to-an-asset-file).
| `--no_signing_verify` | None | N/A |  Do not validate the signature after signing an asset, which speeds up signing. See [Speeding up signing](#speeding-up-signing) |
| `--parent` | `-p` | `<parent_file>` | Path to parent file. See [Specifying a parent file](#specifying-a-parent-file). |
| `--remote` | `-r` | `<manifest_url>` | URL for remote manifest available over HTTP. See [Generating a remote manifest](#generating-a-remote-manifest)| N/A? |
| `--reserve-size` | N/A | Only valid with `--signer-path` argument. The amount of memory to reserve for signing. Default: 20000. For more information, see CLI help. |
| `--sidecar` | `-s` | N/A | Put manifest in external "sidecar" file with `.c2pa` extension. See [Generating an external manifest](#generating-an-external-manifest). |
| `--signer-path` | N/A | Specify path to command-line executable for signing.  See [Signing claim bytes with your own signer](#signing-claim-bytes-with-your-own-signer). |
| `--tree` | | N/A | Create a tree diagram of the manifest store. |
| `--version` | `-V` | N/A | Display version information. |

## Displaying manifest data

To display the manifest associated with an asset file, provide the path to the file as the argument; for example:

```shell
c2patool sample/C.jpg
```

The tool displays the manifest JSON to standard output (stdout).

Use the `--output` argument to write the contents of the manifest, (including the manifest's assertion and ingredient thumbnails) to the specified directory.

```shell
c2patool sample/C.jpg --output ./report
```

### Detailed manifest report

Use the `-d` option to display a detailed report describing the internal C2PA format of manifests contained in the asset; for example, using one of the example images in the `sample` directory:

```shell
c2patool sample/C.jpg -d
```

By default, the tool displays the detailed report to standard output (stdout). If you specify an output folder, the tool saves it to a file named `detailed.json` in that folder.

### Displaying an information report

Use the `--info` option to print a high-level report about the asset file and related C2PA data.
For a cloud manifest the tool displays the URL to the manifest.
Displays the size of the manifest store and number of manifests.
It will report if the manifest validated or show any errors encountered in validation.


```shell
c2patool sample/C.jpg --info
```

The tool displays the report to standard output (stdout).

## Creating an ingredient from a file

The `--ingredient` option creates an ingredient report.  When used with the `--output` folder, it extracts or creates a thumbnail image and a binary `.c2pa` manifest store containing the C2PA data from the file. The JSON ingredient this produces can be added to a manifest definition to carry the full history and validation record of that asset into a newly-created manifest.

Provide the path to the file as the argument; for example:

```shell
c2patool sample/C.jpg --ingredient --output ./ingredient
```

## Adding a manifest to an asset file

Use the `--manifest` / `-m` option to add the C2PA manifest definition file specified in the argument to the asset file to be signed. Specify the output file as the argument to the `--output` / `-o` option. The output extension type must match the source. The tool will not convert between file types. For example:

```shell
c2patool sample/image.jpg -m sample/test.json -o signed_image.jpg
```

The tool generates a new manifest using the values given in the file and displays the manifest store to standard output (stdout).

CAUTION: If the output file is the same as the source file, the tool will overwrite the source file.

If the manifest definition file has `private_key` and `sign_cert` fields, then the tool signs the manifest using the private key and certificate they specify, respectively.  Otherwise, the tool uses the built-in test certificate and key, which is suitable ONLY for development and testing.  You can also specify the private key and certificate using environment variables; for more information, see [Creating and using an X.509 certificate](x_509.md). 

**WARNING**: Accessing the private key and signing certificate directly like this is fine during development, but doing so in production may be insecure. Instead use a Key Management Service (KMS) or a hardware security module (HSM) to access the certificate and key; for example as show in the [C2PA Python Example](https://github.com/contentauth/c2pa-python-example).

### Specifying a parent file

A _parent file_ represents the state of the image before the current edits were made.

Specify a parent file as the argument to the `--parent` / `-p` option; for example:

```shell
c2patool sample/image.jpg -m sample/test.json -p sample/c.jpg -o signed_image.jpg
```

You can pass an ingredient generated with the `--ingredient` option by giving the folder or ingredient JSON file.

```shell
c2patool sample/C.jpg --ingredient --output ./ingredient

c2patool sample/image.jpg -m sample/test.json -p ./ingredient -o signed_image.jpg
```

### Forced overwrite

The tool will return an error if the output file already exists. Use the `--force` / `-f` option to force overwriting the output file. For example:

```shell
c2patool sample/image.jpg -m sample/test.json -f -o signed_image.jpg
```

## Generating an external manifest

Use the `--sidecar` / `-s` option to put the manifest in an external sidecar file in the same location as the output file. The manifest will have the same output filename but with a `.c2pa` extension. The tool will copy the output file but the original will be untouched.

```shell
c2patool sample/image.jpg -s -m sample/test.json -o signed_image.jpg
```
## Generating a remote manifest

Use the `--remote` / `-r` option to place an HTTP reference to the manifest in the output file. The manifest is returned as an external sidecar file in the same location as the output file with the same filename but with a `.c2pa` extension. Place the manifest at the location specified by the `-r` option. When using remote manifests the remote URL should be publicly accessible to be most useful to users. When verifying an asset, remote manifests are automatically fetched.

```shell
c2patool sample/image.jpg -r http://my_server/myasset.c2pa -m sample/test.json -o signed_image.jpg
```

In the example above, the tool will embed the URL `http://my_server/myasset.c2pa` in `signed_image.jpg` then fetch the manifest from that URL and save it to `signed_image.c2pa`.

If you use both the `-s` and `-r` options, the tool embeds a manifest in the output file and also adds the remote reference.

## Signing claim bytes with your own signer

When generating a manifest, if the private key is not accessible on the system on which you are running the tool, use the `--signer-path` argument to specify the path to an executable that performs signing. 
This executable receives the claim bytes (the bytes to be signed) from standard input (`stdin`) and outputs the signature bytes to standard output (`stdout`). 
 
 For example, the following command signs the asset's claim bytes by using an executable named `custom-signer`:

```shell
c2patool sample/image.jpg            \
    --manifest sample/test.json      \
    --output sample/signed-image.jpg \
    --signer-path ./custom-signer    \
    --reserve-size 20248             \
    -f
```

For information on calculating the value of the `--reserve-size` argument, see `c2patool --help`.

## Providing a manifest definition on the command line

To provide the manifest definition in a command line argument instead of a file, use the `--config` / `-c` option.

For example, the following command adds a custom assertion called "org.contentauth.test".

```shell
c2patool sample/image.jpg \
  -c '{"assertions": \
    [{"label": "org.contentauth.test", \
      "data": {"my_key": "whatever I want"}}]}'
```

## Speeding up signing

By default, `c2patool` validates the signature immediately after signing a manifest. To disable this and speed up the validation process, use the `--no_signing_verify` option.

## Configuring trust support

Enable trust support by using the `trust` subcommand, as follows:

```
c2patool [path] trust [OPTIONS]
```

When the `trust` subcommand is supplied, should c2patool encounter a problem with validating any of the claims in the asset, its JSON output will contain a `validation_status` field whose value is an array of objects, each describing a validation problem.

### Additional options

Several additional CLI options are available with the `trust` sub-command to specify the location of files containing the trust anchors list or known certificate list, as described in the following table. You can also use environment variables to specify these values.

<div class="trust-table" markdown="1">

| Option | Environment variable | Description |
| ------ | -------------------- | ----------- | 
| `--trust_anchors` | `C2PATOOL_TRUST_ANCHORS` | URL or relative path to a file containing a list of trust anchors (in PEM format) used to validate the manifest certificate chain. To be valid, the manifest certificate chain must lead to a certificate on the trust list. All certificates in the trust anchor list must have the [Basic Constraints extension](https://docs.digicert.com/en/iot-trust-manager/certificate-templates/create-json-formatted-certificate-templates/extensions/basic-constraints.html) and the CA attribute of this extension must be `True`.  |
| `--allowed_list` | `C2PATOOL_ALLOWED_LIST` | URL or relative path to a file containing a list of end-entity certificates (in PEM format) to trust. These certificates are used to sign the manifest. Supersedes the `trust_anchors` setting. The list must NOT contain certificates with the [Basic Constraints extension](https://docs.digicert.com/en/iot-trust-manager/certificate-templates/create-json-formatted-certificate-templates/extensions/basic-constraints.html) with the CA attribute `True`. |
| `--trust_config` | `C2PATOOL_TRUST_CONFIG` | URL or relative path to a file containing the allowed set of custom certificate extended key usages (EKUs). Each entry in the list is an object identifiers in [OID dot notation](http://www.oid-info.com/#oid) format.  |

</div>

For example:

```shell
c2patool sample/C.jpg trust \
  --allowed_list sample/allowed_list.pem \
  --trust_config sample/store.cfg
```

Another example with URL argument values:

```shell
c2patool sample/C.jpg trust \
  --trust_anchors https://server.com/anchors.pem \
  --trust_config https://server.com/store.cfg
```

### Using the Verify known certificate list

**IMPORTANT:** The C2PA intends to publish an official trust list. Until that time, the [C2PA Verify tool uses a temporary known certificate list](https://opensource.contentauthenticity.org/docs/verify-known-cert-list). These lists are subject to change, and will be deprecated when C2PA publishes its trust list.

To configure C2PA tool to use the Verify temporary known certificate list, set the following environment variables on your system:

```shell
export C2PATOOL_TRUST_ANCHORS='https://contentcredentials.org/trust/anchors.pem'
export C2PATOOL_ALLOWED_LIST='https://contentcredentials.org/trust/allowed.sha256.txt'
export C2PATOOL_TRUST_CONFIG='https://contentcredentials.org/trust/store.cfg'
```

**Note:** When these environment variables are set, C2PA Tool will make several HTTP requests each time it  runs. Since these lists may change without notice (and the allowed list may change quite often), check these lists frequently to stay in sync with the Verify site. However, when performing bulk operations, you may want to cache these files locally to avoid a large number of network calls that might affect performance.

You can then run:

```shell
c2patool sample/C.jpg trust
```

You can also specify these values as CLI arguments instead:

```shell
c2patool sample/C.jpg trust \
  --trust_anchors='https://contentcredentials.org/trust/anchors.pem' \
  --allowed_list='https://contentcredentials.org/trust/allowed.sha256.txt' \
  --trust_config='https://contentcredentials.org/trust/store.cfg'
```

**Note:** This sample image should show a `signingCredential.untrusted` validation status since the test signing certificate used to sign them is not contained on the trust lists above.

## Adding a manifest to fragmented BMFF content

The ISO base media file format (BMFF) is a container file format that defines a structure for files that contain time-based multimedia data such as video and audio.

Add a manifest to a fragmented BMFF file by using the `fragment` subcommand, as follows:

```
c2patool <PATH | PATTERN> fragment [--fragments_glob]
```

Where `<PATTERN>` is a [glob pattern](https://en.wikipedia.org/wiki/Glob_(programming)).

For example, to add manifest to a video file:

```
c2patool -m test2.json -o  /1080p_out \
  /Downloads/1080p/avc1/init.mp4 \ 
  fragment --fragments_glob "seg-*[0-9].m4s"
```

Or to verify a manifest and fragments:
```
c2patool  /Downloads/1080p_out/avc1/init.mp4 \
  fragment --fragments_glob "seg-*[0-9].m4s"
```

### Additional option

The `--fragments_glob` option is only available with the `fragment` subcommand and specifies the glob pattern to find the fragments of the asset. The path is automatically set to be the same as the "init" segment, so the pattern must match only segment file names, not full paths.

## WASI

The wasm created for wasm32-wasip2 can be run directly with [wasmtime](https://docs.wasmtime.dev/). It also can be transpiled to a JS + core Wasm for JavaScript execution using [jco](https://bytecodealliance.github.io/jco/transpiling.html).
```
wasmtime -S cli -S http --dir . c2patool.wasm [OPTIONS] <PATH> [COMMAND]
```

