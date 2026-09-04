# Using C2PA Tool

C2PA Tool's command-line syntax is:

```
c2patool <ASSET_PATH> [OPTIONS] [SUBCOMMAND]
```

Where:
- `<ASSET_PATH>` is the (relative or absolute) file path to the asset to read or embed a manifest into.
- `[OPTIONS]` is one or more of the [command-line options](#options) described in following table.
- `[SUBCOMMAND]` is one of the optional [subcommands](#subcommands): `trust`, `fragment`, `live-video`, `live-video-sign`, or `help`.

By default, C2PA Tool writes the JSON manifest data found in the asset to the standard output. You can override the default by using the `--output, -o` option.

## Subcommands

The tool supports the following subcommands:
- `trust` [configures trust support](#configuring-trust-support) for certificates on a "known certificate list." With this subcommand, several additional options are available.
- `fragment` [adds a manifest to fragmented BMFF content](#adding-a-manifest-to-fragmented-bmff-content).  With this subcommand, one additional option is available.
- `live-video` and `live-video-sign` [sign and validate live video streams](#signing-and-validating-live-video-streams-experimental) (experimental, requires the `unstable_live_video` feature).
- `help` displays command line help information.

## Options

The following options are available with any (or no) subcommand.  Additional options are available with each subcommand.

| CLI&nbsp;option&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; | Short version | Argument | Description |
|-----|----|----|----|
| `--certs` | | N/A | Extract a certificate chain to standard output (stdout). See [Extracting a certificate chain](#extracting-a-certificate-chain). |
| `--config` | `-c` | `<config>` | Specify a [manifest definition](manifest.md) as a JSON string. See [Providing a manifest definition on the command line](#providing-a-manifest-definition-on-the-command-line). |
| `--create` | | `<source_type>` | Create a new manifest with the specified [C2PA digital source type](https://cv.iptc.org/newscodes/digitalsourcetype/) (e.g. `digitalCapture`, `trainedAlgorithmicMedia`). Mutually exclusive with `--update` and `--parent`. See [Specifying manifest intent](#specifying-manifest-intent). |
| `--detailed` | `-d` | N/A | Display detailed C2PA-formatted manifest data. See [Displaying a detailed manifest report](#detailed-manifest-report). |
| `--external-manifest` | N/A | `<c2pa_file>` | Path to the binary `.c2pa` (sidecar) manifest to use for validation against the input asset. See [Using an external manifest](#using-an-external-manifest). |
| `--force` | `-f` | N/A | Force overwriting output file. See [Forced overwrite](#forced-overwrite). |
| `--help` | `-h` | N/A | Display CLI help information. |
| `--info` |  | N/A | Display brief information about the file. See [Displaying an information report](#displaying-an-information-report). |
| `--ingredient` | `-i` | N/A | Create an ingredient definition in the `--output` folder. See [Creating an ingredient from a file](#creating-an-ingredient-from-a-file). |
| `--manifest` | `-m` | `<manifest_file>` | Specify a [manifest definition file](manifest.md) to add to an asset file. See [Adding a manifest to an asset file](#adding-a-manifest-to-an-asset-file). |
| `--no_signing_verify` | None | N/A |  Do not validate the signature after signing an asset, which speeds up signing. See [Speeding up signing](#speeding-up-signing) |
| `--output` | `-o` | `<output_file>` | Path to output folder or file. This option can be used in two ways:<br/>&bull;With the `-m` option to [add a manifest to the specified asset file](#adding-a-manifest-to-an-asset-file). The argument then specifies the name of the resulting asset file with Content Credentials added.<br/>&bull;Without the `-m` option to [write the manifest data to a directory](#saving-manifest-data-to-a-directory) (including assertion and ingredient thumbnails). The argument then specifies the output directory to use. |
| `--parent` | `-p` | `<parent_file>` | Path to parent file. See [Specifying a parent file](#specifying-a-parent-file). |
| `--remote` | `-r` | `<manifest_url>` | URL for remote manifest available over HTTP. See [Generating a remote manifest](#generating-a-remote-manifest). |
| `--identity-signer-path` | N/A | `<command>` | Command for signing the CAWG identity assertion. Same protocol as `--signer-path`. See [Signing assets](signing.md). |
| `--reserve-size` | N/A | `<size>` | Space to reserve for signatures when using `--signer-path` or `--identity-signer-path`. Default: 20000. See [Signing assets](signing.md). |
| `--settings` | N/A | `<settings_file>` | Path to the settings file. Default is the value of the `C2PATOOL_SETTINGS` environment variable. If not set, defaults to `~/.config/c2pa/c2pa.toml`. See [Configuring SDK settings](https://opensource.contentauthenticity.org/docs/rust-sdk/docs/context-settings). |
| `--sidecar` | `-s` | N/A | Put manifest in external "sidecar" file with `.c2pa` extension. See [Generating an external manifest](#generating-an-external-manifest). |
| `--signer-path` | N/A | `<command>` | Command for signing the C2PA claim. See [Signing assets](signing.md). |
| `--tree` | | N/A | Create a tree diagram of the manifest store. See [Displaying a tree diagram](#displaying-a-tree-diagram). |
| `--update` | | N/A | Create an [update manifest](https://c2pa.org/specifications/specifications/2.1/specs/C2PA_Specification.html#_update_manifests) (non-editorial changes to an already-signed parent asset). Mutually exclusive with `--create`. See [Specifying manifest intent](#specifying-manifest-intent). |
| `--version` | `-V` | N/A | Display version information. |

## Displaying manifest data

To display the manifest associated with an asset file, provide the path to the file as the argument; for example:

```shell
c2patool sample/C.jpg
```

The tool displays the manifest JSON to standard output (stdout).

### Saving manifest data to a directory

Use the `--output` argument to write the contents of the manifest (including the manifest's assertion and ingredient thumbnails) to the specified directory.

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

### Extracting a certificate chain

Use the `--certs` option to extract the PEM certificate chain from the active manifest's signature and print it to standard output (stdout). For example:

```shell
c2patool sample/C.jpg --certs
```

This is useful for inspecting the signing certificate used to sign the manifest.

### Using an external manifest

Use the `--external-manifest` option to validate an asset against a separate binary `.c2pa` sidecar manifest file instead of the manifest embedded in the asset. This overrides any embedded or remote manifest. For example:

```shell
c2patool sample/image.jpg --external-manifest sample/image.c2pa
```

### Displaying a tree diagram

Use the `--tree` option to display a text tree diagram of the manifest store, showing the structure of assertions and nested ingredients. For example:

```shell
c2patool sample/C.jpg --tree
```

### Forced overwrite

The tool will return an error if the output file already exists. Use the `--force` / `-f` option to force overwriting the output file. For example:

```shell
c2patool sample/image.jpg -m sample/test.json -f -o signed_image.jpg
```

## Creating an ingredient from a file

The `--ingredient` option creates an ingredient report.  When used with the `--output` folder, it extracts or creates a thumbnail image and a binary `.c2pa` manifest store containing the C2PA data from the file. The JSON ingredient this produces can be added to a manifest definition to carry the full history and validation record of that asset into a newly-created manifest.

Provide the path to the file as the argument; for example:

```shell
c2patool sample/C.jpg --ingredient --output ./ingredient
```

## Adding a manifest to an asset file

Use the `--manifest` / `-m` option to add the C2PA [manifest definition file](manifest.md) specified in the argument to the asset file to be signed. Specify the output file as the argument to the `--output` / `-o` option. The output extension type must match the source. The tool will not convert between file types. For example:

```shell
c2patool sample/image.jpg -m sample/test.json -o signed_image.jpg
```

The tool generates a new manifest using the values given in the file and displays the manifest store to standard output (stdout).

> [!WARNING]
> If the output file is the same as the source file, the tool will overwrite the source file.

For full details on configuring signers — including how to write a subprocess signer, use a remote signing service, or add a CAWG identity assertion — see [Signing assets](signing.md).

> [!WARNING]
> Providing a private key directly in a manifest file or settings file is suitable only for development and testing. In production, use a subprocess signer or remote signing service so that private key material never passes through c2patool.

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

### Specifying manifest intent

Every C2PA manifest records an _intent_ that describes how the content was produced. C2PA Tool supports three intents, controlled by the `--create` and `--update` flags:

| Intent | Flag | When to use |
|--------|------|-------------|
| **Create** | `--create <source-type>` | The output is a new original creation with no prior editing history. |
| **Edit** | _(default — no flag needed)_ | The output is derived from one or more source assets through an editorial process. |
| **Update** | `--update` | Non-editorial technical changes were applied to an already-signed asset (e.g., re-encoding or format conversion). |

#### Create intent (`--create`)

Use `--create <source-type>` to declare that the output is a new creation. Provide one of the [IPTC digital source type](https://cv.iptc.org/newscodes/digitalsourcetype/) values:

```shell
c2patool new_image.jpg \
  -c '{"assertions":[]}' \
  --create digitalCapture \
  -o signed_image.jpg
```

The tool automatically adds a `c2pa.created` action. `--create` is mutually exclusive with `--update` and `--parent`.

Some common source-type values:

| Value | Meaning |
|-------|---------|
| `digitalCapture` | Original capture from a camera or microphone |
| `algorithmicMedia` | Produced entirely by an algorithm |
| `trainedAlgorithmicMedia` | Produced by a trained AI model |
| `compositeWithTrainedAlgorithmicMedia` | Composite that includes AI-generated elements |

See the [IPTC digital source type vocabulary](https://cv.iptc.org/newscodes/digitalsourcetype/) for the full list.

#### Edit intent (default)

When neither `--create` nor `--update` is given, the tool applies **Edit** intent. The source asset is automatically added as a parent ingredient and a `c2pa.opened` action is injected into the manifest:

```shell
c2patool source_image.jpg -m sample/test.json -o signed_image.jpg
```

Use `--parent` / `-p` when the parent asset is a different file from the source (see [Specifying a parent file](#specifying-a-parent-file)).

#### Update intent (`--update`)

Use `--update` to declare that non-editorial changes were applied to an already-signed asset. The source asset **must already contain a C2PA manifest**.

```shell
c2patool source_with_manifest.jpg \
  -c '{"assertions":[]}' \
  --update \
  -o updated_image.jpg
```

The tool automatically adds a `c2pa.opened` action and sets the source asset as the parent ingredient. `--update` is mutually exclusive with `--create`.

### Generating an external manifest

Use the `--sidecar` / `-s` option to put the manifest in an external sidecar file in the same location as the output file. The manifest will have the same output filename but with a `.c2pa` extension. The tool will copy the output file but the original will be untouched.

```shell
c2patool sample/image.jpg -s -m sample/test.json -o signed_image.jpg
```
### Generating a remote manifest

Use the `--remote` / `-r` option to place an HTTP reference to the manifest in the output file. The manifest is returned as an external sidecar file in the same location as the output file with the same filename but with a `.c2pa` extension. Place the manifest at the location specified by the `-r` option. When using remote manifests the remote URL should be publicly accessible to be most useful to users. When verifying an asset, remote manifests are automatically fetched.

```shell
c2patool sample/image.jpg -r http://my_server/myasset.c2pa -m sample/test.json -o signed_image.jpg
```

In the example above, the tool will embed the URL `http://my_server/myasset.c2pa` in `signed_image.jpg` then fetch the manifest from that URL and save it to `signed_image.c2pa`.

If you use both the `-s` and `-r` options, the tool embeds a manifest in the output file and also adds the remote reference.

### Signing with your own signer

Use `--signer-path` to delegate C2PA claim signing to an external executable, and `--identity-signer-path` to additionally embed a CAWG identity assertion signed by a separate executable. Both accept a command string (binary path and optional arguments):

```shell
c2patool sample/image.jpg            \
    --manifest sample/test.json      \
    --output sample/signed-image.jpg \
    --signer-path ./my-signer        \
    -f
```

The signer executable must implement the subprocess signing protocol: respond to `--signer-info` with a JSON object describing its certificate and algorithm, and sign bytes received on stdin by writing the raw signature to stdout. For the full protocol specification, error handling details, and guidance on writing your own signer, see [Signing assets](signing.md).

### Providing a manifest definition on the command line

To provide the manifest definition as a command line argument instead of in a file, use the `--config` / `-c` option. The JSON format is the same as in a [manifest definition file](manifest.md).

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

Use the `trust` subcommand to specify _trust lists_ that the tool consults to determine if an asset was signed by a "trusted" certificate, which can be either a certificate on the specified _allowed list_ or a certificate that chains back to a root certificate on the specified _trust anchors_ list. 

There are two significant trust lists for signing Content Credentials:

- The [official C2PA trust list](https://opensource.contentauthenticity.org/docs/conformance/trust-lists#c2pa-trust-list) that products in the [C2PA conformance program](https://opensource.contentauthenticity.org/docs/conformance/) use. The [Adobe Content Authenticity Inspect tool](https://inspect.cr/) uses the official C2PA trust list. 
- The legacy [interim trust list](https://opensource.contentauthenticity.org/docs/conformance/trust-lists#interim-trust-list), which is now frozen; no new certificates can be added to this list. Currently, the [C2PA Verify tool](https://verify.contentauthenticity.org/) uses this trust list.

> [!NOTE]
> With the `trust` subcommand, C2PA Tool will make several HTTP requests each time it runs. Since these lists may change without notice (and the allowed list may change quite often), check these lists frequently to stay in sync with the Verify site. However, when performing bulk operations, you may want to cache these files locally to avoid a large number of network calls that might affect performance.

### Trust subcommand options

Enable trust support by using the `trust` subcommand, as follows:

```
c2patool <ASSET_PATH> trust [OPTIONS]
```

If C2PA Tool can't validate any of the claims in the asset against the specified trust lists, the JSON output will contain a `validation_status` field whose value is an array of objects, each describing a validation problem.

Several additional CLI options are available with the `trust` sub-command, as described in the following table. You can also use environment variables to specify these values.

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

### Using the official C2PA trust list

To specify the [official C2PA trust list](https://github.com/c2pa-org/conformance-public/blob/main/trust-list/C2PA-TRUST-LIST.pem) use the `--trust_anchors` option as follows:

```shell
c2patool sample/C.jpg trust \
  --trust_anchors='https://raw.githubusercontent.com/c2pa-org/conformance-public/refs/heads/main/trust-list/C2PA-TRUST-LIST.pem' \
```

The C2PA trust list does not provide "allowed list" of end-entity certificates, nor do you need to specify the `--trust_config` option.

Alternatively, set the following environment variable on your system:

```shell
export C2PATOOL_TRUST_ANCHORS='https://raw.githubusercontent.com/c2pa-org/conformance-public/refs/heads/main/trust-list/C2PA-TRUST-LIST.pem'
```

### Using the interim trust list

To use the legacy interim trust list, specify the CLI options as follows:

```shell
c2patool sample/C.jpg trust \
  --trust_anchors='https://contentcredentials.org/trust/anchors.pem' \
  --allowed_list='https://contentcredentials.org/trust/allowed.sha256.txt' \
  --trust_config='https://contentcredentials.org/trust/store.cfg'
```

Alternatively, set the following environment variables on your system:

```shell
export C2PATOOL_TRUST_ANCHORS='https://contentcredentials.org/trust/anchors.pem'
export C2PATOOL_ALLOWED_LIST='https://contentcredentials.org/trust/allowed.sha256.txt'
export C2PATOOL_TRUST_CONFIG='https://contentcredentials.org/trust/store.cfg'
```

You can then run, for example:

```shell
c2patool sample/C.jpg trust
```

> [!NOTE]
> This sample image shows a `signingCredential.untrusted` validation status since the test signing certificate used is not contained on the trust lists above.

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

### Additional option for BMFF files

The `--fragments_glob` option is only available with the `fragment` subcommand and specifies the glob pattern to find the fragments of the asset. The path is automatically set to be the same as the "init" segment, so the pattern must match only segment file names, not full paths.

## Signing and validating live video streams (experimental)

C2PA [section 19 (Live Video)](https://spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html#live-video) support is an experimental feature: it's available only in a build with the `unstable_live_video` Cargo feature enabled, and is exempt from the crate's usual stability guarantees. See the [experimental features policy](https://github.com/contentauth/c2pa-rs/blob/main/docs/experimental-features.md).

Live video streams a fragmented MP4 (fMP4) asset segment by segment rather than as one finished file, so it needs its own signing and validation flow instead of the single-asset one described above. Two subcommands are available: `live-video-sign` to sign a stream and `live-video` to validate one.

Two signing methods are supported, per §19.3 (per-segment C2PA Manifest Box, the default) and §19.4 (Verifiable Segment Info, which needs an Ed25519 session key):

```
c2patool <SEGMENTS_DIR> live-video-sign --segments_glob <GLOB> -o <OUTPUT_DIR> -m <MANIFEST_FILE> [--init <INIT_FILE>]

c2patool <SEGMENTS_DIR> live-video-sign --segments_glob <GLOB> -o <OUTPUT_DIR> -m <MANIFEST_FILE> --method vsi --session-key <KEY_FILE> --init <INIT_FILE>
```

The manifest definition passed to `-m` must include a `c2pa.livevideo.segment` assertion with a `streamId`; see [Manifest definition](manifest.md).

To validate a previously signed stream, pass the init segment and the same glob pattern used to sign it. The validation method (§19.3 or §19.4) is detected automatically from the init segment's manifest:

```
c2patool <INIT_FILE> live-video --segments_glob <GLOB>
```

Per-segment progress is written to stderr and a JSON report to stdout, so the report can be redirected on its own:

```
c2patool <INIT_FILE> live-video --segments_glob <GLOB> > report.json
```

The report gives the stream's overall `validation_state`, the detected method, the state of each segment, and any failures, using the [section 19.7 status codes](https://spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html#_live_video_validation_process):

```json
{
  "validation_state": "Valid",
  "method": "19.3 (per-segment C2PA Manifest Box)",
  "init_segment": "stream/init.mp4",
  "segments": [
    { "path": "stream/seg_001.m4s", "state": "Valid" }
  ],
  "validation_results": {
    "failure": [
      {
        "code": "livevideo.segment.invalid",
        "explanation": "previousManifestId does not match the previous segment's manifest identifier"
      }
    ]
  }
}
```

A stream is reported at the level of its weakest segment, following the nesting of manifest states in §14.3.2. The command exits with a non-zero status when the state is `Invalid`.

### Trust lists and live video

Validation follows the general rules of chapter 15, as §19.7.1 requires. A stream whose signer doesn't chain to a trust anchor is reported as `Valid` rather than `Trusted`, and is accepted: §15.7 makes verifying a chain of trust a `should`, and §14.3.3 treats an asset backed by a manifest that is "either Valid or Trusted" as valid. Content failures such as `assertion.bmffHash.mismatch` still make a segment `Invalid`.

Once a trust list is configured, §15.7 requires an unverifiable chain to be rejected, so a `signingCredential.untrusted` failure becomes fatal and the stream is reported as `Invalid`.

`live-video` picks up trust material from sidecar files kept in the settings directory, which defaults to the platform configuration directory (`~/.config/c2pa/` on Linux, and note that `$XDG_CONFIG_HOME` is often unset, in which case that is the path used). No flag is needed to use it: `--settings` only moves that directory elsewhere, which is worth doing in CI or in a script that runs against several trust configurations, so a stray anchor in the shared location cannot silently make everything `Trusted`. Only the directory is used; the settings file inside it does not have to exist.

There are two ways to put the sidecars there.

To trust the official C2PA conformance list, let `c2patool` fetch it:

```
c2patool init trust
c2patool <INIT_FILE> live-video --segments_glob <GLOB>
```

To trust your own anchors, copy the PEM into place yourself:

```
mkdir -p ~/.config/c2pa
cp my-anchors.pem ~/.config/c2pa/c2pa-trust-list.pem
c2patool <INIT_FILE> live-video --segments_glob <GLOB>
```

Or, keeping it out of the shared directory:

```
mkdir -p /tmp/my-trust
cp my-anchors.pem /tmp/my-trust/c2pa-trust-list.pem
c2patool --settings /tmp/my-trust/c2pa.toml <INIT_FILE> live-video --segments_glob <GLOB>
```

Either way, four sidecar names are recognised, and all of them are read for every subcommand:

| File | Contents | Written by |
|-----|----|----|
| `c2pa-trust-list.pem` | Trust anchors. | `init trust` |
| `c2pa-trust-list-legacy.pem` | Legacy interim anchors, applied as user anchors. | `init trust --legacy` |
| `c2pa-trust-store.cfg` | Allowed extended key usage (EKU) OIDs. | `init trust --legacy` |
| `c2pa-trust-allowed.sha256.txt` | Certificates to trust explicitly. | `init trust --legacy` |

The `trust` subcommand's `--trust_anchors`, `--allowed_list` and `--trust_config` options cannot be combined with `live-video`, since a single invocation runs one subcommand. Anchors can also be embedded in the settings file's own `[trust]` section as inline PEM strings, which is what the SDK ultimately consumes, but the sidecars avoid pasting certificates into a configuration document.

### Additional options for live video

| CLI option | Argument | Description |
|-----|----|----|
| `--segments_glob` | `<glob>` | Required with both `live-video` and `live-video-sign`. Glob pattern to find the media segments, resolved relative to the init segment's (or, for `live-video-sign`, the path argument's) directory, and matched in natural (numeric-aware) filename order. |
| `--init` | `<init_file>` | With `live-video-sign` (§19.3), optionally also signs the init segment. With `--method vsi`, the init segment is required (§19.4 mandates a signed manifest there). |
| `--previous-segment` | `<segment_file>` | Resumes the continuity chain from a prior `live-video-sign` invocation's last signed segment, for a process that restarts mid-stream. With `--method vsi`, this also skips re-signing the init segment. |
| `--method` | `manifest` &#124; `vsi` | Signing method for `live-video-sign` (default `manifest`). |
| `--session-key` | `<key_file>` | Required with `--method vsi`: an Ed25519 session key, as a 32-byte raw seed file. Reused across all invocations for the same live video session. |
| `--min-sequence-number` | `<n>` | With `--method vsi`, the VSI session key's starting `minSequenceNumber`. Only used on the first invocation (no `--previous-segment`); if omitted, it's inferred from the first media segment's own `moof/mfhd.sequence_number`. |
| `--session-key-validity` | `<seconds>` | With `--method vsi`, how long the session key stays valid (§18.25.2's `validityPeriod`), default 3600. Only used on the first invocation (no `--previous-segment`), since a resumed session reuses the already-signed init segment's key. Validators reject segments once the key is past this window, so a stream that runs longer must re-sign its init segment with a fresh key before then. |

## WASI

You can run the Wasm binary created for `wasm32-wasip2` directly with [wasmtime](https://docs.wasmtime.dev/). You can also transpile it into an ECMAScript module for JavaScript execution by using [jco](https://bytecodealliance.github.io/jco/transpiling.html) as follows:

```
wasmtime -S cli -S http --dir . c2patool.wasm [OPTIONS] <ASSET_PATH> [COMMAND]
```

