# C2PA Tool command reference

C2PA Tool's command-line syntax is:

```
c2patool <ASSET_PATH> [OPTIONS] [SUBCOMMAND]
```

Where:
- `<ASSET_PATH>` is the (relative or absolute) file path to the asset to read or embed a manifest into.
- `[OPTIONS]` is one or more of the command-line options described in following table.
- `[SUBCOMMAND]` is one of the optional subcommands: `trust`, `fragment`, or `help`.

By default, C2PA Tool writes a JSON representation of C2PA manifest data found in the asset to the standard output. 

## Subcommands

The tool supports the following subcommands:
- `trust` [configures trust support](usage.md#configuring-trust-support) for certificates on a "known certificate list." With this subcommand, several additional options are available.
- `fragment` [adds a manifest to fragmented BMFF content](usage.md#adding-a-manifest-to-fragmented-bmff-content).  With this subcommand, one additional option is available.
- `help` displays command line help information.

## Options

The following options are available with any (or no) subcommand.  Additional options are available with each subcommand.

| CLI&nbsp;option&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp; | Short version | Argument | Description |
|-----|----|----|----|
| `--certs` | | N/A | Extract a certificate chain to standard output (stdout). |
| `--config` | `-c` | `<config>` | Specify a manifest definition as a JSON string. See [Providing a manifest definition on the command line](usage.md#providing-a-manifest-definition-on-the-command-line). |
| `--detailed` | `-d` | N/A | Display detailed C2PA-formatted manifest data. See [Displaying a detailed manifest report](usage.md#detailed-manifest-report). |
| `--external-manifest` | N/A | `<c2pa_file>` | Path to the binary .c2pa manifest to use for validation against the input asset. |
| `--force` | `-f` | N/A | Force overwriting output file. See [Forced overwrite](usage.md#forced-overwrite). |
| `--help` | `-h` | N/A | Display CLI help information. |
| `--info` |  | N/A | Display brief information about the file. |
| `--ingredient` | `-i` | N/A | Create an Ingredient definition in --output folder. |
| `--manifest` | `-m` | `<manifest_file>` | Specify a manifest file to add to an asset file. See [Adding a manifest to an asset file](usage.md#adding-a-manifest-to-an-asset-file).
| `--no_signing_verify` | None | N/A |  Do not validate the signature after signing an asset, which speeds up signing. See [Speeding up signing](usage.md#speeding-up-signing) |
| `--output` | `-o` | `<output_file>` | Path to output folder or file. See [Adding a manifest to an asset file](usage.md#adding-a-manifest-to-an-asset-file). |
| `--parent` | `-p` | `<parent_file>` | Path to parent file. See [Specifying a parent file](usage.md#specifying-a-parent-file). |
| `--remote` | `-r` | `<manifest_url>` | URL for remote manifest available over HTTP. See [Generating a remote manifest](usage.md#generating-a-remote-manifest)| N/A? |
| `--reserve-size` | N/A | Only valid with `--signer-path` argument. The amount of memory to reserve for signing. Default: 20000. For more information, see CLI help. |
| `--settings`  | N/A | Path to the settings file file.<br/>Default is value of environment variable C2PATOOL_SETTINGS. If the environment variable is not set, then default is` ~/.config/c2pa/c2pa.toml`. |  Path to the config file.  See [Configuring SDK settings](../../docs/settings.md) | 
| `--sidecar` | `-s` | N/A | Put manifest in external "sidecar" file with `.c2pa` extension. See [Generating an external manifest](usage.md#generating-an-external-manifest). |
| `--signer-path` | N/A | Specify path to command-line executable for signing.  See [Signing claim bytes with your own signer](usage.md#signing-claim-bytes-with-your-own-signer). |
| `--tree` | | N/A | Create a tree diagram of the manifest store. |
| `--version` | `-V` | N/A | Display version information. |
