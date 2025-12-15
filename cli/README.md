# C2PA command line tool

C2PA Tool, `c2patool`, is a command line tool for working with C2PA [manifests](https://c2pa.org/specifications/specifications/1.4/specs/C2PA_Specification.html#_manifests) and media assets (audio, image or video files).

Use the tool on a file in one of the [supported formats](https://github.com/contentauth/c2pa-rs/blob/main/docs/supported-formats.md) to:

- Read a summary JSON report of C2PA manifests.
- Read a low-level report of C2PA manifest data.
- Create, edit, or update C2PA manifests in media files.
- Manage signing configuration and credentials.

For a simple example of calling c2patool from a Node.js server application, see the [c2patool-service-example](https://github.com/contentauth/c2pa-rs/blob/main/c2patool-service-example) repository.

<div style={{display: 'none'}}>

**Additional documentation**:

- [Using C2PA Tool](https://github.com/contentauth/c2pa-rs/blob/main/cli/docs/usage.md)
- [Manifest definition file](https://github.com/contentauth/c2pa-rs/blob/main/cli/docs/manifest.md)
- [Using an X.509 certificate](https://github.com/contentauth/c2pa-rs/blob/main/cli/docs/x_509.md)
- [Change log / release notes](https://github.com/contentauth/c2pa-rs/blob/main/cli/CHANGELOG.md)
- [Contributing to the project](https://github.com/contentauth/c2pa-rs/blob/main/cli/docs/project-contributions.md)

</div>

## Installation

To install a prebuilt binary of C2PA Tool:

1. Go to the [Releases page and filter for c2patool](https://github.com/contentauth/c2pa-rs/releases?q=c2patool). 
2. Under **Assets**, click on the archive file for your operating system:
   - MacOS: `c2patool-vx.y.z-universal-apple-darwin.zip`
   - Windows: `c2patool-vx.y.z-x86_64-pc-windows-msvc.zip`
   - Linux: `c2patool-vx.y.z-x86_64-unknown-linux-gnu.tar.gz`
3. Download and extract the archive file.
4. Copy the `c2patool` executable file to a location on your `PATH`.
5. Confirm that you can run the tool by entering a command such as:
```
c2patool --help
```

You may need to set execution permission for the tool on your system. 
For macOS, see [If you want to open an app that hasn’t been notarized or is from an unidentified developer](https://support.apple.com/en-us/102445#openanyway).

NOTE: You also may want to get some of the example files provided in the repository `sample` directory.   To do so, clone the repository with `git clone https://github.com/contentauth/c2pa-rs.git`.

### Installing from source

Instead of installing a prebuilt binary, you can [build the project from source](https://github.com/contentauth/c2pa-rs/blob/main/cli/docs/project-contributions.md#building-from-source).

### Upgrading

To display the version of C2PA Tool that you have, enter this command:

```
c2patool -V
```

The tool will display the version installed. Compare the version number displayed with the latest release version shown in the [repository releases page filtered for c2patool](https://github.com/contentauth/c2pa-rs/releases?q=c2patool).  If you don't have the latest version, simply reinstall to get the latest version.

## Quick Start

### Inspecting manifests

Display a summary of C2PA manifest data in an asset:

```sh
c2patool show image.jpg
```

Generate a detailed manifest report:

```sh
c2patool show image.jpg --detailed
```

### Creating manifests

Create a new C2PA manifest for a digital source (no parent):

```sh
c2patool create input.jpg -o output.jpg -m manifest.json
```

The manifest is signed and embedded by default. To create an unsigned work-in-progress:

```sh
c2patool create input.jpg -o output.jpg -m manifest.json --archive
```

### Editing manifests

Edit an existing manifest by adding a new manifest layer with a parent:

```sh
c2patool edit parent.jpg -o output.jpg -m manifest.json
```

You can also specify a different input file:

```sh
c2patool edit parent.jpg --input new_content.jpg -o output.jpg -m manifest.json
```

### Updating manifests

Update an existing manifest with new assertions (restricted set):

```sh
c2patool update input.jpg -o output.jpg -m manifest.json
```

With update, the input file is also the parent.

### Resuming work

Sign an archived (unsigned) manifest:

```sh
c2patool resume archived.jpg -o signed.jpg
```

### Configuration management

Show current configuration:

```sh
c2patool config show
```

Initialize a new settings file:

```sh
c2patool config init
```

Display the settings file path:

```sh
c2patool config path
```

Validate settings file syntax:

```sh
c2patool config validate
```

## Commands

C2patool uses a subcommand structure. Use `c2patool <command> --help` for detailed information about each command.

### `show`

Display C2PA manifest information from an asset.

```sh
c2patool show <asset> [OPTIONS]
```

Options:
- `--detailed` - Show detailed manifest report
- `--output <path>` - Write report to file instead of stdout
- `--force` - Force overwriting output file
- `--no-color` - Disable colored output

### `ingredient`

Generate an ingredient report from an asset.

```sh
c2patool ingredient <asset> [OPTIONS]
```

Options:
- `--output <path>` - Write ingredient JSON to file
- `--force` - Force overwriting output file

### `create`

Create a new C2PA manifest for a digital source asset. This sets the intent to "digitalSourceType" (no parent).

```sh
c2patool create <input> --output <output> --manifest <manifest> [OPTIONS]
```

Options:
- `--output, -o <path>` - Output file path (required)
- `--manifest, -m <path>` - Manifest definition file (required)
- `--archive` - Create unsigned work-in-progress (defers signing)
- `--force, -f` - Force overwriting output file
- `--no-color` - Disable colored output

### `edit`

Edit an existing manifest by adding a new layer with a parent reference.

```sh
c2patool edit <parent> --output <output> --manifest <manifest> [OPTIONS]
```

Options:
- `--output, -o <path>` - Output file path (required)
- `--manifest, -m <path>` - Manifest definition file (required)
- `--input <path>` - Optional different input file (defaults to parent)
- `--archive` - Create unsigned work-in-progress (defers signing)
- `--force, -f` - Force overwriting output file
- `--no-color` - Disable colored output

### `update`

Update an existing manifest with new assertions. The input file is also the parent. Only a restricted set of assertions can be added.

```sh
c2patool update <input> --output <output> --manifest <manifest> [OPTIONS]
```

Options:
- `--output, -o <path>` - Output file path (required)
- `--manifest, -m <path>` - Manifest definition file (required)
- `--archive` - Create unsigned work-in-progress (defers signing)
- `--force, -f` - Force overwriting output file
- `--no-color` - Disable colored output

### `resume`

Sign a previously archived (unsigned) manifest.

```sh
c2patool resume <input> --output <output> [OPTIONS]
```

Options:
- `--output, -o <path>` - Output file path (required)
- `--force, -f` - Force overwriting output file
- `--no-color` - Disable colored output

### `config`

Manage c2patool configuration and settings.

```sh
c2patool config <subcommand>
```

Subcommands:
- `show` - Display current configuration
- `init` - Create a new settings file
- `validate` - Validate settings file syntax
- `path` - Display the settings file path

### `fragment`

Work with fragmented manifests (advanced usage).

```sh
c2patool fragment <input> --output <output> [OPTIONS]
```

Options:
- `--output, -o <path>` - Output file path (required)
- `--manifest, -m <path>` - Manifest definition file (required)
- `--force, -f` - Force overwriting output file
- `--no-color` - Disable colored output

## Settings File

C2patool uses a settings file to store configuration like signing credentials, trust settings, and default behaviors. The settings file is located at:

- **macOS/Linux**: `$XDG_CONFIG_HOME/c2pa/settings.json` (or `~/.config/c2pa/settings.json`)
- **Windows**: `%APPDATA%\c2pa\settings.json`

Use `c2patool config path` to see the exact location on your system.

### Settings Format

The settings file can be in JSON or TOML format. JSON is preferred. Example:

```json
{
  "signer_path": "/path/to/private_key.pem",
  "trust": {
    "trust_anchors": ["/path/to/trust_anchors"],
    "allowed_list": ["/path/to/allowed_list"],
    "trust_config": "/path/to/store.cfg"
  },
  "reserve_size": 20000,
  "verify_after_sign": true
}
```

### Configuration Fields

- `signer_path` - Path to signing credentials (private key or signing box)
- `trust` - Trust configuration for validation
  - `trust_anchors` - Array of paths to trust anchor files or directories
  - `allowed_list` - Array of paths to allowed certificate lists
  - `trust_config` - Path to trust configuration file (store.cfg)
- `reserve_size` - Reserve space for future manifest updates (bytes)
- `verify_after_sign` - Automatically verify manifest after signing

## Additional Documentation

- [Using C2PA Tool](https://github.com/contentauth/c2pa-rs/blob/main/cli/docs/usage.md)
- [Manifest definition file](https://github.com/contentauth/c2pa-rs/blob/main/cli/docs/manifest.md)
- [Using an X.509 certificate](https://github.com/contentauth/c2pa-rs/blob/main/cli/docs/x_509.md)
- [Change log / release notes](https://github.com/contentauth/c2pa-rs/blob/main/cli/CHANGELOG.md)
- [Contributing to the project](https://github.com/contentauth/c2pa-rs/blob/main/cli/docs/project-contributions.md)
