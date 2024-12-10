# c2patool - C2PA command line tool

`c2patool` is a command line tool for working with C2PA [manifests](https://c2pa.org/specifications/specifications/1.3/specs/C2PA_Specification.html#_manifests) and media assets (audio, image or video files).

Use the tool on a file in one of the [supported formats](https://github.com/contentauth/c2pa-rs/blob/main/docs/supported-formats.md) to:

- Read a summary JSON report of C2PA manifests.
- Read a low-level report of C2PA manifest data.
- Add a C2PA manifest to the file.

For a simple example of calling c2patool from a Node.js server application, see the [c2pa-service-example](https://github.com/contentauth/c2patool-service-example) repository.

<div style={{display: 'none'}}>

**Additional documentation**:

- [Using C2PA Tool](./docs/usage.md)
- [Manifest definition file](./docs/manifest.md)
- [Using an X.509 certificate](./docs/x_509.md)
- [Release notes](./docs/release-notes.md)
- [Contributing to the project](./docs/project-contributions.md)

</div>

## Installation

There are two ways to install C2PA Tool:
- [Using a pre-built binary executable](#installing-a-pre-built-binary): This is the quickest way to install the tool.  If you just want to try C2PA Tool quickly, use this method.
- [Using Cargo Binstall](#using-cargo-binstall), a low-complexity way to install Rust binaries.  This method is preferable for long-term use. If you know you want to use C2PA Tool for development, use this method.

**NOTE:** If you want to contribute to the C2PA Tool project itself, or if a pre-built binary is not available for your system, see [Contributing to the project](./docs/project-contributions.md).

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

