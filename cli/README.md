# C2PA command line tool

C2PA Tool, `c2patool`, is a command line tool for working with C2PA [manifests](https://c2pa.org/specifications/specifications/1.4/specs/C2PA_Specification.html#_manifests) and media assets (audio, image or video files).

Use the tool on a file in one of the [supported formats](https://github.com/contentauth/c2pa-rs/blob/main/docs/supported-formats.md) to:

- Read a summary JSON report of C2PA manifests.
- Read a low-level report of C2PA manifest data.
- Add a C2PA manifest to the file.

For a simple example of calling c2patool from a Node.js server application, see the [c2patool-service-example](https://github.com/contentauth/c2patool-service-example) repository.

<div style={{display: 'none'}}>

**Additional documentation**:

- [Using C2PA Tool](./docs/usage.md)
- [Manifest definition file](./docs/manifest.md)
- [Using an X.509 certificate](./docs/x_509.md)
- [Change log / release notes](./CHANGELOG.md)
- [Contributing to the project](./docs/project-contributions.md)

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
c2patool -h
```

You may need to set execution permission for the tool on your system. 
For macOS, see [If you want to open an app that hasn’t been notarized or is from an unidentified developer](https://support.apple.com/en-us/102445#openanyway).

NOTE: You also may want to get some of the example files provided in the repository `sample` directory.   To do so, clone the repository with `git clone https://github.com/contentauth/c2pa-rs.git`.

### Installing from source

Instead of installing a prebuilt binary, you can [build the project from source](https://github.com/contentauth/c2pa-rs/blob/docs/no-c2patool-binstall/cli/docs/project-contributions.md#building-from-source).

### Upgrading

To display the version of C2PA Tool that you have, enter this command:

```
c2patool -V
```

The tool will display the version installed. Compare the version number displayed with the latest release version shown in the [repository releases page filtered for c2patool](https://github.com/contentauth/c2pa-rs/releases?q=c2patool).  If you don't have the latest version, simply reinstall to get the latest version.
