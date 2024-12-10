# Contributing

The information in this page is primarily for those who wish to contribute to the c2patool project itself, rather than those who simply wish to use it as a tool.  For general contribution guidelines, see [CONTRIBUTING.md](../CONTRIBUTING.md).

## Building from source

To build the project from source, enter these commands:

```shell
cargo install c2patool
```

To build the tool on a Windows machine, you need to install the [7zip](https://www.7-zip.org/) tool.

NOTE: If you encounter errors installing, you may need to update your Rust installation by entering this command:

```
rustup update
```

## Nightly builds

Interim binaries are generated every day around 05:30 UTC (overnight for our US-based team) and are available for roughly two weeks thereafter. These can be helpful for testing purposes. For more information, see the documentation on [nightly builds](https://github.com/contentauth/c2patool/tree/main/docs/nightly-builds/README.md).
