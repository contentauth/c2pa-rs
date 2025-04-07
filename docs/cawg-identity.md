# Using the CAWG identity assertion

The CAI Rust library includes an implementation of the core of the [Creator Assertions Working Group identity assertion](https://cawg.io/identity/).

<!-- 

- Should this say v 1.0 and link to https://cawg.io/identity/1.0/ ?

-->

The code in [`cawg_identity/examples/cawg.rs`](https://github.com/contentauth/c2pa-rs/blob/main/cawg_identity/examples/cawg.rs) provides a minimal example.  Run it by entering the command:

```sh
cargo run --example cawg -- <SOURCE_FILE> <OUTPUT_FILE>
```

Where `<SOURCE_FILE>` is the path to the input asset file and `<OUTPUT_FILE>` is the path where the example saves the resulting asset file with CAWG identity assertion.

```sh
cargo run --example cawg -- ./sdk/tests/fixtures/CA.jpg cawg-out.jpg
```