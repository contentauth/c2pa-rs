# `cawg-identity` crate is DISCONTINUED

This crate has been merged into the [`c2pa` crate](https://crates.io/crates/c2pa). It will no longer be maintained or published as a standalone crate.

For the most part, all public APIs can be remapped as follows:

> `cawg_identity::xxx` -> `c2pa::identity::xxx`

This version of the `cawg_identity` crate provides `pub use` aliases for all public APIs to match the above remapping. This can be used as a transition measure, but you should change the references in your code as soon as possible.

There will be no further releases of this crate.
