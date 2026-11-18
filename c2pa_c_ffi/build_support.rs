// Copyright 2026 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

use std::path::Path;

pub fn header_dir_from_out_dir(out_dir: &Path) -> Option<&Path> {
    // Cargo 1.100 split the crate name and hash into separate directories below build/.
    out_dir
        .ancestors()
        .find(|path| path.file_name().is_some_and(|name| name == "build"))
        .and_then(Path::parent)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_directory_matches_library_directory() {
        for (out_dir, expected) in [
            (
                "target/debug/build/c2pa-c-ffi-abc123/out",
                "target/debug",
            ),
            (
                "target/debug/build/c2pa-c-ffi/abc123/out",
                "target/debug",
            ),
            (
                "target/aarch64-apple-ios/release/build/c2pa-c-ffi-abc123/out",
                "target/aarch64-apple-ios/release",
            ),
            (
                "target/aarch64-apple-ios/release/build/c2pa-c-ffi/abc123/out",
                "target/aarch64-apple-ios/release",
            ),
            (
                "/workspace/target-i686-linux-android/i686-linux-android/release/build/c2pa-c-ffi-abc123/out",
                "/workspace/target-i686-linux-android/i686-linux-android/release",
            ),
            (
                "/workspace/target-i686-linux-android/i686-linux-android/release/build/c2pa-c-ffi/abc123/out",
                "/workspace/target-i686-linux-android/i686-linux-android/release",
            ),
            (
                "/workspace/build/target/debug/build/c2pa-c-ffi/abc123/out",
                "/workspace/build/target/debug",
            ),
        ] {
            assert_eq!(
                header_dir_from_out_dir(Path::new(out_dir)),
                Some(Path::new(expected)),
                "{out_dir}",
            );
        }
    }

    #[test]
    fn rejects_paths_without_a_build_directory() {
        assert_eq!(
            header_dir_from_out_dir(Path::new("target/debug/c2pa-c-ffi/abc123/out")),
            None,
        );
    }
}
