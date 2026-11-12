// Copyright 2026 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

use std::{env, fs, path::Path};

#[test]
fn generated_header_is_next_to_library_artifacts() {
    let executable = env::current_exe().expect("could not locate test executable");
    // Cargo 1.100 keeps test executables under build rather than deps.
    let profile_dir = executable
        .ancestors()
        .find(|path| {
            matches!(
                path.file_name().and_then(|name| name.to_str()),
                Some("deps" | "build")
            )
        })
        .and_then(Path::parent)
        .expect("test executable must be inside Cargo's artifact directory");
    let header = fs::read_to_string(profile_dir.join("c2pa.h"))
        .expect("c2pa.h must be generated next to the library artifacts");
    let version = format!("// Version: {}", env!("CARGO_PKG_VERSION"));
    assert!(
        header.lines().any(|line| line == version),
        "generated header must match the package version"
    );
}
