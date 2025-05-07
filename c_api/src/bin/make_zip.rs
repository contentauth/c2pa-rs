// Copyright 2023 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

// Unless required by applicable law or agreed to in writing,
// this software is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR REPRESENTATIONS OF ANY KIND, either express or
// implied. See the LICENSE-MIT and LICENSE-APACHE files for the
// specific language governing permissions and limitations under
// each license.

//! This script generates a ZIP file containing the C2PA C API header and dynamic library
//! for the specified target platform. It is intended to be run after the build process.
//! The ZIP file will be created in the `artifacts` directory located two levels up from the
//! target directory.
//!
//! The ZIP file will be named `c2pa-v<version>-<target>.zip`, where `<version>` is the version.
use std::{fs, path::Path};

use zip::{write::SimpleFileOptions, ZipWriter};

/// This is the main function that runs the script.
/// It takes the target directory as an argument and generates the ZIP file.
/// example `cargo run --release --bin make_zip -- <target_dir>`
/// This is part of the build process for the C2PA C API.
/// It generates a ZIP file containing the C2PA C API header and dynamic library
/// for the specified target platform.
/// The ZIP file will be created in a `artifacts` directory
/// It expects the target directory to contain a `c2pa_version.txt` file
/// with the version information and an include directory with the C2PA header file.
/// The ZIP file will be named `c2pa-v<version>-<target>.zip`
/// where `<version>` is the version read from `c2pa_version.txt`
/// and `<target>` is the target platform (e.g., `x86_64-unknown-linux-gnu`).
/// The ZIP file will contain the C2PA header file and the dynamic library for the target platform.
fn main() -> Result<(), std::io::Error> {
    let args: Vec<String> = std::env::args().collect();
    generate_zip_file(Path::new(&args[1]));
    Ok(())
}

/// Generates the ZIP file for the release build.
fn generate_zip_file(target_dir: &Path) {
    // first build a target folder with some files, including a version.txt file
    // then run this script with the target folder as an argument
    // e.g. cargo run --release --bin make_zip -- target/debug/build/c2pa-capi-1234567890abcdef

    let target = get_target(target_dir);
    let version = fs::read_to_string(target_dir.join("c2pa_version.txt"))
        .expect("could not read version from c2pa_version.txt");

    // Create the ZIP file name.
    let zip_file_name = format!("c2pa-v{}-{}.zip", version, target);
    let artifacts_dir = target_dir
        .ancestors()
        .nth(2)
        .expect("Failed to get parent directory")
        .join("artifacts");

    // Create the artifacts directory if it doesn't exist.
    if !artifacts_dir.exists() {
        fs::create_dir_all(&artifacts_dir).expect("Failed to create artifacts directory");
    }

    let zip_file_path = artifacts_dir.join(&zip_file_name);

    // Create the ZIP file.
    let zip_file = fs::File::create(&zip_file_path).expect("Failed to create zip file");
    let mut zip = ZipWriter::new(zip_file);

    // Add files to the ZIP archive.
    add_file_to_zip(&mut zip, &target_dir.join("c2pa.h"), "include/c2pa.h")
        .expect("Failed to add c2pa.h to zip");
    // add_file_to_zip(
    //     &mut zip,
    //     &Path::new(&crate_dir).join("../README.md"),
    //     "README.md",
    // )
    // .expect("Failed to add README.md to zip");
    // add_file_to_zip(
    //     &mut zip,
    //     &Path::new(&crate_dir).join("../CHANGELOG.md"),
    //     "CHANGELOG.md",
    // )
    // .expect("Failed to add CHANGELOG.md to zip");

    // Add the correct dynamic library for the platform.
    let lib_name = if target.contains("apple-darwin") {
        "libc2pa_c.dylib"
    } else if target.contains("windows") {
        "c2pa.dll"
    } else if target.contains("linux") {
        "libc2pa_c.so"
    } else {
        panic!("Unsupported platform: {}", target);
    };

    let lib_path = target_dir.join(lib_name);
    add_file_to_zip(&mut zip, &lib_path, &format!("lib/{}", lib_name))
        .expect("Failed to add dynamic library to zip");

    // Finish the ZIP archive.
    zip.finish().expect("Failed to finalize zip archive");

    println!("Packaged release into {}", zip_file_path.display());
}

/// Helper function to add a file to the ZIP archive.
fn add_file_to_zip<W: std::io::Write + std::io::Seek>(
    zip: &mut ZipWriter<W>,
    file_path: &Path,
    zip_path: &str,
) -> std::io::Result<()> {
    let mut file = fs::File::open(file_path)?;
    let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::DEFLATE);
    zip.start_file(zip_path, options)?;
    std::io::copy(&mut file, zip)?;
    Ok(())
}

fn get_target(path: &Path) -> String {
    path.components()
        .rev()
        .nth(1) // Get the second-to-last component
        .expect("Path does not have enough components")
        .as_os_str()
        .to_string_lossy()
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_target() {
        let path = Path::new("target/debug/build/c2pa-capi-1234567890abcdef");
        let target = get_target(path);
        assert_eq!(target, "build");
    }

    #[test]
    fn test_generate_zip_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let target_dir = temp_dir
            .path()
            .join("target/x86_64-unknown-linux-musl/release");
        fs::create_dir_all(&target_dir).unwrap();
        fs::write(target_dir.join("c2pa_version.txt"), "1.0.0").unwrap();
        fs::write(target_dir.join("c2pa.h"), "C2PA Header").unwrap();
        fs::write(target_dir.join("libc2pa_c.so"), "C2PA Library").unwrap();

        generate_zip_file(&target_dir);

        println!("Generated ZIP file in: {:?}", temp_dir.path());

        let zip_path = temp_dir
            .path()
            .join("target/artifacts/c2pa-v1.0.0-x86_64-unknown-linux-musl.zip");
        assert!(zip_path.exists());
    }
}
