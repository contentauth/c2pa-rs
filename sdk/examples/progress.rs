// Copyright 2024 Adobe. All rights reserved.
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

//! Example demonstrating the progress/cancel API.
//!
//! With no arguments it runs against embedded test fixtures:
//!   - reads `CA.jpg` and signs it to `target/progress_output.jpg`
//!
//! With one argument it performs a read-only pass:
//!   - `cargo run --example progress -- input.jpg`
//!
//! With two arguments it reads and signs:
//!   - `cargo run --example progress -- input.jpg output.jpg`
//!
//! Progress lines are printed to stdout. Press Enter at any time to cancel.

use std::{
    env,
    fs::{self, OpenOptions},
    io::{BufReader, Cursor},
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Instant,
};
#[cfg(not(target_arch = "wasm32"))]
use std::{io, thread};

use anyhow::{Context as _, Result};
use c2pa::{Builder, BuilderIntent, Context, Error, ProgressPhase, Reader, Settings};
use serde_json::json;

const SOURCE_IMAGE: &[u8] = include_bytes!("../tests/fixtures/CA.jpg");
const DEFAULT_FORMAT: &str = "image/jpeg";

/// Infer the MIME type from a file's extension, falling back to JPEG.
fn format_for_path(path: &std::path::Path) -> String {
    c2pa::format_from_path(path).unwrap_or_else(|| DEFAULT_FORMAT.to_string())
}

fn default_output_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../target/progress_output.jpg")
}

fn manifest_def(title: &str, format: &str) -> String {
    json!({
        "title": title,
        "format": format,
        "claim_generator_info": [{
            "name": "c2pa progress example",
            "version": env!("CARGO_PKG_VERSION")
        }]
    })
    .to_string()
}

fn print_progress(phase: ProgressPhase, step: u32, total: u32, elapsed_ms: f64) {
    if total == 0 {
        println!("[{elapsed_ms:>8.3}ms] {phase:?} {step}/?");
    } else {
        println!("[{elapsed_ms:>8.3}ms] {phase:?} {step}/{total}");
    }
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();

    let (input_path, output_path): (Option<PathBuf>, Option<PathBuf>) = match args.len() {
        1 => (None, Some(default_output_path())),
        2 => (Some(PathBuf::from(&args[1])), None),
        _ => (Some(PathBuf::from(&args[1])), Some(PathBuf::from(&args[2]))),
    };

    let settings =
        Settings::new().with_json(include_str!("../tests/fixtures/test_settings.json"))?;

    let timer: Arc<Mutex<Instant>> = Arc::new(Mutex::new(Instant::now()));
    let timer_cb = timer.clone();

    let context = Context::new()
        .with_settings(settings)?
        .with_progress_callback(move |phase, step, total| {
            let elapsed_ms = timer_cb.lock().unwrap().elapsed().as_secs_f64() * 1000.0;
            print_progress(phase, step, total, elapsed_ms);
            true
        })
        .into_shared();

    // Spawn a thread that cancels the operation when the user presses Enter.
    // If stdin is not a terminal (e.g. redirected from /dev/null) we ignore
    // the immediate EOF and leave the operation to complete normally.
    // Not available on WASM targets (no threads or stdin).
    #[cfg(not(target_arch = "wasm32"))]
    {
        let cancel_ctx = context.clone();
        thread::spawn(move || {
            eprintln!("(press Enter to cancel)");
            let mut buf = String::new();
            if io::stdin().read_line(&mut buf).unwrap_or(0) > 0 {
                eprintln!("Cancelling...");
                cancel_ctx.cancel();
            }
        });
    }

    let result = if let Some(ref out_path) = output_path {
        run_sign(&context, &timer, input_path.as_deref(), out_path)
    } else {
        run_read(&context, &timer, input_path.as_deref())
    };

    match result {
        Ok(()) => {}
        Err(ref e) if is_cancelled(e) => {
            eprintln!("Operation cancelled.");
        }
        Err(e) => return Err(e),
    }

    Ok(())
}

fn run_read(
    context: &Arc<Context>,
    timer: &Arc<Mutex<Instant>>,
    input: Option<&std::path::Path>,
) -> Result<()> {
    eprintln!(
        "Reading: {}",
        input
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "CA.jpg (embedded)".into())
    );
    *timer.lock().unwrap() = Instant::now();

    match input {
        Some(path) => {
            let format = format_for_path(path);
            let mut f = BufReader::new(
                std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?,
            );
            Reader::from_shared_context(context).with_stream(&format, &mut f)?;
        }
        None => {
            let mut src = Cursor::new(SOURCE_IMAGE);
            Reader::from_shared_context(context).with_stream(DEFAULT_FORMAT, &mut src)?;
        }
    }

    eprintln!("Read complete.");
    Ok(())
}

fn run_sign(
    context: &Arc<Context>,
    timer: &Arc<Mutex<Instant>>,
    input: Option<&std::path::Path>,
    output: &std::path::Path,
) -> Result<()> {
    eprintln!(
        "Signing: {} -> {}",
        input
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "CA.jpg (embedded)".into()),
        output.display()
    );

    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)?;
    }

    let input_format = input
        .map(format_for_path)
        .unwrap_or_else(|| DEFAULT_FORMAT.to_string());

    let mut builder = Builder::from_shared_context(context)
        .with_definition(manifest_def("Progress Example", &input_format))?;

    // Edit intent: the source asset is treated as the parent ingredient.
    match input {
        Some(path) => {
            let format = format_for_path(path);
            let mut f = BufReader::new(
                std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?,
            );
            builder.add_ingredient_from_stream(
                json!({ "title": path.file_name().unwrap_or_default().to_string_lossy(), "relationship": "parentOf" })
                    .to_string(),
                &format,
                &mut f,
            )?;
        }
        None => {
            let mut src = Cursor::new(SOURCE_IMAGE);
            builder.add_ingredient_from_stream(
                json!({ "title": "CA.jpg", "relationship": "parentOf" }).to_string(),
                DEFAULT_FORMAT,
                &mut src,
            )?;
        }
    }

    builder.set_intent(BuilderIntent::Edit);

    *timer.lock().unwrap() = Instant::now();

    // dest must be readable and seekable for in-place embedding.
    let mut dest = OpenOptions::new()
        .create(true)
        .write(true)
        .read(true)
        .truncate(true)
        .open(output)
        .with_context(|| format!("creating {}", output.display()))?;

    let sign_result = match input {
        Some(path) => {
            let format = format_for_path(path);
            let mut source = BufReader::new(
                std::fs::File::open(path).with_context(|| format!("opening {}", path.display()))?,
            );
            builder.save_to_stream(&format, &mut source, &mut dest)
        }
        None => {
            let mut source = Cursor::new(SOURCE_IMAGE);
            builder.save_to_stream(DEFAULT_FORMAT, &mut source, &mut dest)
        }
    };

    if let Err(e) = sign_result {
        drop(dest);
        if let Err(remove_err) = fs::remove_file(output) {
            eprintln!(
                "Warning: could not remove partial output {}: {remove_err}",
                output.display()
            );
        }
        return Err(e.into());
    }

    eprintln!("Signed. Output: {}", output.display());
    Ok(())
}

/// Returns true if the error (or any of its chain) is `Error::OperationCancelled`.
fn is_cancelled(e: &anyhow::Error) -> bool {
    e.chain().any(|cause| {
        cause
            .downcast_ref::<Error>()
            .map(|e| matches!(e, Error::OperationCancelled))
            .unwrap_or(false)
    })
}

#[cfg(test)]
mod tests {
    use c2pa_macros::c2pa_test_async;
    #[cfg(all(target_arch = "wasm32", not(target_os = "wasi")))]
    use wasm_bindgen_test::*;

    use super::*;

    #[c2pa_test_async]
    async fn test_progress_sign() -> Result<()> {
        let out = default_output_path();
        run_sign(
            &Context::new()
                .with_settings(
                    Settings::new()
                        .with_json(include_str!("../tests/fixtures/test_settings.json"))?,
                )?
                .into_shared(),
            &Arc::new(Mutex::new(Instant::now())),
            None,
            &out,
        )
    }
}
