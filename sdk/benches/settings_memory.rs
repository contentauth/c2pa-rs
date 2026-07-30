#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

use c2pa::settings::Settings;
use dhat::{HeapStats, Profiler};

fn large_trust_settings() -> Settings {
    let blob = "a".repeat(1024 * 1024);
    Settings::default()
        .with_value("trust.trust_config", blob.as_str())
        .unwrap()
}

fn report(label: &str, stats: HeapStats) {
    println!(
        "{label}\n  total: {} bytes ({} blocks)\n  peak:  {} bytes ({} blocks)",
        stats.total_bytes, stats.total_blocks, stats.max_bytes, stats.max_blocks,
    );
}

fn bench_with_value_bool() {
    let _profiler = Profiler::builder().testing().build();
    Settings::default()
        .with_value("verify.verify_trust", false)
        .unwrap();
    report("with_value", HeapStats::get());
}

fn bench_with_value_1mb_trust(blob: &str) {
    let _profiler = Profiler::builder().testing().build();
    Settings::default()
        .with_value("trust.trust_config", blob)
        .unwrap();
    report("with_value 1MB trust", HeapStats::get());
}

fn bench_with_value_bool_on_large_settings(large_settings: &Settings) {
    let _profiler = Profiler::builder().testing().build();
    large_settings
        .with_value("verify.verify_trust", false)
        .unwrap();
    report("with_value on 1MB trust settings", HeapStats::get());
}

fn bench_with_json_large_overlay(large_json: &str) {
    let _profiler = Profiler::builder().testing().build();
    Settings::default().with_json(large_json).unwrap();
    report(
        "with_json 1MB trust overlay on existing settings",
        HeapStats::get(),
    );
}

fn main() {
    let blob = "a".repeat(1024 * 1024);
    let large_json = serde_json::json!({ "trust": { "trust_config": blob } }).to_string();
    let large_settings = large_trust_settings();

    bench_with_value_bool();
    bench_with_value_1mb_trust(&blob);
    bench_with_value_bool_on_large_settings(&large_settings);
    bench_with_json_large_overlay(&large_json);
}
