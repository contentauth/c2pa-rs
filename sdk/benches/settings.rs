use c2pa::settings::Settings;
use criterion::{criterion_group, criterion_main, Criterion};

fn large_trust_settings() -> Settings {
    let blob = "a".repeat(1024 * 1024);
    Settings::default()
        .with_value("trust.trust_config", blob.as_str())
        .unwrap()
}

fn bench_with_value(c: &mut Criterion) {
    let settings = Settings::default();

    c.bench_function("settings/with_value", |b| {
        b.iter(|| settings.with_value("verify.verify_trust", false).unwrap());
    });
}

fn bench_with_value_large_trust(c: &mut Criterion) {
    let blob = "a".repeat(1024 * 1024);
    let settings = Settings::default();

    c.bench_function("settings/with_value 1MB trust", |b| {
        b.iter(|| {
            settings
                .with_value("trust.trust_config", blob.as_str())
                .unwrap()
        });
    });
}

fn bench_with_value_overlay_value_on_large_trust(c: &mut Criterion) {
    let settings = large_trust_settings();

    c.bench_function(
        "settings/with_value overlay value on 1MB trust settings",
        |b| {
            b.iter(|| settings.with_value("verify.verify_trust", false).unwrap());
        },
    );
}

fn bench_with_json_large_trust_overlay(c: &mut Criterion) {
    let blob = "a".repeat(1024 * 1024);
    let json = serde_json::json!({ "trust": { "trust_config": blob } }).to_string();
    let settings = Settings::default();

    c.bench_function(
        "settings/with_json 1MB trust overlay on existing settings",
        |b| {
            b.iter(|| settings.with_json(&json).unwrap());
        },
    );
}

criterion_group!(
    benches,
    bench_with_value,
    bench_with_value_large_trust,
    bench_with_value_overlay_value_on_large_trust,
    bench_with_json_large_trust_overlay,
);
criterion_main!(benches);
