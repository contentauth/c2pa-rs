fn main() {
    // TODO: we don't want this to run during a normal debug build, check out:
    // https://github.com/rust-lang/cargo/issues/1581#issuecomment-1216924878

    std::process::Command::new("git")
        .args([
            "submodule",
            "update",
            "--init",
            "--depth",
            "1",
            "--recommend-shallow",
        ])
        .current_dir(std::path::Path::new(env!("CARGO_MANIFEST_DIR")))
        .output()
        .expect("Failed to fetch git submodules!");
}
