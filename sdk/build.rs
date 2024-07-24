fn main() {
    // TODO: we don't want this to run during a normal debug build, check out:
    // https://github.com/rust-lang/cargo/issues/1581#issuecomment-1216924878

    // We only need the submodule (assets) when testing.
    #[cfg(debug_assertions)]
    std::process::Command::new("git")
        .args([
            "submodule",
            "update",
            "--init",
            "--depth 1",
            "--recommend-shallow",
        ])
        .output()
        .expect("Failed to fetch git submodules!");
}
