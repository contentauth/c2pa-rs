// Copyright 2026 Adobe. All rights reserved.
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

//! Shared helpers for the `live-video` and `live-video-sign` CLI subcommands.

use std::{
    cmp::Ordering,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};

/// Finds media segments matching `segments_glob` under `base_dir`, sorted in natural
/// (numeric-aware) filename order.
///
/// A plain lexicographic (byte-wise) sort misorders real-world segment names such as
/// DASH-IF's `$Time$`/unpadded `$Number$` templates once the numeric part's digit count
/// changes (e.g. `seg-9600.m4s` would sort after `seg-10800.m4s`), which breaks
/// sequence-number-based continuity validation on real streams.
pub(crate) fn collect_segments(base_dir: &Path, segments_glob: &Path) -> Result<Vec<PathBuf>> {
    let seg_glob = base_dir.join(segments_glob);
    let seg_glob_str = seg_glob
        .to_str()
        .context("segment glob path is not valid UTF-8")?;

    let mut paths: Vec<PathBuf> = glob::glob(seg_glob_str)
        .context("invalid segment glob pattern")?
        .filter_map(|r| r.ok())
        .collect();

    paths.sort_by(|a, b| {
        let a_name = a.file_name().and_then(|n| n.to_str()).unwrap_or_default();
        let b_name = b.file_name().and_then(|n| n.to_str()).unwrap_or_default();
        natural_cmp(a_name, b_name)
    });
    Ok(paths)
}

/// Compares two strings so that embedded runs of digits are ordered by numeric value
/// rather than byte value (e.g. `"seg-2.m4s"` sorts before `"seg-10.m4s"`).
fn natural_cmp(a: &str, b: &str) -> Ordering {
    let mut a_chars = a.chars().peekable();
    let mut b_chars = b.chars().peekable();

    loop {
        let (ac, bc) = match (a_chars.peek(), b_chars.peek()) {
            (None, None) => return Ordering::Equal,
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (Some(&ac), Some(&bc)) => (ac, bc),
        };

        if ac.is_ascii_digit() && bc.is_ascii_digit() {
            let mut a_digits = String::new();
            while let Some(&c) = a_chars.peek() {
                if !c.is_ascii_digit() {
                    break;
                }
                a_digits.push(c);
                a_chars.next();
            }
            let mut b_digits = String::new();
            while let Some(&c) = b_chars.peek() {
                if !c.is_ascii_digit() {
                    break;
                }
                b_digits.push(c);
                b_chars.next();
            }

            // Compare by numeric value first (length of the zero-stripped run, then the
            // digits themselves — correct for arbitrarily large numbers), then fall back to
            // the raw digit strings so e.g. "007" still sorts after "07".
            let a_trimmed = a_digits.trim_start_matches('0');
            let b_trimmed = b_digits.trim_start_matches('0');
            match a_trimmed
                .len()
                .cmp(&b_trimmed.len())
                .then_with(|| a_trimmed.cmp(b_trimmed))
                .then_with(|| a_digits.cmp(&b_digits))
            {
                Ordering::Equal => continue,
                other => return other,
            }
        }

        match ac.cmp(&bc) {
            Ordering::Equal => {
                a_chars.next();
                b_chars.next();
            }
            other => return other,
        }
    }
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    use super::*;

    fn write_temp_file(dir: &TempDir, name: &str) {
        std::fs::write(dir.path().join(name), b"x").unwrap();
    }

    #[test]
    fn natural_cmp_orders_by_numeric_value() {
        let mut names = vec![
            "wdr-video=762993-9600.dash",
            "wdr-video=762993-0.dash",
            "wdr-video=762993-10800.dash",
            "wdr-video=762993-1200.dash",
        ];
        names.sort_by(|a, b| natural_cmp(a, b));
        assert_eq!(
            names,
            [
                "wdr-video=762993-0.dash",
                "wdr-video=762993-1200.dash",
                "wdr-video=762993-9600.dash",
                "wdr-video=762993-10800.dash",
            ]
        );
    }

    #[test]
    fn collect_segments_orders_real_world_dash_time_names() {
        let dir = tempfile::tempdir().unwrap();
        for t in [0, 1200, 2400, 3600, 4800, 6000, 7200, 8400, 9600, 10800] {
            write_temp_file(&dir, &format!("wdr-video=762993-{t}.dash"));
        }

        let segments = collect_segments(dir.path(), Path::new("wdr-video=762993-*.dash")).unwrap();

        let names: Vec<_> = segments
            .iter()
            .map(|p| p.file_name().unwrap().to_str().unwrap())
            .collect();
        assert_eq!(
            names,
            [
                "wdr-video=762993-0.dash",
                "wdr-video=762993-1200.dash",
                "wdr-video=762993-2400.dash",
                "wdr-video=762993-3600.dash",
                "wdr-video=762993-4800.dash",
                "wdr-video=762993-6000.dash",
                "wdr-video=762993-7200.dash",
                "wdr-video=762993-8400.dash",
                "wdr-video=762993-9600.dash",
                "wdr-video=762993-10800.dash",
            ]
        );
    }

    #[test]
    fn collect_segments_returns_sorted_paths() {
        let dir = tempfile::tempdir().unwrap();
        write_temp_file(&dir, "seg_003.m4s");
        write_temp_file(&dir, "seg_001.m4s");
        write_temp_file(&dir, "seg_002.m4s");

        let segments = collect_segments(dir.path(), Path::new("seg_*.m4s")).unwrap();

        let names: Vec<_> = segments
            .iter()
            .map(|p| p.file_name().unwrap().to_str().unwrap())
            .collect();
        assert_eq!(names, ["seg_001.m4s", "seg_002.m4s", "seg_003.m4s"]);
    }

    #[test]
    fn collect_segments_returns_empty_when_no_match() {
        let dir = tempfile::tempdir().unwrap();

        let segments = collect_segments(dir.path(), Path::new("seg_*.m4s")).unwrap();

        assert!(segments.is_empty());
    }
}
