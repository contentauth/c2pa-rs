// Copyright 2026 Adobe. All rights reserved.
// This file is licensed under the Apache-2.0 or MIT license, at your option.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::{io::Cursor, ops::Range};

use super::*;

fn boxed(kind: &[u8; 4], payload: &[u8], large: bool) -> Vec<u8> {
    let size = payload.len() + if large { 16 } else { 8 };
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&(if large { 1 } else { size as u32 }).to_be_bytes());
    bytes.extend_from_slice(kind);
    if large {
        bytes.extend_from_slice(&(size as u64).to_be_bytes());
    }
    bytes.extend_from_slice(payload);
    bytes
}

fn tfra(version: u8, widths: [u8; 3], track: u32, offsets: &[u64], large: bool) -> Vec<u8> {
    let mut payload = vec![version, 0, 0, 0];
    payload.extend_from_slice(&track.to_be_bytes());
    let sizes = ((widths[0] - 1) << 4) | ((widths[1] - 1) << 2) | (widths[2] - 1);
    payload.extend_from_slice(&u32::from(sizes).to_be_bytes());
    payload.extend_from_slice(&(offsets.len() as u32).to_be_bytes());
    for (i, offset) in offsets.iter().enumerate() {
        let time = 123 + i as u64 * 997;
        if version == 1 {
            payload.extend_from_slice(&(time + u64::from(u32::MAX)).to_be_bytes());
            payload.extend_from_slice(&offset.to_be_bytes());
        } else {
            payload.extend_from_slice(&(time as u32).to_be_bytes());
            payload.extend_from_slice(&u32::try_from(*offset).unwrap().to_be_bytes());
        }
        for (field, width) in widths.iter().enumerate() {
            for byte in 0..*width {
                payload.push(1 + i as u8 + field as u8 * 16 + byte);
            }
        }
    }
    boxed(b"tfra", &payload, large)
}

// A direct arena isolates TFRA validation, including malformed boxes the tree parser rejects.
fn adjust_box(
    bytes: &mut Cursor<Vec<u8>>,
    size: u64,
    delta: i64,
    replaced: Range<u64>,
) -> Result<()> {
    let (tree, token) = Arena::with_data(BoxInfo {
        path: "tfra".to_string(),
        parent: None,
        offset: 0,
        size,
        box_type: BoxType::TfraBox,
        user_type: None,
        version: None,
        flags: None,
    });
    let map = HashMap::from([("/mfra/tfra".to_string(), vec![token])]);
    adjust_known_offsets(bytes, &tree, &map, delta, replaced)
}

#[test]
fn versions_widths_and_large_headers_preserve_every_non_offset_byte() {
    for version in [0, 1] {
        for large in [false, true] {
            for traf in 1..=4 {
                for trun in 1..=4 {
                    for sample in 1..=4 {
                        let widths = [traf, trun, sample];
                        for (delta, offsets) in [
                            (-37, [100, 100, 500, 900]),
                            (0, [100, 100, 500, 900]),
                            (53, [100, 100, 500, 900]),
                            (53, [100; 4]),
                        ] {
                            let original = tfra(version, widths, 7, &offsets, large);
                            let size = original.len() as u64;
                            let mut output = Cursor::new(original);
                            output.set_position(3);
                            adjust_box(&mut output, size, delta, 50..50).unwrap();
                            assert_eq!(output.position(), 3);
                            let expected = offsets.map(|n| n.checked_add_signed(delta).unwrap());
                            assert_eq!(
                                output.into_inner(),
                                tfra(version, widths, 7, &expected, large)
                            );
                        }
                    }
                }
            }
        }
    }
}

#[test]
fn splice_boundaries_use_original_coordinates() {
    for version in [0, 1] {
        for (range, delta, offsets, expected) in [
            (100..100, 20, [99, 100, 101], [99, 120, 121]),
            (100..120, 30, [99, 120, 121], [99, 150, 151]),
            (100..120, -20, [99, 120, 121], [99, 100, 101]),
            (100..120, 0, [99, 120, 121], [99, 120, 121]),
            (1000..1020, i64::MIN, [0, 99, 999], [0, 99, 999]),
        ] {
            let mut output = Cursor::new(tfra(version, [1, 2, 3], 1, &offsets, false));
            let size = output.get_ref().len() as u64;
            adjust_box(&mut output, size, delta, range).unwrap();
            assert_eq!(
                output.into_inner(),
                tfra(version, [1, 2, 3], 1, &expected, false)
            );
        }
        for offset in [100, 110, 119] {
            for delta in [-20, 0, 30] {
                let mut output = Cursor::new(tfra(version, [1; 3], 1, &[offset], false));
                let size = output.get_ref().len() as u64;
                assert!(matches!(
                    adjust_box(&mut output, size, delta, 100..120),
                    Err(Error::InvalidAsset(_))
                ));
            }
        }
    }
}

#[test]
fn checked_offset_arithmetic() {
    let big = i64::from(i32::MAX) + 1;
    for (version, offset, delta, expected) in [
        (0, 0, big, Some(big as u64)),
        (0, u64::from(u32::MAX), -big - 1, Some(big as u64 - 2)),
        (0, u64::from(u32::MAX) - 1, 1, Some(u64::from(u32::MAX))),
        (0, u64::from(u32::MAX), 1, None),
        (0, 0, -1, None),
        (0, 1, -2, None),
        (0, u64::from(u32::MAX), i64::MIN, None),
        (
            1,
            u64::from(u32::MAX),
            big,
            Some(u64::from(u32::MAX) + big as u64),
        ),
        (1, big as u64 + 1, -big - 1, Some(0)),
        (1, u64::MAX - 1, 1, Some(u64::MAX)),
        (1, u64::MAX, 1, None),
        (1, 1 << 63, i64::MAX, Some(u64::MAX)),
        (1, (1 << 63) + 1, i64::MAX, None),
        (1, 0, -1, None),
        (1, 1, -2, None),
        (1, 1 << 63, i64::MIN, Some(0)),
        (1, (1 << 63) - 1, i64::MIN, None),
        (1, u64::MAX, i64::MIN, Some(i64::MAX as u64)),
    ] {
        let mut output = Cursor::new(tfra(version, [4, 2, 3], 1, &[offset], false));
        let size = output.get_ref().len() as u64;
        let result = adjust_box(&mut output, size, delta, 0..0);
        if let Some(expected) = expected {
            result.unwrap();
            assert_eq!(
                output.into_inner(),
                tfra(version, [4, 2, 3], 1, &[expected], false)
            );
        } else {
            assert!(
                matches!(result, Err(Error::InvalidAsset(_))),
                "v{version}: {offset} + {delta}: {result:?}"
            );
        }
    }
}

#[test]
fn empty_tables_and_unknown_versions() {
    for large in [false, true] {
        for version in [0, 1, 2, 255] {
            for offsets in [&[][..], &[100][..]] {
                let original = tfra(version, [4; 3], 1, offsets, large);
                let size = original.len() as u64;
                let mut output = Cursor::new(original.clone());
                let result = adjust_box(&mut output, size, 1, 0..0);
                if version <= 1 {
                    result.unwrap();
                    if offsets.is_empty() {
                        assert_eq!(output.into_inner(), original);
                    }
                } else {
                    assert!(matches!(result, Err(Error::InvalidAsset(_))));
                }
            }
        }
    }
}

#[test]
fn short_headers_and_truncated_trailing_numbers() {
    for version in [0, 1] {
        for large in [false, true] {
            let original = tfra(version, [4; 3], 1, &[100], large);
            let header = if large { 16 } else { 8 };
            // Keep the declared size: these exercise actual short reads, not just size preflight.
            for length in (0..header + 16).chain(original.len() - 12..original.len()) {
                let mut output = Cursor::new(original[..length].to_vec());
                assert!(
                    adjust_box(&mut output, original.len() as u64, 1, 0..0).is_err(),
                    "v{version}, large={large}, truncated at {length}"
                );
            }
        }
    }
}

#[test]
fn declared_bounds_do_not_consume_following_box() {
    let sentinel = boxed(b"free", &[0xa5; 64], false);
    for version in [0, 1] {
        for large in [false, true] {
            let valid = tfra(version, [4; 3], 1, &[100], large);
            let header = if large { 16 } else { 8 };
            for size in header..valid.len() {
                let mut bytes = valid[..size].to_vec();
                if large {
                    bytes[8..16].copy_from_slice(&(size as u64).to_be_bytes());
                } else {
                    bytes[..4].copy_from_slice(&(size as u32).to_be_bytes());
                }
                bytes.extend_from_slice(&sentinel);
                let mut output = Cursor::new(bytes.clone());
                assert!(
                    matches!(
                        adjust_box(&mut output, size as u64, 1, 0..0),
                        Err(Error::InvalidAsset(_))
                    ),
                    "v{version}, large={large}, declared size={size}"
                );
                assert_eq!(output.into_inner(), bytes, "preflight must precede writes");
            }
            for count in [2u32, u32::MAX] {
                let mut bytes = valid.clone();
                bytes[header + 12..header + 16].copy_from_slice(&count.to_be_bytes());
                bytes.extend_from_slice(&sentinel);
                let mut output = Cursor::new(bytes.clone());
                assert!(matches!(
                    adjust_box(&mut output, valid.len() as u64, 1, 0..0),
                    Err(Error::InvalidAsset(_))
                ));
                assert_eq!(output.into_inner(), bytes, "preflight must precede writes");
            }
        }
    }
}

fn synthetic(version: u8, middle: &[u8]) -> Vec<u8> {
    let mut bytes = boxed(b"ftyp", b"mp41\0\0\0\0", false);
    let mut offsets = Vec::new();
    for sequence in 1u32..=3 {
        offsets.push(bytes.len() as u64);
        let mut mfhd = vec![0; 4];
        mfhd.extend_from_slice(&sequence.to_be_bytes());
        let mut moof = boxed(b"mfhd", &mfhd, false);
        for track in [1u32, 2] {
            let mut tfhd = vec![0, 2, 0, 0]; // default-base-is-moof, no absolute TFHD offset
            tfhd.extend_from_slice(&track.to_be_bytes());
            moof.extend(boxed(b"traf", &boxed(b"tfhd", &tfhd, false), false));
        }
        bytes.extend(boxed(b"moof", &moof, false));
        if sequence == 1 {
            bytes.extend_from_slice(middle);
        }
    }
    let mut mfra = tfra(
        version,
        [1, 2, 3],
        1,
        &[offsets[0], offsets[0], offsets[2]],
        false,
    );
    mfra.extend(tfra(version, [4, 3, 2], 2, &[offsets[1], offsets[2]], true));
    bytes.extend(boxed(b"mfra", &mfra, true));
    bytes
}

// Compare entire TFRA boxes, replacing only offsets with the intended moof's new position.
// Entries may repeat a moof or skip moofs; no one-entry-per-moof assumption is made.
// This checks TFRA preservation, not the correctness of other media-addressing fields.
fn assert_targets(original: &[u8], current: &[u8]) {
    let (old_tree, old_map) = BMFFArena::from_stream(&mut Cursor::new(original)).unwrap();
    let (new_tree, new_map) = BMFFArena::from_stream(&mut Cursor::new(current)).unwrap();
    let old_moofs = &old_map["/moof"];
    let new_moofs = &new_map["/moof"];
    assert_eq!(old_moofs.len(), new_moofs.len());
    for (old, new) in old_moofs.iter().zip(new_moofs) {
        let old = &old_tree.as_ref()[*old].data;
        let new = &new_tree.as_ref()[*new].data;
        // Absolute TFHD base offsets within a moof may also be relocated.
        assert_eq!(old.size, new.size);
    }
    assert_eq!(old_map["/mfra/tfra"].len(), new_map["/mfra/tfra"].len());
    for (old, new) in old_map["/mfra/tfra"].iter().zip(&new_map["/mfra/tfra"]) {
        let old = &old_tree.as_ref()[*old].data;
        let new = &new_tree.as_ref()[*new].data;
        let mut expected =
            Cursor::new(original[old.offset as usize..(old.offset + old.size) as usize].to_vec());
        BoxHeaderLite::read(&mut expected).unwrap();
        let (version, _) = read_box_header_ext(&mut expected).unwrap();
        expected.read_u32::<BigEndian>().unwrap(); // track ID
        let widths = expected.read_u32::<BigEndian>().unwrap();
        let trailing = ((widths >> 4) & 3) + ((widths >> 2) & 3) + (widths & 3) + 3;
        let count = expected.read_u32::<BigEndian>().unwrap();
        for _ in 0..count {
            let width = if version == 1 { 8 } else { 4 };
            expected.seek(SeekFrom::Current(width)).unwrap(); // time
            let position = expected.position();
            let offset = if version == 1 {
                expected.read_u64::<BigEndian>().unwrap()
            } else {
                u64::from(expected.read_u32::<BigEndian>().unwrap())
            };
            let index = old_moofs
                .iter()
                .position(|t| old_tree.as_ref()[*t].data.offset == offset)
                .expect("original TFRA entry must point to an actual moof");
            let target = new_tree.as_ref()[new_moofs[index]].data.offset;
            expected.set_position(position);
            if version == 1 {
                expected.write_u64::<BigEndian>(target).unwrap();
            } else {
                expected
                    .write_u32::<BigEndian>(u32::try_from(target).unwrap())
                    .unwrap();
            }
            expected
                .seek(SeekFrom::Current(i64::from(trailing)))
                .unwrap();
        }
        assert_eq!(
            expected.into_inner(),
            &current[new.offset as usize..(new.offset + new.size) as usize]
        );
    }
}

#[test]
fn public_manifest_write_grow_shrink_and_remove() {
    let io = BmffIO::new("mp4");
    for version in [0, 1] {
        for later in [false, true] {
            let mut middle = Vec::new();
            if later {
                write_c2pa_box(&mut middle, &[0; 32], MANIFEST, &[], 0).unwrap();
            }
            let original = synthetic(version, &middle);
            let mut current = original.clone();
            for size in [64, 256, 4, 4] {
                let mut output = Cursor::new(Vec::new());
                io.write_c2pa(&mut Cursor::new(&current), &mut output, &vec![0; size])
                    .unwrap();
                current = output.into_inner();
                assert_targets(&original, &current);
                assert_eq!(
                    io.read_c2pa(&mut Cursor::new(&current)).unwrap(),
                    vec![0; size]
                );
            }
            let mut output = Cursor::new(Vec::new());
            io.remove_c2pa(&mut Cursor::new(&current), &mut output)
                .unwrap();
            assert_targets(&original, output.get_ref());
            assert_eq!(output.into_inner(), synthetic(version, &[]));
        }
    }
}

#[test]
fn public_xmp_and_placeholder_adjust_tfra() {
    let io = BmffIO::new("mp4");
    for version in [0, 1] {
        for later in [false, true] {
            let mut middle = Vec::new();
            if later {
                write_xmp_box(&mut middle, b"<x:xmpmeta/>").unwrap();
            }
            let original = synthetic(version, &middle);
            let mut current = original.clone();
            for padding in [32, 128, 0, 0] {
                let xmp = format!("<x:xmpmeta>{}</x:xmpmeta>", " ".repeat(padding));
                let mut output = Cursor::new(Vec::new());
                io.write_xmp(&mut Cursor::new(&current), &mut output, &xmp)
                    .unwrap();
                current = output.into_inner();
                assert_targets(&original, &current);
                assert_eq!(io.read_xmp(&mut Cursor::new(&current)).unwrap(), xmp);
            }
        }
        let original = synthetic(version, &[]);
        let mut output = Cursor::new(Vec::new());
        assert_eq!(
            inject_placeholder(&mut Cursor::new(&original), &mut output, 80).unwrap(),
            16
        );
        assert_targets(&original, output.get_ref());
        assert_eq!(output.get_ref().len(), original.len() + 80);
    }
}

#[test]
fn fragmented_fixture_preserves_intended_moofs() {
    let original = include_bytes!("../../../tests/fixtures/fragmented_mfra.mp4");
    let (tree, map) = BMFFArena::from_stream(&mut Cursor::new(original.as_slice())).unwrap();
    // This specific ffmpeg fixture has five fragments and one TFRA entry per fragment.
    assert_eq!(map["/moof"].len(), 5);
    assert_eq!(map["/mfra/tfra"].len(), 1);
    let info = &tree.as_ref()[map["/mfra/tfra"][0]].data;
    let mut reader = Cursor::new(original.as_slice());
    reader.set_position(info.offset);
    BoxHeaderLite::read(&mut reader).unwrap();
    reader.seek(SeekFrom::Current(12)).unwrap();
    assert_eq!(reader.read_u32::<BigEndian>().unwrap(), 5);
    assert_targets(original, original);

    let io = BmffIO::new("mp4");
    let mut current = original.to_vec();
    for size in [32, 512, 4, 4] {
        let mut output = Cursor::new(Vec::new());
        io.write_c2pa(&mut Cursor::new(&current), &mut output, &vec![0; size])
            .unwrap();
        current = output.into_inner();
        assert_targets(original, &current);
    }
    let mut output = Cursor::new(Vec::new());
    io.remove_c2pa(&mut Cursor::new(current), &mut output)
        .unwrap();
    assert_targets(original, output.get_ref());
    assert_eq!(output.get_ref().as_slice(), original);
}

#[test]
fn full_signing_preserves_tfra_targets() {
    use crate::{
        status_tracker::StatusTracker,
        store::Store,
        utils::{
            test::{create_test_claim, test_context},
            test_signer::test_signer,
        },
        SigningAlg,
    };

    let original = include_bytes!("../../../tests/fixtures/fragmented_mfra.mp4");
    let context = test_context();
    let signer = test_signer(SigningAlg::Ps256);
    let mut store = Store::from_context(&context);
    store.commit_claim(create_test_claim().unwrap()).unwrap();
    let mut output = Cursor::new(Vec::new());
    store
        .save_to_stream(
            "video/mp4",
            &mut Cursor::new(original.as_slice()),
            &mut output,
            signer.as_ref(),
            &context,
        )
        .unwrap();

    assert_targets(original, output.get_ref());
    output.rewind().unwrap();
    let mut report = StatusTracker::default();
    Store::from_stream("video/mp4", &mut output, &mut report, &context).unwrap();
    assert!(!report.has_any_error(), "{report:?}");
}
