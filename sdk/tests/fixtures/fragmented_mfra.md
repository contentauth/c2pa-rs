# Fragmented MP4 TFRA Fixture

`fragmented_mfra.mp4` is a synthetic FFmpeg `testsrc` video generated for this
regression. It contains no customer footage, Big Buck Bunny content, or audio.
It follows the five-fragment fixture design contributed by BibinBaby444 in
[PR #1](https://github.com/mstattma/c2pa-rs/pull/1), commit
`6c1328cd83fe170123cf630a5a15b049a384c063`, but was regenerated using the command
below rather than copying the original binary.

Run from the repository root with FFmpeg 6.1.1 (Ubuntu package
`6.1.1-3ubuntu5`, libavcodec 60.31.102, libavformat 60.16.100):

```sh
ffmpeg -hide_banner -loglevel error -y \
  -f lavfi -i 'testsrc=size=64x64:rate=10:duration=5' \
  -an -c:v libx264 -preset ultrafast -crf 23 -pix_fmt yuv420p \
  -threads 1 -g 10 -keyint_min 10 -sc_threshold 0 -bf 0 \
  -movflags +frag_keyframe+empty_moov -map_metadata -1 \
  sdk/tests/fixtures/fragmented_mfra.mp4
```

The generated file is 38,547 bytes, with SHA-256
`18060be8e53932f018479c1752ec876617436996ede12eff0dda2505cf55a2e1`.
Encoder or muxer version changes can produce different bytes; the tests check
fragment targets rather than fixed byte positions. No FFmpeg installation is
needed to run the tests against the checked-in fixture.

The fixture exercises preservation of the intended `moof` targets in `mfra/tfra`
when a C2PA manifest is inserted, grown, shrunk, or removed. Its one-entry-per-moof
layout is specific to this fixture, not a general TFRA requirement. Omitting
`default_base_moof` keeps explicit absolute TFHD base offsets in the generated
file, while `frag_keyframe` and the fixed GOP produce five fragments and TFRA
entries.
