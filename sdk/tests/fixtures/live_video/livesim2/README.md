# livesim2 DASH/CMAF interop capture

These are unmodified responses from the DASH-IF reference simulator at
<https://livesim2.dashif.org>, captured on 2026-10-15. Tests use these checked-in
bytes offline; they do not require livesim2, Go, Docker, or network access.

## Provenance

- Server `/version` response: `{"Version":"v1.14.0, date: 2026-09-30"}`.
- Corresponding upstream release:
  [livesim2 v1.14.0](https://github.com/Dash-Industry-Forum/livesim2/tree/8a8d768017cdad2583dc15d5fd6e5c69d2225241).
  The server reports its version string; it does not attest a deployed Git commit.
- Source asset: DASH-IF
  [livesim-content, testpic_2s](https://github.com/Dash-Industry-Forum/livesim-content/tree/e2db1d1697eca2ef1a6cd0188158655b9f396acf/testpic_2s),
  representation `V300` (640x360 AVC, 30 fps, approximately 300 kbit/s).
  This is the content repository revision observed during capture; the server's
  deployed content revision is not exposed.
- URL prefix: `/livesim2/scte35_1/testpic_2s/`.
- Query on every request: `nowMS=1760000100000`, the simulator's supported override
  of its UTC clock. This keeps requests inside a fixed time-shift buffer window.
- The MPD advertises a Unix-epoch availability start, two-second segments, and
  `urn:scte:scte35:2013:bin` in-band events.

`capture.json` records each exact request URL path, byte length, and SHA-256 hash.
`SHA256SUMS` provides the same checksums for command-line verification.

| File | Contents |
| --- | --- |
| `Manifest.mpd` | Dynamic MPD from the same SCTE-35 stream and simulated clock |
| `init.mp4` | `ftyp` + `moov`; video track timescale 90000; no `mdat` |
| `880000021.m4s` | `styp`, SCTE-35 v1 `emsg`, `moof`, `mdat` |
| `880000022.m4s` | Next `styp`, `moof`, `mdat` segment |
| `880000023.m4s` | Next `styp`, `moof`, `mdat` segment |

The segment sequence numbers are 880000021–880000023. Presentation starts are
1760000042, 1760000044, and 1760000046 Unix seconds
(2025-10-09 08:54:02–08:54:06 UTC). The first `tfdt` is 158400003780000 ticks,
well above 32 bits. Each segment contains 180000 ticks (two seconds) of video.
The first segment's cue announces the legacy `scte35_1` break at Unix second
1760000050, seven seconds ahead of the splice time.

## Verification and recapture

From the repository root, verify all five captured responses without networking:

```sh
python3 sdk/tests/fixtures/live_video/livesim2/capture.py
```

To download the same fixed-time requests (using Python 3 and curl) and replace
files only if all hashes still match the recorded capture:

```sh
python3 sdk/tests/fixtures/live_video/livesim2/capture.py --recapture
```

A locally hosted simulator can be selected with `--base-url http://localhost:8888`.
Content and simulator changes can produce different bytes; the script refuses to
replace any files when a response differs. Updating the capture requires reviewing
new provenance, metadata, and hashes together.

## Test scope

The tests sign the init with a currently valid ephemeral certificate, read its
session-keys assertion and certificate from native CBOR, sign all three media
segments, and validate with `set_media_time_origin(UNIX_EPOCH)`. They check the live
sequence numbers, 64-bit media timestamps, segment duration, and preservation of
every original box. Negative tests alter/remove the real SCTE-35 cue, alter media
payload bytes, expire the session key during the captured sequence, and supply an
incorrect epoch origin.

This test change is stacked on [#2865](https://github.com/contentauth/c2pa-rs/pull/2865)
for presentation-time support. It does not assert corrected VSI insertion placement;
that belongs to [#2864](https://github.com/contentauth/c2pa-rs/pull/2864).

Because these are archived responses, the test sets the signer's private `created_at`
to the first captured presentation time before signing the init. This makes the
session validity independent of the test runner's current date and exercises
presentation-time validation despite the VSI's current `iat`. It adds no public
API for backdating keys; that API question remains separate.

## Licenses

The source media in `Dash-Industry-Forum/livesim-content` is distributed under
Apache-2.0; its full license is included as `LICENSE-content`. The simulator's
BSD-3-Clause license and DASH Industry Forum copyright notice are included as
`LICENSE-livesim2.md`. The captures
have not been edited or re-encoded.
