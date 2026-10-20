# livesim2 encrypted (ECCP) DASH/CMAF capture

These are unmodified responses from the DASH-IF reference simulator at
<https://livesim2.dashif.org>, captured on 2026-10-16 with its ECCP option
(test encryption with a ClearKey licence). They are the encrypted counterparts of
the clear capture in [`../livesim2`](../livesim2/README.md): the same asset,
representation, simulated clock and segment numbers, under `eccp_cenc` and
`eccp_cbcs` instead of `scte35_1`. Tests use these checked-in bytes offline; they
do not require livesim2, Go, Docker, or network access.

## Provenance

- Server `/version` response: `{"Version":"v1.14.0, date: 2026-09-30"}`.
- Corresponding upstream release:
  [livesim2 v1.14.0](https://github.com/Dash-Industry-Forum/livesim2/tree/8a8d768017cdad2583dc15d5fd6e5c69d2225241).
  The server reports its version string; it does not attest a deployed Git commit.
- Source asset: DASH-IF
  [livesim-content, testpic_2s](https://github.com/Dash-Industry-Forum/livesim-content/tree/e2db1d1697eca2ef1a6cd0188158655b9f396acf/testpic_2s),
  representation `V300` (640x360 AVC, 30 fps, approximately 300 kbit/s).
- URL prefixes: `/livesim2/eccp_cenc/testpic_2s/` and `/livesim2/eccp_cbcs/testpic_2s/`.
- Query on every request: `nowMS=1760000100000`, the simulator's supported override
  of its UTC clock.
- Two captures made one after the other were byte-identical: livesim2 encrypts
  with a fixed test key, so the responses are deterministic.
- The MPDs signal `urn:mpeg:dash:mp4protection:2011` (`cenc` or `cbcs`) with
  `cenc:default_KID` `2880fe36-e44b-f9bf-79d2-752e234818a5`, and a ClearKey
  `ContentProtection`. The init segments carry no `pssh`.

`capture.json` records each exact request URL path, byte length, and SHA-256 hash.
`SHA256SUMS` provides the same checksums for command-line verification.

| Files | Contents |
| --- | --- |
| `cenc/`, `cbcs/` `Manifest.mpd` | Dynamic MPD of the encrypted stream at the simulated clock |
| `cenc/`, `cbcs/` `init.mp4` | `ftyp` + `moov` with an `encv` sample entry: `sinf` (`frma`, `schm` `cenc`/`cbcs`, `schi`/`tenc`) |
| `cenc/`, `cbcs/` `880000021.m4s` – `880000023.m4s` | `styp`, `moof` (`traf`: `tfhd` with `default-base-is-moof`, `tfdt`, `trun`, `saiz`, `saio`, `senc`), encrypted `mdat` |

Sequence numbers, presentation times and durations are those of the clear capture:
880000021–880000023, starting at Unix second 1760000042, two seconds each. The
`saio` and `trun` offsets are relative to the `moof` (`tfhd` flag `0x020000`).

## Verification and recapture

From the repository root, verify all ten captured responses without networking:

```sh
python3 sdk/tests/fixtures/live_video/livesim2_eccp/capture.py
```

To download the same fixed-time requests (using Python 3 and curl) and replace
files only if all hashes still match the recorded capture:

```sh
python3 sdk/tests/fixtures/live_video/livesim2_eccp/capture.py --recapture
```

A locally hosted simulator can be selected with `--base-url http://localhost:8888`.
The script refuses to replace any files when a response differs.

## Test scope

The tests sign each encrypted init and its three media segments with a VSI session
key, then validate them with `set_media_time_origin(UNIX_EPOCH)`. They check that
every original box is kept, that the `saio` offsets still point at the `senc`
initialization vectors and the `trun` data offsets at the `mdat` payload after
the VSI `emsg` is inserted, and that changing the `senc` data or the encrypted
media fails the segment hash. The media is not decrypted.

## Licenses

The source media in `Dash-Industry-Forum/livesim-content` is distributed under
Apache-2.0; its full license is included as `LICENSE-content`. The simulator's
BSD-3-Clause license and DASH Industry Forum copyright notice are included as
`LICENSE-livesim2.md`. The captures have not been edited or re-encoded.
