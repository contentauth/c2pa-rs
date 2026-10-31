# Experimental VSI session key rotation

These APIs and CLI options require `unstable_live_video`. They implement the session
key rotation item in [#2862](https://github.com/contentauth/c2pa-rs/issues/2862) on top
of the experimental live-video branch.

## Scheduled keys with c2patool

`live-video-sign --method vsi` accepts the primary Ed25519 seed through
`--session-key` and additional seeds through `--session-key-schedule keys.json`.
Each seed is a raw 32-byte file. The schedule is a JSON array:

```json
[
  {
    "path": "next-session.key",
    "kid": "session-key-2",
    "minSequenceNumber": 120,
    "validityPeriod": 3600
  }
]
```

Paths are relative to the schedule file. The primary key has kid `session-key-1`;
additional kids must be nonempty and unique. Every scheduled key is included in the
signed init manifest. The signer selects the eligible key with the greatest
`minSequenceNumber`; ties select the last added key. Key validity starts when the
signer creates the key announcement, not at the scheduled sequence boundary.

Pass the same primary key and schedule when using `--previous-segment`. Resume
verifies the previous segment with the matching key, restores the counter, and
checks that every configured key was announced in the signed init segment. It
restores each key's original sequence bound and validity metadata from that init.
The CLI schedule supports keys announced in advance; adding new announcements to
an ongoing stream uses the SDK APIs below.

## Announcing new keys during a session

Call `LiveVideoVsiSigner::add_session_key` with the manifest signer, the new seed,
kid, minimum sequence number, and validity period. The minimum must be at least the
signer's next sequence number. All keys must bind the same manifest signer.

After adding a key, announce it before signing more ordinary media segments:

- Sign and deliver an updated init segment with `sign_init_segment`, or
- Call `sign_media_segment_with_manifest` with a `Context` containing the manifest
  signer. This embeds a new manifest carrying all configured keys and a VSI that
  references that manifest.

The latter method reserves the manifest and VSI boxes before computing hashes,
then replaces the placeholders without changing their lengths. This preserves the
BMFF v3 box offsets for both bindings. It requires a leading `styp` or `ftyp` and
currently rejects indexed segments containing `sidx` or `ssix`.

## Receiving updates

After validating the init manifest and applying the application's trust policy,
call `LiveVideoValidator::validate_session_keys_from_reader`. This reads the native
CBOR assertion; the JSON-facing manifest API drops tags needed by `signerBinding`.

Use `validate_verifiable_segment_info_with_context` to validate media segments with
the same trust settings and I/O resolvers as the init segment. Embedded manifests
are validated before their keys are installed. New keys must have a minimum
sequence number at least equal to the segment announcing them. Identical previously
verified key objects may be announced again with their original bounds.

The validator retains earlier keys and associates each key with its authorizing
manifest ID. A matching kid under a different manifest ID is insufficient.
`session_key_manifest_state` exposes the authorizing manifest's validation state
for stream reporting. As with other live-video APIs, callers must check both the
returned result and failures recorded in `StatusTracker`.

Remote `manifestUri` retrieval is a separate work item and is not implemented here.
