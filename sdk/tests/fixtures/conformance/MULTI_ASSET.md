# Multipart JPEG fixtures

Unmodified assets from [c2pa-org/conformance PR #504](https://github.com/c2pa-org/conformance/pull/504), commit `9837e21771b546a1d7ce63db5143b92b1b87a90b`, under `tests/validation/assets/`.

The nine `multipart_*.jpg` fixtures cover intact optional/required parts, removal of one/two optional parts, a missing required part, a tampered optional part, a truncated optional part, a gap between parts, and appended extra data. Tests isolate asset binding results from unrelated signing-credential expiry or trust failures in these historical fixtures.
