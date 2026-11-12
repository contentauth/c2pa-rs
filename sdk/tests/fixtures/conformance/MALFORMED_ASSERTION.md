`malformed_assertion.jpg` is copied unmodified from c2pa-org/conformance PR #504,
commit 9837e21771b546a1d7ce63db5143b92b1b87a90b, tests/validation/assets/.

https://github.com/c2pa-org/conformance/pull/504

Its `c2pa.actions.v2` assertion is not well-formed CBOR. The test checks
assertion statuses only; the full conformance case uses a historical validation
time and test trust roots.
