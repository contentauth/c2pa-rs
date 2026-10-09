These unmodified fixtures come from c2pa-org/conformance PR #504, commit
9837e21771b546a1d7ce63db5143b92b1b87a90b, under tests/validation/assets/.

Source: https://github.com/c2pa-org/conformance/pull/504

The WAV and WebP fixtures exclude the C2PA chunk payload while retaining its
8-byte header in the data hash. Tests here check asset binding results only;
the conformance cases use a historical validation time and test trust roots.
