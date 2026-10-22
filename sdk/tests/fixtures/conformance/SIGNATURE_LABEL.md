Unmodified fixtures from c2pa-org/conformance PR #504, commit
9837e21771b546a1d7ce63db5143b92b1b87a90b, tests/validation/assets/.

https://github.com/c2pa-org/conformance/pull/504

The missing-signature fixture has a valid COSE signature under the wrong box
label; the invalid-URI fixture references a nonexistent signature label.
The intact ES256 fixture is a positive control. Tests check signature
resolution only, independently of historical validation time and trust roots.
