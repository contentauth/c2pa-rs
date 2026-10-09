# Handling validation results in downstream systems

Applications that store C2PA validation results alongside their own records should preserve the distinction between C2PA validation state and application-level decisions.

## ValidationState is a C2PA validation result

The SDK exposes three validation states:

- `Valid` — the manifest is well-formed and cryptographic integrity checks succeed.
- `Trusted` — the manifest is valid and its signing certificate chains to a trusted root or known authority in the configured trust list.
- `Invalid` — the manifest does not satisfy the conditions required for a valid manifest.

`Trusted` is therefore a stronger C2PA validation result than `Valid`; a valid manifest does not necessarily have a trusted signer.

## Do not use Invalid as a synonym for tampering

`ValidationState::Invalid` can also be returned when validation has not been performed or has been disabled. A downstream system should therefore inspect the validation configuration and detailed status codes before presenting `Invalid` as evidence that an asset was modified or that a signature failed.

To distinguish among states such as "not checked", "validation unavailable", and "cryptographically invalid", downstream applications should keep an application-level status alongside the C2PA result rather than collapsing all of those conditions into one value.

## Preserve detailed status codes

`ValidationResults` contains structured status codes for success, information, and failure. When storing or displaying validation evidence, retaining these codes and their associated manifest/ingredient context provides more information than storing only the top-level `ValidationState`.

In particular, downstream systems may need to distinguish:

1. Successful cryptographic validation;
2. Trusted versus untrusted signing credentials;
3. Informational conditions where a check was skipped or could not be performed; and
4. Actual validation failures.

The detailed status records should be treated as evidence of what the C2PA validator evaluated, not as an application-level assertion of ownership, authorship, legal title, authenticity, or institutional certification.

## Keep institutional or application decisions separate

A museum, archive, publisher, marketplace, registry, or other application may maintain additional evidence and review decisions outside the C2PA manifest. Such a system can record the C2PA validation result as one evidence source while keeping its own review, publication, authenticity, or certification state separate.

This separation is useful when an asset has a valid C2PA history but the application also needs to evaluate documentary evidence, historical records, or other information that is outside the manifest.

## Example application model

A downstream record can therefore use a structure conceptually similar to:

```text
c2pa.validationState = Trusted
c2pa.validationStatuses = [...] 
c2pa.validatedAt = <time recorded by the application>
application.reviewState = Reviewed
application.certificationState = NotCertified
```

The application should not derive `application.certificationState` automatically from `Trusted` or `Valid`.

This approach lets C2PA remain the source of cryptographically verifiable digital-provenance results while allowing downstream systems to apply their own domain-specific evidence and governance without changing the meaning of the C2PA result.
