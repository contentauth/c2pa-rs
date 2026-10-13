# Benchmarks

## Fixtures

All benches load their assets from `sdk/benches/fixtures`, which is not checked into the repo since some
of the generated fixtures are large.

Fixtures are generated with [c2pagen](https://github.com/contentauth/c2pagen). To generate all of them:

```bash
$ c2pagen generate --output sdk/benches/fixtures
```

This can take 1hr+ to complete due to the complexity of the file formats and the sheer size of some of
the assets.

To see a list of all possible assets to generate:

```bash
$ c2pagen list
```

If you only want to benchmark a specific asset, generate it explicitly instead, for example:

```bash
$ c2pagen generate small-jpeg --output sdk/benches/fixtures
```

This generates both the signed and unsigned asset used by the `sign` and `read` benches, so you can then
run just that asset's benchmarks, e.g.:

```bash
$ cargo bench --bench sign -- "sign jpeg/small"
$ cargo bench --bench read -- "read jpeg/small"
```
