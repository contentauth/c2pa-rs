use std::{
    io::{SeekFrom, Write},
    sync::Arc,
};

use ::asset_io::{
    container_api::{
        BoxFuture, ContainerHandler, FormatSpec, Io, MetadataUpdate, PlanBuilder, StructureBuilder,
        WritePlan,
    },
    containers::bmff::BmffUpdates,
    labels::MERKLE,
    ItemKind, NullSink, SegmentId, Sink, Structure, Updates,
};
use async_generic::async_generic;

use crate::{
    assertions::asset_binding::{
        asset_io_error, binding_from_claim, default_binding, AssetBinding, BindingHasher,
        BuiltAssertion, PlannedAsset, ProgressSink,
    },
    asset_handlers::asset_io_adapter::MANIFEST_PLACEHOLDER,
    asset_io::{ReadSeek, ReadWriteSeek},
    claim::{ClaimAssetData, RemoteManifest},
    context::{Context, ProgressPhase},
    dynamic_assertion::{AsyncDynamicAssertion, DynamicAssertion, PartialClaim},
    error::{Error, Result},
    store::Store,
    utils::xmp_inmemory_utils::{add_provenance, extract_provenance, remove_provenance, MIN_XMP},
    AsyncSigner, Signer,
};

/// Unregistered fallback for assets that can only be copied to a sidecar output.
#[derive(Debug)]
struct OpaqueHandler;

impl ContainerHandler for OpaqueHandler {
    fn id(&self) -> &'static str {
        "opaque"
    }

    fn formats(&self) -> &[FormatSpec] {
        &[]
    }

    fn parse_async(self: Arc<Self>, io: Io) -> BoxFuture<'static, ::asset_io::Result<Structure>> {
        Box::pin(async move {
            let mut builder = StructureBuilder::new(self, "application/octet-stream", io.len());
            builder.push_tail()?;
            builder.finish()
        })
    }

    fn write_plan_async<'f, 'a: 'f>(
        &'f self,
        source: &'f Structure,
        _io: Io,
        updates: &'a Updates,
    ) -> BoxFuture<'f, ::asset_io::Result<WritePlan<'a>>> {
        Box::pin(async move {
            for (update, kind) in [
                (updates.xmp(), ItemKind::Xmp),
                (updates.c2pa(), ItemKind::C2pa),
            ] {
                if matches!(update, MetadataUpdate::Set(_)) {
                    return Err(::asset_io::Error::UnsupportedItem(kind));
                }
            }
            let mut builder = PlanBuilder::new(source);
            for index in 0..source.segments().len() {
                builder.copy_segment(SegmentId::from_index(index)?)?;
            }
            builder.finish()
        })
    }
}

/// Parse `input` with `handler`.
fn open_structure(
    handler: Arc<dyn ContainerHandler>,
    input: &mut dyn ReadSeek,
) -> Result<Structure> {
    input.rewind()?;
    handler.parse(&mut &mut *input).map_err(asset_io_error)
}

/// The plan for writing `structure` with `updates`. A value the container cannot
/// hold is refused here, before anything is written.
fn plan_write<'a>(
    structure: &Structure,
    input: &mut dyn ReadSeek,
    updates: &'a Updates,
) -> Result<WritePlan<'a>> {
    structure
        .write_plan(&mut &mut *input, updates)
        .map_err(|error| match error {
            ::asset_io::Error::UnsupportedItem(ItemKind::Xmp) => Error::XmpNotSupported,
            ::asset_io::Error::UnsupportedItem(ItemKind::C2pa) => Error::UnsupportedType,
            other => asset_io_error(other),
        })
}

/// Fill the placeholder Merkle proof boxes of `written`, already in `output`, with
/// `proofs`, which are the size the boxes were planned with.
fn patch_merkle(
    written: &Structure,
    output: &mut dyn ReadWriteSeek,
    proofs: &[Vec<u8>],
) -> Result<()> {
    let items: Vec<_> = written.items_labelled(ItemKind::Other, MERKLE).collect();
    if items.len() != proofs.len() {
        return Err(Error::JumbfCreationError);
    }
    output.rewind()?;
    let mut output = output;
    for (item, proof) in items.into_iter().zip(proofs) {
        written
            .patch_exact(&mut output, item, proof)
            .map_err(asset_io_error)?;
    }
    output.flush()?;
    output.rewind()?;
    Ok(())
}

/// The Merkle proof payloads already in the asset, if any.
fn existing_merkle_proofs(
    structure: &Structure,
    input: &mut dyn ReadSeek,
) -> Result<Option<Vec<Vec<u8>>>> {
    let proofs = structure
        .items_labelled(ItemKind::Other, MERKLE)
        .map(|item| {
            structure
                .read_item(&mut &mut *input, item)
                .map_err(asset_io_error)
        })
        .collect::<Result<Vec<_>>>()?;
    Ok((!proofs.is_empty()).then_some(proofs))
}

/// The XMP to write so the asset's provenance points at `remote_url`, or no
/// longer points anywhere. `None` when the XMP needs no change.
fn provenance_xmp(
    structure: &Structure,
    input: &mut dyn ReadSeek,
    remote_url: Option<&str>,
) -> Result<Option<Vec<u8>>> {
    let xmp = structure.xmp(&mut &mut *input).map_err(asset_io_error)?;
    let has_provenance = xmp.as_deref().is_some_and(|xmp| {
        std::str::from_utf8(xmp)
            .ok()
            .and_then(extract_provenance)
            .is_some()
    });
    if remote_url.is_none() && !has_provenance {
        return Ok(None);
    }
    let packet = match xmp.as_deref() {
        Some(bytes) => {
            std::str::from_utf8(bytes).map_err(|e| Error::XmpWriteError(e.to_string()))?
        }
        None => MIN_XMP,
    };
    let packet = match remote_url {
        Some(url) => add_provenance(packet, url)?,
        None => remove_provenance(packet)?,
    };
    Ok(Some(packet.into_bytes()))
}

/// Stream `plan` from `input` into `output` and `sink`, reporting progress in
/// `phase`, and give `sink` back.
fn run_plan<S: Sink>(
    plan: &WritePlan<'_>,
    input: &mut dyn ReadSeek,
    output: &mut dyn Write,
    sink: S,
    phase: ProgressPhase,
    context: &Context,
) -> Result<S> {
    let mut sink = ProgressSink::new(sink, context, phase, plan.structure().total_size());
    input.rewind()?;
    plan.execute(input, output, &mut sink)
        .map_err(asset_io_error)?;
    Ok(sink.into_inner())
}

/// Write `plan` into `output`, reporting progress in `phase`.
fn write_plan<S: Sink>(
    plan: &WritePlan<'_>,
    input: &mut dyn ReadSeek,
    output: &mut dyn ReadWriteSeek,
    sink: S,
    phase: ProgressPhase,
    context: &Context,
) -> Result<S> {
    output.rewind()?;
    let sink = run_plan(plan, input, output, sink, phase, context)?;
    output.flush()?;
    Ok(sink)
}

/// Fill the placeholder store of `written`, already in `output`, with the whole
/// `store`. A container that holds the store in parts (a PDF's revisions) patches
/// only its active part.
fn patch_store(written: &Structure, output: &mut dyn ReadWriteSeek, store: &[u8]) -> Result<()> {
    output.rewind()?;
    let mut output = output;
    written
        .patch_c2pa_store(&mut output, store)
        .map_err(asset_io_error)?;
    output.flush()?;
    output.rewind()?;
    Ok(())
}

impl Store {
    /// [`sign_with_asset_io`](Self::sign_with_asset_io) with the context's signer.
    #[async_generic]
    pub(crate) fn save_to_stream_asset_io(
        &mut self,
        format: &str,
        input: &mut dyn ReadSeek,
        output: &mut dyn ReadWriteSeek,
        context: &Context,
    ) -> Result<Vec<u8>> {
        if _sync {
            self.sign_with_asset_io(format, input, output, context.signer()?, context)
        } else {
            self.sign_with_asset_io_async(format, input, output, context.async_signer()?, context)
                .await
        }
    }

    /// Writes and hashes the asset into an empty output in one pass, then signs
    /// with `signer`. Only embedded stores are patched; detached manifest bytes
    /// are returned for the caller to persist or upload. Optional post-sign
    /// verification may reread the output.
    ///
    /// The context's handler registry decides how `format` is saved. An asset-io
    /// container (built in, or added with `Context::with_io_handler`) is saved
    /// directly. While legacy handlers remain, a format served by one is saved
    /// through it with [`save_to_stream`](Self::save_to_stream). A format with no
    /// handler is copied unchanged and its manifest returned for a sidecar.
    #[async_generic(async_signature(
        &mut self,
        format: &str,
        input: &mut dyn ReadSeek,
        output: &mut dyn ReadWriteSeek,
        signer: &dyn AsyncSigner,
        context: &Context,
    ))]
    pub(crate) fn sign_with_asset_io(
        &mut self,
        format: &str,
        input: &mut dyn ReadSeek,
        output: &mut dyn ReadWriteSeek,
        signer: &dyn Signer,
        context: &Context,
    ) -> Result<Vec<u8>> {
        let io = context.io();
        let handler = io.container_handler(format);
        if handler.is_none() && io.handler(format).is_some() {
            return if _sync {
                self.save_to_stream(format, input, output, signer, context)
            } else {
                self.save_to_stream_async(format, input, output, signer, context)
                    .await
            };
        }

        // Reserve the signer's dynamic assertions before anything is sized; they
        // are written just before signing.
        let dynamic_assertions = signer.dynamic_assertions();
        if _sync {
            self.add_dynamic_assertion_placeholders(&dynamic_assertions)?;
        } else {
            self.add_dynamic_assertion_placeholders_async(&dynamic_assertions)
                .await?;
        }

        let claim = self.provenance_claim().ok_or(Error::ClaimEncoding)?;
        let (embed, remote_url) = match claim.remote_manifest() {
            RemoteManifest::NoRemote => (true, None),
            RemoteManifest::SideCar => (false, None),
            RemoteManifest::Remote(url) => (false, Some(url)),
            RemoteManifest::EmbedWithRemote(url) => (true, Some(url)),
        };
        let alg = claim.alg().to_owned();
        let update = claim.update_manifest();
        let claim_binding = binding_from_claim(claim)?;
        if update && claim_binding.is_some() {
            return Err(Error::UpdateManifestInvalid);
        }

        // An asset with no container handler is copied unchanged.
        let handler = handler.unwrap_or_else(|| Arc::new(OpaqueHandler));
        let structure = open_structure(handler, input)?;
        let manifest_only = structure.container_id() == ::asset_io::containers::c2pa::ID;
        let xmp = provenance_xmp(&structure, input, remote_url.as_deref())?;
        // Any existing store is removed, and replaced by `store` if given.
        let updates_with = |store: Option<Vec<u8>>| {
            let mut updates = Updates::new().remove_c2pa();
            if let Some(xmp) = &xmp {
                updates = updates.set_xmp(xmp.clone());
            }
            if let Some(store) = store {
                updates = updates.set_c2pa(store);
            }
            updates
        };

        // An update manifest has no hard binding, so it is signed first and written
        // once. A container that keeps the original store apart (ISO BMFF) leaves
        // it in place and adds only the update.
        if update {
            let signed = if _sync {
                self.sign_for_save(signer, &dynamic_assertions, context, None)?
            } else {
                self.sign_for_save_async(signer, &dynamic_assertions, context, None)
                    .await?
            };
            let mut updates = updates_with(embed.then(|| signed.clone()));
            if embed {
                updates = updates.as_update();
            }
            let plan = plan_write(&structure, input, &updates)?;
            write_plan(
                &plan,
                input,
                output,
                NullSink,
                ProgressPhase::Writing,
                context,
            )?;
            if embed {
                context.check_progress(ProgressPhase::Embedding, 1, 1)?;
            }
            self.embedded = embed;
            if _sync {
                self.verify_after_save(output, format, context)?;
            } else {
                self.verify_after_save_async(output, format, context)
                    .await?;
            }
            return Ok(signed);
        }

        let existing = claim_binding.is_some();
        let mut binding = match claim_binding {
            Some(binding) => binding,
            None => {
                let claim = self.provenance_claim().ok_or(Error::ClaimEncoding)?;
                default_binding(&structure, context, claim, &alg)?
            }
        };
        binding.check_structure(&structure)?;

        // Merkle proof boxes belong with the manifest that describes them. A Merkle
        // binding replaces the asset's own with its proofs, planned at their final
        // size and patched in once the leaves are hashed; any other keeps them.
        let mut merkle = match binding.merkle_proofs() {
            Some(proofs) => Some(proofs.to_vec()),
            None => existing_merkle_proofs(&structure, input)?,
        };
        let base_updates = updates_with;
        let updates_with = |store: Option<Vec<u8>>, merkle: &Option<Vec<Vec<u8>>>| match merkle {
            Some(proofs) if proofs.is_empty() => base_updates(store).remove_merkle(),
            Some(proofs) => base_updates(store).set_merkle(proofs.clone()),
            None => base_updates(store),
        };

        // A compressed store's size is only known once it is signed, so an
        // embedded one can only be bound by a binding that does not depend on the
        // store's size; anything else is saved uncompressed. Such a store is hashed
        // in a pass that writes nothing and written once signed. A detached store
        // is not in the asset, so it can always be compressed.
        let claim = self.provenance_claim_mut().ok_or(Error::ClaimEncoding)?;
        if claim.compressed() && embed && binding.depends_on_store_size() {
            claim.set_compressed_manifest(false);
        }
        // Manifest-only output may discard writes, so write the signed store once
        // instead of patching a placeholder in the destination.
        let write_after_signing = embed && (claim.compressed() || manifest_only);
        let reserve_size = signer.reserve_size();

        // Fix the binding's and an embedded store's sizes from the binding's ranges
        // with the smallest store. Like the legacy save, the binding carries
        // padding for its final ranges' CBOR to grow into.
        //
        // The first plan's store is built from the claim, not a generic placeholder,
        // because a PDF only takes a store that extends the manifests already in it.
        let mut store = embed.then(|| MANIFEST_PLACEHOLDER.to_vec());
        let mut sizes = None;
        if embed && !write_after_signing {
            self.put_binding(binding.as_ref(), existing)?;
            let updates = updates_with(Some(self.to_jumbf_internal(reserve_size)?), &merkle);
            {
                let plan = plan_write(&structure, input, &updates)?;
                binding.plan_hashes(&mut PlannedAsset::new(&plan, &mut *input)?, &alg)?;
            }
            self.put_binding(binding.as_ref(), true)?;
            let binding_len = binding.assertion()?.data().len();
            let sized = self.to_jumbf_internal(reserve_size)?;
            sizes = Some((binding_len, sized.len()));
            store = Some(sized);
        }

        // Hash the output, writing it unless it waits for the signed store.
        let updates = updates_with(store, &merkle);
        let plan = plan_write(&structure, input, &updates)?;
        let (spans, leaves) = {
            let mut planned = PlannedAsset::new(&plan, &mut *input)?;
            let spans = binding.plan_hashes(&mut planned, &alg)?;
            (spans, binding.plan_leaves(&planned)?)
        };
        let merkle_planned = leaves.is_some();
        match sizes {
            Some((binding_len, _)) => binding.fit_to_size(binding_len)?,
            None => self.put_binding(binding.as_ref(), existing)?,
        }
        let hasher = BindingHasher::new(spans, leaves)?;
        let hasher = if write_after_signing {
            let sink = &mut std::io::sink();
            run_plan(&plan, input, sink, hasher, ProgressPhase::Hashing, context)?
        } else {
            write_plan(
                &plan,
                input,
                output,
                hasher,
                ProgressPhase::Hashing,
                context,
            )?
        };
        let (digests, leaf_digests) = hasher.finish();
        binding.set_hashes(digests);
        if let Some(leaf_digests) = leaf_digests {
            binding.set_leaves(leaf_digests)?;
            merkle = binding.merkle_proofs().map(<[_]>::to_vec);
        }
        self.put_binding(binding.as_ref(), true)?;

        let store_len = sizes.map(|(_, store_len)| store_len);
        if let Some(store_len) = store_len {
            if self.to_jumbf_internal(reserve_size)?.len() != store_len {
                return Err(Error::JumbfCreationError);
            }
        }
        let signed = if _sync {
            self.sign_for_save(signer, &dynamic_assertions, context, store_len)?
        } else {
            self.sign_for_save_async(signer, &dynamic_assertions, context, store_len)
                .await?
        };
        if write_after_signing {
            let updates = updates_with(Some(signed.clone()), &merkle);
            let plan = plan_write(&structure, input, &updates)?;
            write_plan(
                &plan,
                input,
                output,
                NullSink,
                ProgressPhase::Writing,
                context,
            )?;
        } else {
            if embed {
                patch_store(plan.structure(), output, &signed)?;
            }
            if let (true, Some(proofs)) = (merkle_planned, &merkle) {
                patch_merkle(plan.structure(), output, proofs)?;
            }
        }
        if embed {
            context.check_progress(ProgressPhase::Embedding, 1, 1)?;
        }
        self.embedded = embed;
        if _sync {
            self.verify_after_save(output, format, context)?;
        } else {
            self.verify_after_save_async(output, format, context)
                .await?;
        }
        Ok(signed)
    }

    /// Write the signer's dynamic assertions into the slots reserved for them,
    /// sign the provenance claim and return the store. With `target_len`, the
    /// store is padded to that length and may not exceed it.
    #[async_generic(async_signature(
        &mut self,
        signer: &dyn AsyncSigner,
        dynamic_assertions: &[Box<dyn AsyncDynamicAssertion>],
        context: &Context,
        target_len: Option<usize>,
    ))]
    fn sign_for_save(
        &mut self,
        signer: &dyn Signer,
        dynamic_assertions: &[Box<dyn DynamicAssertion>],
        context: &Context,
        target_len: Option<usize>,
    ) -> Result<Vec<u8>> {
        context.check_progress(ProgressPhase::Signing, 1, 1)?;
        if !dynamic_assertions.is_empty() {
            let claim = self.provenance_claim().ok_or(Error::ClaimEncoding)?;
            let mut preliminary_claim = PartialClaim::default();
            for assertion in claim.assertions() {
                preliminary_claim.add_assertion(assertion);
            }
            if _sync {
                self.write_dynamic_assertions(dynamic_assertions, &mut preliminary_claim)?;
            } else {
                self.write_dynamic_assertions_async(dynamic_assertions, &mut preliminary_claim)
                    .await?;
            }
        }
        let claim = self.provenance_claim().ok_or(Error::ClaimEncoding)?;
        let reserve_size = signer.reserve_size();
        let signature = if _sync {
            self.sign_claim(claim, signer, reserve_size, context)?
        } else {
            self.sign_claim_async(claim, signer, reserve_size, context)
                .await?
        };
        self.provenance_claim_mut()
            .ok_or(Error::ClaimEncoding)?
            .set_signature_val(signature);
        let mut store = self.to_jumbf_internal(reserve_size)?;
        if let Some(len) = target_len {
            if store.len() > len {
                return Err(Error::BadParam(format!(
                    "signed manifest ({} bytes) exceeds its reserved size ({len} bytes)",
                    store.len()
                )));
            }
            store.resize(len, 0);
        }
        Ok(store)
    }

    /// Put `binding` in the provenance claim, replacing the one there if
    /// `existing`.
    fn put_binding(&mut self, binding: &dyn AssetBinding, existing: bool) -> Result<()> {
        let assertion = binding.assertion()?;
        let claim = self.provenance_claim_mut().ok_or(Error::ClaimEncoding)?;
        if existing {
            claim.replace_assertion(assertion)
        } else {
            claim
                .add_assertion(&BuiltAssertion::new(assertion))
                .map(|_| ())
        }
    }

    /// Verify the saved store against `output` if the settings ask for it.
    #[async_generic]
    fn verify_after_save(
        &mut self,
        output: &mut dyn ReadWriteSeek,
        format: &str,
        context: &Context,
    ) -> Result<()> {
        let verify = &context.settings().verify;
        if verify.verify_after_sign {
            // An output that keeps nothing (a detached save into `io::empty()`)
            // has no asset to check the hashes against, as in `save_to_stream`.
            let has_output = output.seek(SeekFrom::End(0))? > 0;
            output.rewind()?;
            let mut asset = (verify.verify_after_sign_hash && has_output)
                .then_some(ClaimAssetData::Stream(output, format));
            if _sync {
                self.verify_store_strict(asset.as_mut(), context)?;
            } else {
                self.verify_store_strict_async(asset.as_mut(), context)
                    .await?;
            }
            output.rewind()?;
        } else {
            output.rewind()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};

    use super::open_structure;
    use crate::{
        assertion::AssertionBase,
        assertions::{Action, Actions, BmffHash, BoxHash, DataHash, Ingredient},
        claim::Claim,
        error::Error,
        hashed_uri::HashedUri,
        status_tracker::{ErrorBehavior, StatusTracker},
        store::Store,
        utils::{test::test_context, test_signer::test_signer},
        ClaimGeneratorInfo, Context, DigitalSourceType, ProgressPhase, Reader, SigningAlg,
        ValidationState,
    };

    const FIXTURES: [(&str, &[u8]); 4] = [
        (
            "image/jpeg",
            include_bytes!("../../tests/fixtures/earth_apollo17.jpg"),
        ),
        (
            "image/png",
            include_bytes!("../../tests/fixtures/libpng-test.png"),
        ),
        (
            "image/svg+xml",
            include_bytes!("../../tests/fixtures/sample1.svg"),
        ),
        (
            "image/tiff",
            include_bytes!("../../tests/fixtures/TUSCANY.TIF"),
        ),
    ];

    #[derive(Default)]
    struct TrackedOutput {
        stream: Cursor<Vec<u8>>,
        reads: Vec<(u64, usize)>,
        writes: Vec<(u64, usize)>,
        fail_writes: bool,
    }

    impl Read for TrackedOutput {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let offset = self.stream.position();
            let len = self.stream.read(buf)?;
            self.reads.push((offset, len));
            Ok(len)
        }
    }

    impl Write for TrackedOutput {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if self.fail_writes {
                return Err(io::Error::other("test write failure"));
            }
            let offset = self.stream.position();
            let len = self.stream.write(buf)?;
            self.writes.push((offset, len));
            Ok(len)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.stream.flush()
        }
    }

    impl Seek for TrackedOutput {
        fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
            self.stream.seek(position)
        }
    }

    fn unsigned_store(context: &Context) -> Store {
        let mut store = Store::from_context(context);
        let mut claim = Claim::new("direct asset-io", Some("direct_asset_io"), 1);
        let actions = Actions::new()
            .add_action(Action::new("c2pa.created").set_source_type(DigitalSourceType::Empty));
        claim.add_assertion(&actions).unwrap();
        claim.add_claim_generator_info(ClaimGeneratorInfo::new("asset_io_save_test"));
        store.commit_claim(claim).unwrap();
        store
    }

    fn bmff_fixture() -> Vec<u8> {
        bmff_fixture_with_mdats(&[256])
    }

    /// A file with one `mdat` box per size in `sizes`; its sample table points at
    /// the first.
    fn bmff_fixture_with_mdats(sizes: &[usize]) -> Vec<u8> {
        fn atom(name: &[u8; 4], bytes: &[u8]) -> Vec<u8> {
            let mut out = ((bytes.len() + 8) as u32).to_be_bytes().to_vec();
            out.extend_from_slice(name);
            out.extend_from_slice(bytes);
            out
        }
        let mut bytes = atom(b"ftyp", b"isom\0\0\0\0isom");
        bytes.extend(atom(b"free", b"padding"));
        let stco = atom(b"stco", &[0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0]);
        let moov = atom(
            b"moov",
            &atom(
                b"trak",
                &atom(b"mdia", &atom(b"minf", &atom(b"stbl", &stco))),
            ),
        );
        let mdat_offset = (bytes.len() + moov.len() + 8) as u32;
        let mut moov = moov;
        let last = moov.len();
        moov[last - 4..].copy_from_slice(&mdat_offset.to_be_bytes());
        bytes.extend(moov);
        for (index, &size) in sizes.iter().enumerate() {
            let media: Vec<u8> = (0..size).map(|n| (n * 7 + index) as u8).collect();
            bytes.extend(atom(b"mdat", &media));
        }
        bytes
    }

    fn assert_valid_manifest(format: &str, manifest: &[u8], output: &mut Cursor<Vec<u8>>) {
        output.rewind().unwrap();
        let reader = Reader::from_context(test_context())
            .with_manifest_data_and_stream(manifest, format, output)
            .map_err(|error| format!("{format}: {error}"))
            .unwrap();
        assert_ne!(
            reader.validation_state(),
            ValidationState::Invalid,
            "{format}: {:?}",
            reader.validation_status()
        );
    }

    fn assert_forward_write(
        output: &TrackedOutput,
        structure: &::asset_io::Structure,
        embed: bool,
    ) {
        let segments: Vec<_> = structure
            .items_of(::asset_io::ItemKind::C2pa)
            .flat_map(|item| {
                item.extents()
                    .map(|ex| structure.segment(ex.segment()).unwrap().range())
            })
            .collect();
        let in_manifest = |offset, len| {
            segments
                .iter()
                .any(|range| offset >= range.offset() && offset + len as u64 <= range.end())
        };
        for &(offset, len) in &output.reads {
            assert!(
                embed && in_manifest(offset, len),
                "output reread at {offset}"
            );
        }
        let mut end = 0;
        let mut patching = false;
        for &(offset, len) in &output.writes {
            if !patching && offset == end {
                end += len as u64;
            } else {
                patching = true;
                assert!(
                    embed && in_manifest(offset, len),
                    "non-manifest rewrite at {offset}"
                );
            }
        }
        assert_eq!(end, structure.total_size());
        assert_eq!(patching, embed);
    }

    #[test]
    fn direct_asset_io_manifest_only_accepts_empty_streams() {
        let context = test_context()
            .with_settings(
                r#"{"builder":{"prefer_box_hash":false},"verify":{"verify_after_sign":true,"verify_after_sign_hash":true}}"#,
            )
            .unwrap()
            .with_signer(test_signer(SigningAlg::Ed25519));
        for compressed in [false, true] {
            let mut store = unsigned_store(&context);
            store
                .provenance_claim_mut()
                .unwrap()
                .set_compressed_manifest(compressed);
            let manifest = store
                .save_to_stream_asset_io(
                    "application/c2pa",
                    &mut io::empty(),
                    &mut io::empty(),
                    &context,
                )
                .expect("manifest-only signing with empty streams");
            assert!(!manifest.is_empty());
            let claim = store.provenance_claim().unwrap();
            assert_eq!(claim.compressed(), compressed);
            let assertions = claim.box_hash_assertions();
            assert_eq!(assertions.len(), 1);
            let binding = BoxHash::from_assertion(assertions[0].assertion()).unwrap();
            assert_eq!(binding.boxes.len(), 1);
            assert_eq!(binding.boxes[0].names, ["C2PA"]);
            assert!(binding.boxes[0].hash.is_empty());

            let mut store = unsigned_store(&context);
            store
                .provenance_claim_mut()
                .unwrap()
                .set_compressed_manifest(compressed);
            let mut output = Cursor::new(Vec::new());
            let manifest = store
                .save_to_stream_asset_io(
                    "application/c2pa",
                    &mut io::empty(),
                    &mut output,
                    &context,
                )
                .expect("manifest-only signing to a retained destination");
            assert_eq!(output.get_ref(), &manifest);
            assert_valid_manifest("application/c2pa", &manifest, &mut output);
        }
    }

    #[test]
    fn direct_asset_io_requested_data_hash_and_bmff_are_single_pass() {
        let bmff = bmff_fixture();
        for (format, source) in FIXTURES.into_iter().chain([("video/mp4", bmff.as_slice())]) {
            let context = test_context()
                .with_settings(r#"{"verify":{"verify_after_sign":false}}"#)
                .unwrap()
                .with_signer(test_signer(SigningAlg::Ed25519));
            let mut store = unsigned_store(&context);
            if format != "video/mp4" {
                store
                    .provenance_claim_mut()
                    .unwrap()
                    .add_assertion(&DataHash::new("requested", "sha384"))
                    .unwrap();
            }
            let mut output = TrackedOutput::default();
            let manifest = store
                .save_to_stream_asset_io(format, &mut Cursor::new(source), &mut output, &context)
                .map_err(|error| format!("{format}: {error}"))
                .unwrap();
            let handler = ::asset_io::HandlerRegistry::builtin()
                .handler(format)
                .unwrap()
                .clone();
            output.stream.rewind().unwrap();
            let structure = handler.parse(&mut output.stream).unwrap();
            assert_forward_write(&output, &structure, true);
            assert_valid_manifest(format, &manifest, &mut output.stream);
        }
    }

    /// A hard binding the caller already computed is signed as given, as
    /// `save_to_stream` signs it, so a wrong one fails verification after signing
    /// instead of being recomputed.
    #[test]
    fn direct_asset_io_signs_supplied_bindings_unchanged() {
        use crate::assertions::BoxMap;

        let bmff = bmff_fixture();
        let (jpeg, jpeg_source) = FIXTURES[0];
        let mut data_hash = DataHash::new("supplied", "sha256");
        data_hash.set_hash(vec![1; 32]);
        let mut bmff_hash = BmffHash::new("supplied", "sha256", None);
        bmff_hash.set_default_exclusions();
        bmff_hash.set_hash(vec![1; 32]);
        let box_hash = BoxHash {
            boxes: vec![BoxMap {
                names: vec!["SOI".to_string()],
                alg: Some("sha256".to_string()),
                hash: vec![1; 32].into(),
                excluded: None,
                exclusions: None,
                pad: Vec::new().into(),
                range_start: 0,
                range_len: 0,
            }],
        };
        type AddBinding = Box<dyn Fn(&mut Claim)>;
        let cases: [(&str, &[u8], AddBinding); 3] = [
            (
                jpeg,
                jpeg_source,
                Box::new(move |claim| {
                    claim.add_assertion(&data_hash).unwrap();
                }),
            ),
            (
                jpeg,
                jpeg_source,
                Box::new(move |claim| {
                    claim.add_assertion(&box_hash).unwrap();
                }),
            ),
            (
                "video/mp4",
                bmff.as_slice(),
                Box::new(move |claim| {
                    claim.add_assertion(&bmff_hash).unwrap();
                }),
            ),
        ];
        for (format, source, add_binding) in cases {
            let context = test_context().with_signer(test_signer(SigningAlg::Ed25519));
            let mut store = unsigned_store(&context);
            add_binding(store.provenance_claim_mut().unwrap());
            let error = store
                .save_to_stream_asset_io(
                    format,
                    &mut Cursor::new(source),
                    &mut Cursor::new(Vec::new()),
                    &context,
                )
                .unwrap_err();
            assert!(
                matches!(error, Error::InvalidManifest(_) | Error::HashMismatch(_)),
                "{format}: {error:?}"
            );
        }
    }

    #[test]
    fn direct_asset_io_replaces_or_removes_existing_manifest_and_remote_url() {
        use crate::utils::xmp_inmemory_utils::{
            extract_instance_id, extract_provenance, set_instance_id, MIN_XMP,
        };
        let bmff = bmff_fixture();
        for (format, source) in FIXTURES.into_iter().chain([("video/mp4", bmff.as_slice())]) {
            let context = test_context()
                .with_settings(r#"{"verify":{"verify_after_sign":false}}"#)
                .unwrap()
                .with_signer(test_signer(SigningAlg::Ed25519));
            let handler = ::asset_io::HandlerRegistry::builtin()
                .handler(format)
                .unwrap()
                .clone();
            let mut input = Cursor::new(source);
            let structure = handler.clone().parse(&mut input).unwrap();
            let mut seed = Cursor::new(Vec::new());
            let xmp = set_instance_id(MIN_XMP, "uuid:keep-me").unwrap();
            structure
                .write(
                    &mut input,
                    &mut seed,
                    &::asset_io::Updates::new().set_xmp(xmp.into_bytes()),
                    &mut ::asset_io::NullSink,
                )
                .unwrap();
            let mut first = unsigned_store(&context);
            first
                .provenance_claim_mut()
                .unwrap()
                .set_embed_remote_manifest("https://example.com/old.c2pa")
                .unwrap();
            let mut signed = Cursor::new(Vec::new());
            first
                .save_to_stream_asset_io(format, &mut seed, &mut signed, &context)
                .unwrap();
            for mode in ["embed", "sidecar", "remote", "embed_remote"] {
                let mut next = unsigned_store(&context);
                let claim = next.provenance_claim_mut().unwrap();
                match mode {
                    "sidecar" => claim.set_external_manifest(),
                    "remote" => claim
                        .set_remote_manifest("https://example.com/new.c2pa")
                        .unwrap(),
                    "embed_remote" => claim
                        .set_embed_remote_manifest("https://example.com/new.c2pa")
                        .unwrap(),
                    _ => {}
                }
                let embed = matches!(mode, "embed" | "embed_remote");
                let mut output = TrackedOutput::default();
                let manifest = next
                    .save_to_stream_asset_io(format, &mut signed, &mut output, &context)
                    .map_err(|error| format!("{format}/{mode}: {error}"))
                    .unwrap();
                output.stream.rewind().unwrap();
                let structure = handler.clone().parse(&mut output.stream).unwrap();
                assert_forward_write(&output, &structure, embed);
                assert_eq!(
                    structure
                        .item(::asset_io::ItemKind::C2pa)
                        .unwrap()
                        .is_some(),
                    embed
                );
                let xmp = structure.xmp(&mut output.stream).unwrap().unwrap();
                let xmp = std::str::from_utf8(&xmp).unwrap();
                assert_eq!(extract_instance_id(xmp).as_deref(), Some("uuid:keep-me"));
                assert_eq!(
                    extract_provenance(xmp).as_deref(),
                    mode.contains("remote")
                        .then_some("https://example.com/new.c2pa")
                );
                assert_valid_manifest(format, &manifest, &mut output.stream);
            }
        }
    }

    #[test]
    fn direct_asset_io_bmff_preserves_selectors_and_versions() {
        use crate::assertions::{DataMap, ExclusionsMap, SubsetMap};
        for version in [1, 2, 3] {
            let context = test_context()
                .with_settings(r#"{"verify":{"verify_after_sign":false}}"#)
                .unwrap()
                .with_signer(test_signer(SigningAlg::Ed25519));
            let mut store = unsigned_store(&context);
            let mut hash = BmffHash::new("requested", "sha384", None);
            hash.set_default_exclusions_with_options(context.settings());
            hash.set_bmff_version(version);
            let mut ex = ExclusionsMap::new("/moov/trak/mdia/minf/stbl/stco".into());
            ex.version = Some(0);
            ex.flags = Some(vec![0, 0, 0].into());
            ex.data = Some(vec![DataMap {
                offset: 12,
                value: vec![0, 0, 0, 1],
            }]);
            ex.subset = Some(vec![SubsetMap {
                offset: 16,
                length: 4,
            }]);
            hash.add_exclusions(&mut vec![ex]);
            let expected = hash.to_assertion().unwrap();
            store
                .provenance_claim_mut()
                .unwrap()
                .add_assertion(&hash)
                .unwrap();
            let mut output = Cursor::new(Vec::new());
            let manifest = store
                .save_to_stream_asset_io(
                    "video/mp4",
                    &mut Cursor::new(bmff_fixture()),
                    &mut output,
                    &context,
                )
                .unwrap();
            let claim = store.provenance_claim().unwrap();
            let hash =
                BmffHash::from_assertion(claim.bmff_hash_assertions()[0].assertion()).unwrap();
            assert_eq!(hash.bmff_version(), version);
            assert_eq!(
                serde_json::to_value(hash.exclusions()).unwrap(),
                serde_json::to_value(BmffHash::from_assertion(&expected).unwrap().exclusions())
                    .unwrap()
            );
            assert_valid_manifest("video/mp4", &manifest, &mut output);
        }
    }

    #[test]
    fn direct_asset_io_unhandled_sidecar_and_capability_errors() {
        use crate::assertions::CollectionHash;
        let context = test_context()
            .with_settings(r#"{"verify":{"verify_after_sign":false}}"#)
            .unwrap()
            .with_signer(test_signer(SigningAlg::Ed25519));
        let mut store = unsigned_store(&context);
        store
            .provenance_claim_mut()
            .unwrap()
            .set_external_manifest();
        let source = b"opaque sidecar asset";
        let mut output = TrackedOutput::default();
        let manifest = store
            .save_to_stream_asset_io(
                "application/octet-stream",
                &mut Cursor::new(source),
                &mut output,
                &context,
            )
            .unwrap();
        assert_eq!(output.stream.get_ref(), source);
        assert!(output.reads.is_empty());
        assert_valid_manifest("application/octet-stream", &manifest, &mut output.stream);

        for kind in [
            "unknown_embed",
            "unknown_remote",
            "unknown_boxes",
            "unknown_bmff",
            "multiple",
            "collection",
            "update_with_binding",
            "pdf",
        ] {
            let context = test_context().with_signer(test_signer(SigningAlg::Ed25519));
            let mut store = unsigned_store(&context);
            let claim = store.provenance_claim_mut().unwrap();
            match kind {
                "unknown_remote" => {
                    claim
                        .set_remote_manifest("https://example.com/manifest.c2pa")
                        .unwrap();
                }
                "unknown_boxes" => {
                    claim.set_external_manifest();
                    claim.add_assertion(&BoxHash { boxes: Vec::new() }).unwrap();
                }
                "unknown_bmff" => {
                    claim.set_external_manifest();
                    claim
                        .add_assertion(&BmffHash::new("requested", "sha256", None))
                        .unwrap();
                }
                "multiple" => {
                    claim
                        .add_assertion(&DataHash::new("one", "sha256"))
                        .unwrap();
                    claim.add_assertion(&BoxHash { boxes: Vec::new() }).unwrap();
                }
                "collection" => {
                    claim
                        .add_assertion(&CollectionHash::new("sha256".into()))
                        .unwrap();
                }
                "update_with_binding" => {
                    claim.set_update_manifest(true);
                    claim
                        .add_assertion(&DataHash::new("one", "sha256"))
                        .unwrap();
                }
                _ => {}
            }
            let (format, source): (&str, &[u8]) = match kind {
                "unknown_embed" | "unknown_remote" | "unknown_boxes" | "unknown_bmff" => {
                    ("application/octet-stream", source)
                }
                "pdf" => (
                    "application/pdf",
                    include_bytes!("../../tests/fixtures/basic.pdf"),
                ),
                _ => FIXTURES[0],
            };
            let mut output = TrackedOutput::default();
            let result = store.save_to_stream_asset_io(
                format,
                &mut Cursor::new(source),
                &mut output,
                &context,
            );
            // With the `pdf` feature the PDF is saved; this fixture has nothing that
            // stops a PDF revision from being added.
            if kind == "pdf" && cfg!(feature = "pdf") {
                result.map_err(|error| format!("{kind}: {error}")).unwrap();
                continue;
            }
            assert!(result.is_err(), "{kind}: expected an error");
            let error = result.err().unwrap();
            match kind {
                "unknown_embed" => {
                    assert!(matches!(error, Error::UnsupportedType), "{kind}: {error}")
                }
                // Without the `pdf` feature the context has no PDF handler.
                "pdf" => assert!(matches!(error, Error::UnsupportedType), "{kind}: {error}"),
                "unknown_remote" => assert!(matches!(error, Error::XmpNotSupported), "{error}"),
                "multiple" => assert!(matches!(error, Error::BadParam(_)), "{error}"),
                "update_with_binding" => {
                    assert!(matches!(error, Error::UpdateManifestInvalid), "{error}")
                }
                _ => assert!(matches!(error, Error::NotImplemented(_)), "{kind}: {error}"),
            }
            assert!(output.writes.is_empty(), "{kind} wrote before rejection");
        }
    }

    #[test]
    fn direct_asset_io_opaque_sidecars_hash_the_entire_payload() {
        let payload = vec![42; 128 * 1024 + 1];
        for prefer_box_hash in [false, true] {
            let context = test_context()
                .with_settings(
                    format!(
                        r#"{{"builder":{{"prefer_box_hash":{prefer_box_hash}}},"verify":{{"verify_after_sign":false}}}}"#
                    )
                    .as_str(),
                )
                .unwrap()
                .with_signer(test_signer(SigningAlg::Ed25519));
            for source in [&b"x"[..], payload.as_slice()] {
                for explicit in [false, true] {
                    let mut store = unsigned_store(&context);
                    let claim = store.provenance_claim_mut().unwrap();
                    claim.set_external_manifest();
                    if explicit {
                        let hash = DataHash::placeholder(
                            "sha384",
                            vec![crate::utils::hash_utils::HashRange::new(0, 1)],
                        )
                        .unwrap();
                        claim.add_assertion(&hash).unwrap();
                    }
                    let mut output = TrackedOutput::default();
                    let manifest = store
                        .save_to_stream_asset_io(
                            "application/octet-stream",
                            &mut Cursor::new(source),
                            &mut output,
                            &context,
                        )
                        .unwrap();
                    assert_eq!(output.stream.get_ref(), source);
                    assert!(output.reads.is_empty());
                    let claim = store.provenance_claim().unwrap();
                    let hash =
                        DataHash::from_assertion(claim.data_hash_assertions()[0].assertion())
                            .unwrap();
                    assert!(hash.exclusions.is_none());
                    if explicit {
                        assert_eq!(hash.alg.as_deref(), Some("sha384"));
                    }
                    hash.verify_stream_hash(&mut Cursor::new(source), Some(claim.alg()))
                        .unwrap();
                    assert_valid_manifest(
                        "application/octet-stream",
                        &manifest,
                        &mut output.stream,
                    );
                }
            }
        }
    }

    #[test]
    fn direct_asset_io_does_not_treat_malformed_known_formats_as_opaque() {
        let context = test_context().with_signer(test_signer(SigningAlg::Ed25519));
        let mut store = unsigned_store(&context);
        store
            .provenance_claim_mut()
            .unwrap()
            .set_external_manifest();
        let mut output = TrackedOutput::default();
        assert!(store
            .save_to_stream_asset_io(
                "image/png",
                &mut Cursor::new(b"not a PNG"),
                &mut output,
                &context,
            )
            .is_err());
        assert!(output.writes.is_empty());
    }

    /// Sign `source` with a direct save, then return the store read back from
    /// the output, the output, and the validation log.
    fn save_and_read(
        mut store: Store,
        format: &str,
        source: &[u8],
        context: &Context,
    ) -> (Store, Vec<u8>, StatusTracker) {
        let mut output = Cursor::new(Vec::new());
        store
            .save_to_stream_asset_io(format, &mut Cursor::new(source), &mut output, context)
            .map_err(|error| format!("{format}: {error}"))
            .unwrap();
        let mut report = StatusTracker::with_error_behavior(ErrorBehavior::StopOnFirstError);
        output.rewind().unwrap();
        let read = Store::from_stream(format, &mut output, &mut report, &test_context())
            .map_err(|error| format!("{format}: {error}"))
            .unwrap();
        assert!(!report.has_any_error(), "{format}: {report:?}");
        (read, output.into_inner(), report)
    }

    /// An embedded compressed manifest needs a binding that does not depend on
    /// the store's size (a box hash); with any other binding it is saved
    /// uncompressed.
    #[test]
    fn direct_asset_io_saves_compressed_manifests() {
        let bmff = bmff_fixture();
        let cases: [(&str, &[u8], bool, bool); 6] = [
            (FIXTURES[0].0, FIXTURES[0].1, true, true),
            (FIXTURES[1].0, FIXTURES[1].1, true, true),
            (FIXTURES[0].0, FIXTURES[0].1, false, false),
            (FIXTURES[2].0, FIXTURES[2].1, true, false),
            ("video/mp4", bmff.as_slice(), true, false),
            (
                "image/gif",
                include_bytes!("../../tests/fixtures/sample1.gif"),
                true,
                true,
            ),
        ];
        for (format, source, box_default, compressed) in cases {
            let context = test_context()
                .with_settings(
                    format!(r#"{{"builder":{{"prefer_box_hash":{box_default}}}}}"#).as_str(),
                )
                .unwrap()
                .with_signer(test_signer(SigningAlg::Ed25519));
            let mut store = unsigned_store(&context);
            store
                .provenance_claim_mut()
                .unwrap()
                .set_compressed_manifest(true);
            let (read, _, _) = save_and_read(store, format, source, &context);
            let claim = read.provenance_claim().unwrap();
            assert_eq!(claim.compressed(), compressed, "{format}");
            assert_eq!(
                !claim.box_hash_assertions().is_empty(),
                compressed,
                "{format}: compressed only with a box hash"
            );
        }
    }

    /// A detached store is compressed whatever binds the asset, since its size
    /// does not affect the asset's hashes.
    #[test]
    fn direct_asset_io_compresses_detached_manifests() {
        let bmff = bmff_fixture();
        let cases: [(&str, &[u8]); 2] = [
            (FIXTURES[0].0, FIXTURES[0].1),
            ("video/mp4", bmff.as_slice()),
        ];
        for (format, source) in cases {
            let context = test_context()
                .with_settings(r#"{"builder":{"prefer_box_hash":false}}"#)
                .unwrap()
                .with_signer(test_signer(SigningAlg::Ed25519));
            let mut store = unsigned_store(&context);
            let claim = store.provenance_claim_mut().unwrap();
            claim.set_external_manifest();
            claim.set_compressed_manifest(true);
            let mut output = Cursor::new(Vec::new());
            let manifest = store
                .save_to_stream_asset_io(format, &mut Cursor::new(source), &mut output, &context)
                .expect("detached compressed save");
            assert!(
                manifest.windows(4).any(|w| w == b"brob"),
                "{format}: detached store not compressed"
            );
            assert_valid_manifest(format, &manifest, &mut output);
        }
    }

    #[test]
    fn direct_asset_io_respects_prefer_box_hash() {
        let bmff = bmff_fixture();
        for preference in [None, Some(false), Some(true)] {
            let context = test_context()
                .with_settings(
                    match preference {
                        None => "{}".to_owned(),
                        Some(value) => format!(r#"{{"builder":{{"prefer_box_hash":{value}}}}}"#),
                    }
                    .as_str(),
                )
                .unwrap()
                .with_signer(test_signer(SigningAlg::Ed25519));
            for (format, source) in FIXTURES.into_iter().chain([("video/mp4", bmff.as_slice())]) {
                let (read, _, _) =
                    save_and_read(unsigned_store(&context), format, source, &context);
                let claim = read.provenance_claim().unwrap();
                let box_hash =
                    preference.unwrap_or(false) && matches!(format, "image/jpeg" | "image/png");
                assert_eq!(
                    !claim.box_hash_assertions().is_empty(),
                    box_hash,
                    "{format}"
                );
                assert_eq!(
                    !claim.bmff_hash_assertions().is_empty(),
                    format == "video/mp4",
                    "{format}"
                );
                assert_eq!(
                    !claim.data_hash_assertions().is_empty(),
                    !box_hash && format != "video/mp4",
                    "{format}"
                );
            }
        }
    }

    /// An update manifest is signed without a hard binding and added to the
    /// existing store; ISO BMFF keeps the original store in place.
    #[test]
    fn direct_asset_io_saves_update_manifests() {
        let context = test_context().with_signer(test_signer(SigningAlg::Ed25519));
        let bmff = bmff_fixture();
        for (format, source) in [FIXTURES[0], FIXTURES[1], ("video/mp4", bmff.as_slice())] {
            let (signed_store, signed, _) =
                save_and_read(unsigned_store(&context), format, source, &context);
            let parent = signed_store.provenance_claim().unwrap();

            let mut claim = Claim::new("direct asset-io", Some("update_manifest"), 1);
            let (jumbf, _) =
                Store::load_jumbf_from_stream(format, &mut Cursor::new(&signed), &context).unwrap();
            let mut update =
                Store::load_ingredient_to_claim(&mut claim, &jumbf, None, &context).unwrap();
            let hashes = update.get_manifest_box_hashes(parent);
            let parent_uri = HashedUri::new(
                signed_store.provenance_path().unwrap(),
                Some(parent.alg().to_string()),
                &hashes.manifest_box_hash,
            );
            let ingredient = Ingredient::new_v2("parent", format)
                .set_parent()
                .set_c2pa_manifest_from_hashed_uri(Some(parent_uri));
            claim.add_assertion(&ingredient).unwrap();
            update.commit_update_manifest(claim).unwrap();

            let (read, updated, _) = save_and_read(update, format, &signed, &context);
            let claim = read.provenance_claim().unwrap();
            assert!(claim.update_manifest(), "{format}");
            assert!(claim.hash_assertions().is_empty(), "{format}");

            if format == "video/mp4" {
                // The original store stays where it was, so no offset moved.
                let handler = ::asset_io::containers::bmff::handler();
                let structure = handler.clone().parse(&mut Cursor::new(&updated)).unwrap();
                let labels: Vec<_> = structure
                    .items_of(::asset_io::ItemKind::C2pa)
                    .map(|item| item.label().unwrap_or_default().to_owned())
                    .collect();
                assert_eq!(labels, ["original", "update"], "{format}");
                let media_boxes = |bytes: &[u8]| {
                    let s = handler.clone().parse(&mut Cursor::new(bytes)).unwrap();
                    let mut boxes = Vec::new();
                    s.walk(&mut Cursor::new(bytes), |node| {
                        if node.depth == 1 && node.path != "/uuid" {
                            boxes.push((node.path.to_owned(), node.range));
                        }
                        Ok(())
                    })
                    .unwrap();
                    boxes
                };
                assert_eq!(media_boxes(&updated), media_boxes(&signed), "{format}");
            }
        }
    }

    /// A signer's dynamic assertions are reserved before the manifest is sized,
    /// so the signed manifest fits the space written for it.
    #[test]
    fn direct_asset_io_writes_dynamic_assertions() {
        use crate::dynamic_assertion::{DynamicAssertion, DynamicAssertionContent, PartialClaim};

        #[derive(Debug)]
        struct Tag;

        impl DynamicAssertion for Tag {
            fn label(&self) -> String {
                "com.example.dynamic".to_string()
            }

            fn reserve_size(&self) -> crate::Result<usize> {
                Ok(c2pa_cbor::to_vec(&"dynamic content placeholder")?.len())
            }

            fn content(
                &self,
                _label: &str,
                _size: Option<usize>,
                _claim: &PartialClaim,
            ) -> crate::Result<DynamicAssertionContent> {
                Ok(DynamicAssertionContent::Cbor(
                    c2pa_cbor::to_vec(&"dynamic content").unwrap(),
                ))
            }
        }

        struct DynamicSigner(crate::BoxedSigner);

        impl crate::Signer for DynamicSigner {
            fn sign(&self, data: &[u8]) -> crate::Result<Vec<u8>> {
                self.0.sign(data)
            }

            fn alg(&self) -> SigningAlg {
                self.0.alg()
            }

            fn certs(&self) -> crate::Result<Vec<Vec<u8>>> {
                self.0.certs()
            }

            fn reserve_size(&self) -> usize {
                self.0.reserve_size()
            }

            fn dynamic_assertions(&self) -> Vec<Box<dyn DynamicAssertion>> {
                vec![Box::new(Tag)]
            }
        }

        let bmff = bmff_fixture();
        for (format, source) in FIXTURES.into_iter().chain([("video/mp4", bmff.as_slice())]) {
            for prefer_box_hash in [true, false] {
                let context = test_context()
                    .with_settings(
                        format!(r#"{{"builder":{{"prefer_box_hash":{prefer_box_hash}}}}}"#)
                            .as_str(),
                    )
                    .unwrap()
                    .with_signer(DynamicSigner(test_signer(SigningAlg::Ed25519)));
                let (read, _, _) =
                    save_and_read(unsigned_store(&context), format, source, &context);
                assert!(
                    read.provenance_claim()
                        .unwrap()
                        .assertion_hashed_uri_from_label("com.example.dynamic")
                        .is_some(),
                    "{format}"
                );
            }
        }
    }

    /// The async save signs with the context's async signer and writes its async
    /// dynamic assertions, embedded or detached, with a data hash or a box hash.
    #[c2pa_macros::c2pa_test_async]
    async fn direct_asset_io_signs_with_an_async_signer() {
        use async_trait::async_trait;

        use crate::{
            dynamic_assertion::{AsyncDynamicAssertion, DynamicAssertionContent, PartialClaim},
            utils::test_signer::async_test_signer,
            AsyncSigner, BoxedAsyncSigner,
        };

        struct Tag;

        #[cfg_attr(not(target_arch = "wasm32"), async_trait)]
        #[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
        impl AsyncDynamicAssertion for Tag {
            fn label(&self) -> String {
                "com.example.dynamic".to_string()
            }

            fn reserve_size(&self) -> crate::Result<usize> {
                Ok(c2pa_cbor::to_vec(&"dynamic content placeholder")?.len())
            }

            async fn content(
                &self,
                _label: &str,
                _size: Option<usize>,
                _claim: &PartialClaim,
            ) -> crate::Result<DynamicAssertionContent> {
                Ok(DynamicAssertionContent::Cbor(
                    c2pa_cbor::to_vec(&"dynamic content").unwrap(),
                ))
            }
        }

        struct DynamicSigner(BoxedAsyncSigner);

        #[cfg_attr(not(target_arch = "wasm32"), async_trait)]
        #[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
        impl AsyncSigner for DynamicSigner {
            async fn sign(&self, data: Vec<u8>) -> crate::Result<Vec<u8>> {
                self.0.sign(data).await
            }

            fn alg(&self) -> SigningAlg {
                self.0.alg()
            }

            fn certs(&self) -> crate::Result<Vec<Vec<u8>>> {
                self.0.certs()
            }

            fn reserve_size(&self) -> usize {
                self.0.reserve_size()
            }

            fn dynamic_assertions(&self) -> Vec<Box<dyn AsyncDynamicAssertion>> {
                vec![Box::new(Tag)]
            }
        }

        let (format, source) = FIXTURES[0];
        for prefer_box_hash in [true, false] {
            for embed in [true, false] {
                let context = test_context()
                    .with_settings(
                        format!(r#"{{"builder":{{"prefer_box_hash":{prefer_box_hash}}}}}"#)
                            .as_str(),
                    )
                    .unwrap()
                    .with_async_signer(DynamicSigner(async_test_signer(SigningAlg::Ed25519)));
                let mut store = unsigned_store(&context);
                if !embed {
                    store
                        .provenance_claim_mut()
                        .unwrap()
                        .set_external_manifest();
                }
                let mut output = Cursor::new(Vec::new());
                let manifest = store
                    .save_to_stream_asset_io_async(
                        format,
                        &mut Cursor::new(source),
                        &mut output,
                        &context,
                    )
                    .await
                    .unwrap();
                output.rewind().unwrap();
                let reader = Reader::from_context(test_context())
                    .with_manifest_data_and_stream(&manifest, format, &mut output)
                    .unwrap();
                assert_ne!(
                    reader.validation_state(),
                    ValidationState::Invalid,
                    "box hash {prefer_box_hash}, embed {embed}: {:?}",
                    reader.validation_status()
                );
                let read = Store::from_jumbf_with_context(
                    &manifest,
                    &mut StatusTracker::default(),
                    &test_context(),
                )
                .unwrap();
                assert!(read
                    .provenance_claim()
                    .unwrap()
                    .assertion_hashed_uri_from_label("com.example.dynamic")
                    .is_some());
            }
        }
    }

    #[test]
    fn direct_asset_io_preserves_unrelated_jumbf() {
        let context = test_context().with_signer(test_signer(SigningAlg::Ed25519));
        let mut other = super::MANIFEST_PLACEHOLDER.to_vec();
        other[16..20].copy_from_slice(b"test");
        let handler = ::asset_io::HandlerRegistry::builtin()
            .handler("image/jpeg")
            .unwrap()
            .clone();
        // `Updates` only changes the C2PA store, so insert the other JUMBF as a
        // JPEG XT APP11 segment by hand: marker, length, "JP", box instance,
        // packet sequence, then the box.
        let source = FIXTURES[0].1;
        assert_eq!(&source[..2], b"\xff\xd8");
        let mut app11 = b"\xff\xeb".to_vec();
        app11.extend_from_slice(&u16::try_from(10 + other.len()).unwrap().to_be_bytes());
        app11.extend_from_slice(b"JP\x00\x07\x00\x00\x00\x01");
        app11.extend_from_slice(&other);
        let mut seeded = Cursor::new([&source[..2], &app11, &source[2..]].concat());
        let mut embedded = Cursor::new(Vec::new());
        unsigned_store(&context)
            .save_to_stream_asset_io("image/jpeg", &mut seeded, &mut embedded, &context)
            .unwrap();
        let mut detached = unsigned_store(&context);
        detached
            .provenance_claim_mut()
            .unwrap()
            .set_external_manifest();
        let mut output = Cursor::new(Vec::new());
        let manifest = detached
            .save_to_stream_asset_io("image/jpeg", &mut embedded, &mut output, &context)
            .unwrap();
        output.rewind().unwrap();
        let structure = handler.parse(&mut output).unwrap();
        assert!(structure.c2pa_item().unwrap().is_none());
        let item = structure
            .items_of(::asset_io::ItemKind::Other)
            .find(|item| item.encoding() == ::asset_io::Encoding::Jumbf)
            .expect("the unrelated JUMBF is kept");
        assert_eq!(item.jumbf_type().unwrap()[..4], *b"test");
        assert_eq!(structure.read_item(&mut output, item).unwrap(), other);
        assert_valid_manifest("image/jpeg", &manifest, &mut output);
    }

    #[test]
    fn direct_asset_io_bmff_default_exclusion_setting_is_honored() {
        for exclude in [true, false] {
            let context = test_context()
                .with_settings(format!(
                    r#"{{"builder":{{"bmff_hash_exclude_free_and_skip_boxes":{exclude}}}}}"#
                ))
                .unwrap()
                .with_signer(test_signer(SigningAlg::Ed25519));
            let mut store = unsigned_store(&context);
            let mut output = Cursor::new(Vec::new());
            store
                .save_to_stream_asset_io(
                    "video/mp4",
                    &mut Cursor::new(bmff_fixture()),
                    &mut output,
                    &context,
                )
                .unwrap();
            let hash = BmffHash::from_assertion(
                store.provenance_claim().unwrap().bmff_hash_assertions()[0].assertion(),
            )
            .unwrap();
            assert_eq!(
                hash.exclusions().iter().any(|ex| ex.xpath == "/free"),
                exclude
            );
            let handler = ::asset_io::HandlerRegistry::builtin()
                .handler("video/mp4")
                .unwrap()
                .clone();
            output.rewind().unwrap();
            let structure = handler.parse(&mut output).unwrap();
            let free = structure
                .segments()
                .iter()
                .enumerate()
                .find(|(i, segment)| {
                    let id = ::asset_io::SegmentId::from_index(*i).unwrap();
                    structure.box_name(id, segment).as_deref() == Some("free")
                })
                .unwrap()
                .1;
            output.get_mut()[free.range().offset() as usize + 8] ^= 1;
            output.rewind().unwrap();
            assert_eq!(
                hash.verify_stream_hash(&mut output, Some("sha256")).is_ok(),
                exclude
            );
        }
    }

    /// The deprecated `url` field of a hash assertion is ignored when signing
    /// (C2PA 2.5): the hash is bound as usual and written without it.
    #[test]
    fn direct_asset_io_ignores_the_deprecated_hash_url() {
        use crate::{assertions::UserCbor, utils::cbor_types::UriT};

        // The assertion's CBOR with a `url` entry added, as another generator wrote it.
        fn with_url(assertion: crate::assertion::Assertion) -> Vec<u8> {
            let mut data = assertion.data().to_vec();
            assert!(data[0] >> 5 == 5 && data[0] & 0x1f < 23, "a short map");
            data[0] += 1;
            data.extend(c2pa_cbor::to_vec(&"url").unwrap());
            data.extend(c2pa_cbor::to_vec(&UriT("https://example.com/hash".into())).unwrap());
            data
        }

        let context = test_context().with_signer(test_signer(SigningAlg::Ed25519));
        let bmff = bmff_fixture();

        for (format, source, label) in [
            (FIXTURES[0].0, FIXTURES[0].1, DataHash::LABEL),
            ("video/mp4", bmff.as_slice(), BmffHash::LABEL),
        ] {
            let assertion = if label == DataHash::LABEL {
                DataHash::new("requested", "sha256").to_assertion().unwrap()
            } else {
                let mut hash = BmffHash::new("requested", "sha256", None);
                hash.set_default_exclusions_with_options(context.settings());
                hash.to_assertion().unwrap()
            };
            let mut store = unsigned_store(&context);
            store
                .provenance_claim_mut()
                .unwrap()
                .add_assertion(&UserCbor::new(label, with_url(assertion)))
                .unwrap();
            let claim = store.provenance_claim().unwrap();
            let remote = if label == DataHash::LABEL {
                DataHash::from_assertion(claim.data_hash_assertions()[0].assertion())
                    .unwrap()
                    .is_remote_hash()
            } else {
                BmffHash::from_assertion(claim.bmff_hash_assertions()[0].assertion())
                    .unwrap()
                    .is_remote_hash()
            };
            assert!(remote, "{format}: the test hash has a url");
            let mut output = Cursor::new(Vec::new());
            let manifest = store
                .save_to_stream_asset_io(format, &mut Cursor::new(source), &mut output, &context)
                .map_err(|error| format!("{format}: {error}"))
                .unwrap();

            let claim = store.provenance_claim().unwrap();
            if label == DataHash::LABEL {
                let hash = DataHash::from_assertion(claim.data_hash_assertions()[0].assertion());
                assert!(!hash.unwrap().is_remote_hash(), "{format}");
            } else {
                let hash = BmffHash::from_assertion(claim.bmff_hash_assertions()[0].assertion());
                assert!(!hash.unwrap().is_remote_hash(), "{format}");
            }
            assert_valid_manifest(format, &manifest, &mut output);
        }
    }

    /// A BMFF hash the caller computed is signed as given even when it has Merkle
    /// maps, whose proofs are already in the asset. It is not refused as
    /// unsupported; a wrong one fails verification instead.
    #[test]
    fn direct_asset_io_signs_a_supplied_bmff_hash_with_merkle_maps() {
        let context = test_context().with_signer(test_signer(SigningAlg::Ed25519));
        let mut store = unsigned_store(&context);
        let mut hash = BmffHash::new("supplied", "sha256", None);
        hash.set_default_exclusions_with_options(context.settings());
        hash.set_hash(vec![1; 32]);
        hash.set_merkle(Vec::new());
        store
            .provenance_claim_mut()
            .unwrap()
            .add_assertion(&hash)
            .unwrap();
        let result = store.save_to_stream_asset_io(
            "video/mp4",
            &mut Cursor::new(bmff_fixture()),
            &mut Cursor::new(Vec::new()),
            &context,
        );
        assert!(
            !matches!(result, Err(Error::NotImplemented(_))),
            "{result:?}"
        );
    }

    /// The Merkle maps and proof boxes of a direct save are those of the legacy save:
    /// both come from the source's media. A signed file takes a new manifest with
    /// its proofs replaced, or kept when the new manifest has no Merkle tree.
    #[test]
    fn direct_asset_io_bmff_merkle_matches_the_legacy_save() {
        use ::asset_io::{labels::MERKLE, ItemKind};

        const VIDEO: &[u8] = include_bytes!("../../tests/fixtures/video1_no_manifest.mp4");

        /// The Merkle settings: a block size in KB (0 is one leaf per `mdat`) and the
        /// most proof rows to keep.
        fn merkle_context(merkle: Option<(i64, i64)>) -> Context {
            let mut context = test_context().with_signer(test_signer(SigningAlg::Ps256));
            if let Some((chunk_kb, max_proofs)) = merkle {
                context = context
                    .with_settings_value("core.merkle_tree_chunk_size_in_kb", chunk_kb)
                    .unwrap()
                    .with_settings_value("core.merkle_tree_max_proofs", max_proofs)
                    .unwrap();
            }
            context
        }

        fn merkle_store(context: &Context) -> Store {
            // Merkle trees need BMFF hash v3, so a v2 claim.
            let mut store = Store::from_context(context);
            store
                .commit_claim(crate::utils::test::create_test_claim().unwrap())
                .unwrap();
            store
        }

        fn proofs(data: &[u8]) -> Vec<Vec<u8>> {
            let handler = ::asset_io::HandlerRegistry::builtin()
                .handler("video/mp4")
                .unwrap()
                .clone();
            let mut stream = Cursor::new(data);
            let structure = handler.parse(&mut stream).unwrap();
            structure
                .items_labelled(ItemKind::Other, MERKLE)
                .map(|item| structure.read_item(&mut stream, item).unwrap())
                .collect()
        }

        fn maps(store: &Store) -> Vec<u8> {
            let hash = BmffHash::from_assertion(
                store.provenance_claim().unwrap().bmff_hash_assertions()[0].assertion(),
            )
            .unwrap();
            c2pa_cbor::to_vec(&hash.merkle().expect("Merkle maps")).unwrap()
        }

        // Two `mdat` boxes of three 1 KB blocks each, to cover each in turn.
        let two = bmff_fixture_with_mdats(&[3000, 2500]);
        let cases: [(&[u8], i64, i64); 6] = [
            (VIDEO, 1, 0),
            (VIDEO, 1, 3),
            (&two, 1, 0),
            (&two, 1, 3),
            (&two, 0, 3),
            (&two, 1, 100),
        ];
        for (source, chunk_kb, max_proofs) in cases {
            let case = format!("{} bytes, {chunk_kb} KB, {max_proofs} proofs", source.len());
            let context = merkle_context(Some((chunk_kb, max_proofs)));
            let mut direct_store = merkle_store(&context);
            let mut direct = Cursor::new(Vec::new());
            let direct_manifest = direct_store
                .save_to_stream_asset_io(
                    "video/mp4",
                    &mut Cursor::new(source),
                    &mut direct,
                    &context,
                )
                .unwrap();

            let mut legacy_store = merkle_store(&context);
            let mut legacy = Cursor::new(Vec::new());
            legacy_store
                .save_to_stream(
                    "video/mp4",
                    &mut Cursor::new(source),
                    &mut legacy,
                    context.signer().unwrap(),
                    &context,
                )
                .unwrap();

            assert_eq!(maps(&direct_store), maps(&legacy_store), "{case}");
            let direct_proofs = proofs(direct.get_ref());
            assert_eq!(direct_proofs, proofs(legacy.get_ref()), "{case}");
            assert_valid_manifest("video/mp4", &direct_manifest, &mut direct);

            // Re-sign: a new tree replaces the proofs, no tree keeps them.
            for resign in [Some((chunk_kb, max_proofs)), None] {
                let context = merkle_context(resign);
                let mut resigned = Cursor::new(Vec::new());
                let manifest = merkle_store(&context)
                    .save_to_stream_asset_io(
                        "video/mp4",
                        &mut Cursor::new(direct.get_ref().as_slice()),
                        &mut resigned,
                        &context,
                    )
                    .unwrap();
                assert_eq!(
                    proofs(resigned.get_ref()),
                    direct_proofs,
                    "{case}: {resign:?}"
                );
                assert_valid_manifest("video/mp4", &manifest, &mut resigned);
            }
        }

        // Proof boxes are written when there are proof rows to keep.
        let boxes = |source: &[u8], merkle| {
            let context = merkle_context(Some(merkle));
            let mut output = Cursor::new(Vec::new());
            merkle_store(&context)
                .save_to_stream_asset_io(
                    "video/mp4",
                    &mut Cursor::new(source),
                    &mut output,
                    &context,
                )
                .unwrap();
            proofs(output.get_ref()).len()
        };
        assert_eq!(boxes(&two, (1, 0)), 0);
        assert_eq!(boxes(&two, (1, 3)), 6);
        assert_eq!(boxes(&two, (0, 3)), 0);
    }

    /// An unsupported BMFF request is refused before anything is written.
    #[test]
    fn direct_asset_io_rejects_unsupported_bmff_requests_before_writing() {
        let context = test_context().with_signer(test_signer(SigningAlg::Ed25519));
        let mut store = unsigned_store(&context);
        let mut hash = BmffHash::new("requested", "sha256", None);
        hash.set_default_exclusions_with_options(context.settings());
        hash.set_merkle(Vec::new());
        store
            .provenance_claim_mut()
            .unwrap()
            .add_assertion(&hash)
            .unwrap();
        let mut output = TrackedOutput::default();
        let result = store.save_to_stream_asset_io(
            "video/mp4",
            &mut Cursor::new(bmff_fixture()),
            &mut output,
            &context,
        );
        assert!(matches!(result, Err(Error::NotImplemented(_))));
        assert!(output.writes.is_empty());
    }

    /// An indexed selector excludes the box it names: changing it leaves the
    /// hash valid, changing the media does not.
    #[test]
    fn direct_asset_io_bmff_indexed_selector_excludes_its_box() {
        use crate::assertions::ExclusionsMap;
        let context = test_context()
            .with_settings(r#"{"verify":{"verify_after_sign":false}}"#)
            .unwrap()
            .with_signer(test_signer(SigningAlg::Ed25519));
        let mut store = unsigned_store(&context);
        let mut hash = BmffHash::new("requested", "sha256", None);
        hash.set_default_exclusions_with_options(context.settings());
        hash.add_exclusions(&mut vec![ExclusionsMap::new("/moov/trak[1]".into())]);
        store
            .provenance_claim_mut()
            .unwrap()
            .add_assertion(&hash)
            .unwrap();
        let mut output = Cursor::new(Vec::new());
        let manifest = store
            .save_to_stream_asset_io(
                "video/mp4",
                &mut Cursor::new(bmff_fixture()),
                &mut output,
                &context,
            )
            .unwrap();
        let signed = output.into_inner();
        let tampered = |tag: &[u8], at: usize| {
            let mut bytes = signed.clone();
            let found = bytes.windows(4).position(|w| w == tag).unwrap();
            bytes[found + 4 + at] ^= 1;
            let reader = Reader::from_context(test_context())
                .with_manifest_data_and_stream(&manifest, "video/mp4", Cursor::new(bytes))
                .unwrap();
            reader.validation_state()
        };
        assert_ne!(tampered(b"stco", 11), ValidationState::Invalid);
        assert_eq!(tampered(b"mdat", 10), ValidationState::Invalid);
    }

    /// A data predicate over an offset table the write relocates sees the bytes
    /// as written, which are what a validator reads.
    #[test]
    fn direct_asset_io_bmff_predicates_see_relocated_offsets() {
        use crate::assertions::{DataMap, ExclusionsMap};
        const STCO: &str = "/moov/trak/mdia/minf/stbl/stco";
        // Where the first chunk offset of `bytes` is, and its value.
        let first_chunk_offset = |bytes: &[u8]| {
            let handler = ::asset_io::HandlerRegistry::builtin()
                .handler("video/mp4")
                .unwrap()
                .clone();
            let mut src = Cursor::new(bytes);
            let structure = handler.parse(&mut src).unwrap();
            let mut at = None;
            structure
                .walk(&mut src, |node| {
                    if node.path == STCO {
                        at = Some(node.range.offset() as usize + 16);
                    }
                    Ok(())
                })
                .unwrap();
            let at = at.expect("an stco box");
            (at, bytes[at..at + 4].to_vec())
        };
        let save = |value: Vec<u8>| {
            let context = test_context().with_signer(test_signer(SigningAlg::Ed25519));
            let mut store = unsigned_store(&context);
            let mut hash = BmffHash::new("requested", "sha256", None);
            hash.set_default_exclusions_with_options(context.settings());
            let mut ex = ExclusionsMap::new(STCO.into());
            ex.data = Some(vec![DataMap { offset: 16, value }]);
            hash.add_exclusions(&mut vec![ex]);
            store
                .provenance_claim_mut()
                .unwrap()
                .add_assertion(&hash)
                .unwrap();
            let mut output = Cursor::new(Vec::new());
            store
                .save_to_stream_asset_io(
                    "video/mp4",
                    &mut Cursor::new(bmff_fixture()),
                    &mut output,
                    &context,
                )
                .unwrap();
            output
        };
        // Changing the table (its flags, not the bytes the predicate reads) keeps
        // the signature valid only if the table was excluded.
        let still_valid_after_tamper = |mut output: Cursor<Vec<u8>>| {
            let (at, _) = first_chunk_offset(output.get_ref());
            output.get_mut()[at - 5] ^= 1;
            output.rewind().unwrap();
            let reader = Reader::from_context(test_context())
                .with_stream("video/mp4", output)
                .unwrap();
            reader.validation_state() != ValidationState::Invalid
        };

        let (_, original) = first_chunk_offset(&bmff_fixture());
        let unmatched = save(original.clone());
        let (_, relocated) = first_chunk_offset(unmatched.get_ref());
        assert_ne!(
            relocated, original,
            "inserting the manifest moves the media"
        );
        assert!(!still_valid_after_tamper(unmatched));
        assert!(still_valid_after_tamper(save(relocated)));
    }

    #[test]
    fn direct_asset_io_requested_box_algorithms_and_excluded_boxes_are_preserved() {
        let context = test_context().with_signer(test_signer(SigningAlg::Ed25519));
        let (format, source) = FIXTURES[0];
        let mut first = unsigned_store(&context);
        first
            .provenance_claim_mut()
            .unwrap()
            .add_assertion(&BoxHash { boxes: Vec::new() })
            .unwrap();
        first
            .save_to_stream_asset_io(
                format,
                &mut Cursor::new(source),
                &mut Cursor::new(Vec::new()),
                &context,
            )
            .unwrap();
        let mut hash = BoxHash::from_assertion(
            first.provenance_claim().unwrap().box_hash_assertions()[0].assertion(),
        )
        .unwrap();
        // Hashes already computed would be signed as given, so clear them to
        // request the binding again with these algorithms.
        for entry in &mut hash.boxes {
            entry.hash = Vec::new().into();
            if entry.names != ["C2PA"] {
                entry.alg = Some("sha512".into());
            }
        }
        hash.boxes[0].excluded = Some(true);
        let mut next = unsigned_store(&context);
        next.provenance_claim_mut()
            .unwrap()
            .add_assertion(&hash)
            .unwrap();
        let mut output = Cursor::new(Vec::new());
        let manifest = next
            .save_to_stream_asset_io(format, &mut Cursor::new(source), &mut output, &context)
            .unwrap();
        let actual = BoxHash::from_assertion(
            next.provenance_claim().unwrap().box_hash_assertions()[0].assertion(),
        )
        .unwrap();
        for (requested, actual) in hash.boxes.iter().zip(actual.boxes) {
            assert_eq!(requested.names, actual.names);
            assert_eq!(requested.alg, actual.alg);
            assert_eq!(requested.excluded, actual.excluded);
        }
        assert_valid_manifest(format, &manifest, &mut output);
    }

    #[test]
    fn direct_asset_io_default_bindings_for_other_structured_containers() {
        let fixtures: [(&str, &[u8]); 4] = [
            (
                "image/gif",
                include_bytes!("../../tests/fixtures/sample1.gif"),
            ),
            (
                "audio/wav",
                include_bytes!("../../tests/fixtures/sample1.wav"),
            ),
            (
                "image/webp",
                include_bytes!("../../tests/fixtures/test_lossless.webp"),
            ),
            (
                "audio/mpeg",
                include_bytes!("../../tests/fixtures/sample1.mp3"),
            ),
        ];
        for (format, source) in fixtures {
            for mode in ["embed", "sidecar", "remote", "embed_remote"] {
                let context = test_context()
                    .with_settings(r#"{"verify":{"verify_after_sign":false}}"#)
                    .unwrap()
                    .with_signer(test_signer(SigningAlg::Ed25519));
                let mut store = unsigned_store(&context);
                let claim = store.provenance_claim_mut().unwrap();
                match mode {
                    "sidecar" => claim.set_external_manifest(),
                    "remote" => claim
                        .set_remote_manifest("https://example.com/manifest.c2pa")
                        .unwrap(),
                    "embed_remote" => claim
                        .set_embed_remote_manifest("https://example.com/manifest.c2pa")
                        .unwrap(),
                    _ => {}
                }
                let mut output = TrackedOutput::default();
                let manifest = store
                    .save_to_stream_asset_io(
                        format,
                        &mut Cursor::new(source),
                        &mut output,
                        &context,
                    )
                    .map_err(|error| format!("{format}/{mode}: {error}"))
                    .unwrap();
                let handler = ::asset_io::HandlerRegistry::builtin()
                    .handler(format)
                    .unwrap()
                    .clone();
                output.stream.rewind().unwrap();
                let structure = handler.parse(&mut output.stream).unwrap();
                assert_forward_write(
                    &output,
                    &structure,
                    matches!(mode, "embed" | "embed_remote"),
                );
                assert_valid_manifest(format, &manifest, &mut output.stream);
            }
        }
    }

    #[test]
    fn direct_asset_io_save_embeds_valid_manifests() {
        for (format, source) in FIXTURES {
            let context = test_context()
                .with_settings(r#"{"verify":{"verify_after_sign":true}}"#)
                .unwrap()
                .with_signer(test_signer(SigningAlg::Ed25519));
            let mut input = Cursor::new(source.to_vec());
            let mut output = Cursor::new(Vec::new());
            let mut store = unsigned_store(&context);

            let manifest = store
                .save_to_stream_asset_io(format, &mut input, &mut output, &context)
                .map_err(|error| format!("{format}: {error}"))
                .unwrap();
            assert!(!manifest.is_empty(), "{format}: empty manifest");

            output.rewind().unwrap();
            let reader = Reader::from_context(test_context())
                .with_stream(format, &mut output)
                .map_err(|error| format!("{format}: {error}"))
                .unwrap();
            assert_ne!(
                reader.validation_state(),
                ValidationState::Invalid,
                "{format}: {:?}",
                reader.validation_status()
            );
        }
    }

    #[test]
    fn direct_asset_io_save_writes_once_then_patches_only_the_manifest() {
        for (format, source) in FIXTURES {
            let context = test_context()
                .with_settings(r#"{"verify":{"verify_after_sign":false}}"#)
                .unwrap()
                .with_signer(test_signer(SigningAlg::Ps256));
            let mut input = Cursor::new(source);
            let mut output = TrackedOutput::default();
            let mut store = unsigned_store(&context);
            store
                .save_to_stream_asset_io(format, &mut input, &mut output, &context)
                .map_err(|error| format!("{format}: {error}"))
                .unwrap();

            let handler = ::asset_io::HandlerRegistry::builtin()
                .handler(format)
                .unwrap()
                .clone();
            output.stream.rewind().unwrap();
            let structure = handler.parse(&mut output.stream).unwrap();
            let item = structure.c2pa_item().unwrap().unwrap();
            let manifest_segments: Vec<_> = item
                .extents()
                .map(|extent| structure.segment(extent.segment()).unwrap().range())
                .collect();
            let in_manifest = |offset: u64, len: usize| {
                manifest_segments
                    .iter()
                    .any(|range| offset >= range.offset() && offset + len as u64 <= range.end())
            };
            // Container checksum repair may read manifest segments, never the asset payload.
            for (offset, len) in output.reads {
                assert!(
                    in_manifest(offset, len),
                    "{format}: output reread at {offset}"
                );
            }
            let mut written = 0;
            let mut patching = false;
            for (offset, len) in output.writes {
                if !patching && offset == written {
                    written += len as u64;
                } else {
                    patching = true;
                    assert!(
                        in_manifest(offset, len),
                        "{format}: non-manifest rewrite at {offset}"
                    );
                }
            }
            assert_eq!(written, structure.total_size(), "{format}: incomplete pass");
            assert!(patching, "{format}: manifest was not patched");

            output.stream.rewind().unwrap();
            let reader = Reader::from_context(test_context())
                .with_stream(format, &mut output.stream)
                .map_err(|error| format!("{format}: {error}"))
                .unwrap();
            assert_ne!(
                reader.validation_state(),
                ValidationState::Invalid,
                "{format}: {:?}",
                reader.validation_status()
            );
        }
    }

    #[test]
    fn direct_asset_io_save_propagates_write_cancellation_and_io_errors() {
        for cancel in [true, false] {
            let context = test_context()
                .with_signer(test_signer(SigningAlg::Ps256))
                .with_progress_callback(move |phase, step, _| {
                    !cancel || phase != ProgressPhase::Hashing || step < 2
                });
            let mut store = unsigned_store(&context);
            let mut input = Cursor::new(include_bytes!("../../tests/fixtures/earth_apollo17.jpg"));
            let mut output = TrackedOutput {
                fail_writes: !cancel,
                ..Default::default()
            };
            let error = store
                .save_to_stream_asset_io("image/jpeg", &mut input, &mut output, &context)
                .unwrap_err();
            if cancel {
                assert!(matches!(error, Error::OperationCancelled), "{error}");
            } else {
                assert!(
                    matches!(error, Error::IoError(ref source) if source.to_string() == "test write failure"),
                    "{error}"
                );
            }
        }
    }

    /// A JPEG container served under a format only a context registers.
    #[derive(Debug)]
    struct DirectOnlyJpeg(std::sync::Arc<dyn ::asset_io::container_api::ContainerHandler>);

    impl ::asset_io::container_api::ContainerHandler for DirectOnlyJpeg {
        fn id(&self) -> &'static str {
            "direct-only-jpeg"
        }

        fn formats(&self) -> &[::asset_io::container_api::FormatSpec] {
            const FORMATS: &[::asset_io::container_api::FormatSpec] =
                &[::asset_io::container_api::FormatSpec::new(
                    "image/x-direct",
                    "xdirect",
                )];
            FORMATS
        }

        fn parse_async(
            self: std::sync::Arc<Self>,
            io: ::asset_io::container_api::Io,
        ) -> ::asset_io::container_api::BoxFuture<'static, ::asset_io::Result<::asset_io::Structure>>
        {
            std::sync::Arc::clone(&self.0).parse_async(io)
        }
    }

    #[test]
    fn direct_asset_io_uses_the_context_handler_registry() {
        let (_, source) = FIXTURES[0];
        let save = |context: &Context| {
            let mut store = unsigned_store(context);
            let mut output = Cursor::new(Vec::new());
            store
                .save_to_stream_asset_io(
                    "image/x-direct",
                    &mut Cursor::new(source),
                    &mut output,
                    context,
                )
                .map(|manifest| (manifest, output))
        };

        // Without a handler the format is unknown, so it cannot be embedded.
        let context = test_context().with_signer(test_signer(SigningAlg::Ed25519));
        assert!(matches!(save(&context), Err(Error::UnsupportedType)));

        // The context's handler is used for the direct save.
        let jpeg = ::asset_io::HandlerRegistry::builtin()
            .handler("image/jpeg")
            .unwrap()
            .clone();
        let context = test_context()
            .with_signer(test_signer(SigningAlg::Ed25519))
            .with_io_handler(DirectOnlyJpeg(jpeg));
        let (manifest, mut output) = save(&context).unwrap();
        assert!(!manifest.is_empty());
        assert_valid_manifest("image/jpeg", &manifest, &mut output);

        // A format the context serves with a legacy handler is saved through it.
        let context = test_context().with_signer(test_signer(SigningAlg::Ed25519));
        assert!(context.io().container_handler("zip").is_none());
        assert!(context.io().handler("zip").is_some());
        let mut store = unsigned_store(&context);
        let mut output = Cursor::new(Vec::new());
        let manifest = store
            .save_to_stream_asset_io(
                "zip",
                &mut Cursor::new(include_bytes!("../../tests/fixtures/sample1.zip")),
                &mut output,
                &context,
            )
            .unwrap();
        assert_valid_manifest("zip", &manifest, &mut output);

        // ISO BMFF is served by asset-io by default.
        assert!(context.io().container_handler("video/mp4").is_some());
    }

    #[test]
    fn direct_asset_io_rejects_noncontiguous_manifest_segments() {
        let handler = ::asset_io::HandlerRegistry::builtin()
            .handler("image/jpeg")
            .unwrap()
            .clone();
        let mut input = Cursor::new(include_bytes!("../../tests/fixtures/CA.jpg").to_vec());
        let structure = handler.clone().parse(&mut input).unwrap();
        let item = structure.c2pa_item().unwrap().unwrap();
        let second = item.extents().nth(1).expect("multi-segment manifest");
        let gap_start = structure
            .segment(second.segment())
            .unwrap()
            .range()
            .offset() as usize;
        let foreign_segment = b"\xff\xe1\x00\x06test";
        input
            .get_mut()
            .splice(gap_start..gap_start, foreign_segment.iter().copied());
        input.rewind().unwrap();
        assert!(matches!(
            open_structure(handler, &mut input),
            Err(Error::InvalidAsset(message))
                if message.contains("JUMBF APP11 segments are not contiguous")
        ));
    }

    #[test]
    fn direct_asset_io_binding_and_options_matrix() {
        use crate::utils::xmp_inmemory_utils::extract_provenance;
        let bmff = bmff_fixture();
        for (format, source) in FIXTURES.into_iter().chain([("video/mp4", bmff.as_slice())]) {
            for binding in ["default", "data", "boxes", "bmff"] {
                for mode in ["embed", "sidecar", "remote", "embed_remote"] {
                    let context = test_context()
                        .with_settings(r#"{"verify":{"verify_after_sign":false}}"#)
                        .unwrap()
                        .with_signer(test_signer(SigningAlg::Ed25519));
                    let mut store = unsigned_store(&context);
                    let claim = store.provenance_claim_mut().unwrap();
                    match binding {
                        "data" => {
                            claim
                                .add_assertion(&DataHash::new("requested", "sha384"))
                                .unwrap();
                        }
                        "boxes" => {
                            claim.add_assertion(&BoxHash { boxes: Vec::new() }).unwrap();
                        }
                        "bmff" => {
                            let mut hash = BmffHash::new("requested", "sha512", None);
                            hash.set_default_exclusions_with_options(context.settings());
                            hash.set_bmff_version(2);
                            claim.add_assertion(&hash).unwrap();
                        }
                        _ => {}
                    }
                    let url = "https://example.com/manifest.c2pa?x=1&y=2";
                    match mode {
                        "sidecar" => claim.set_external_manifest(),
                        "remote" => claim.set_remote_manifest(url).unwrap(),
                        "embed_remote" => claim.set_embed_remote_manifest(url).unwrap(),
                        _ => {}
                    }
                    let embed = matches!(mode, "embed" | "embed_remote");
                    let mut input = Cursor::new(source);
                    let mut output = TrackedOutput::default();
                    let result =
                        store.save_to_stream_asset_io(format, &mut input, &mut output, &context);
                    let supported = match binding {
                        "data" => format != "video/mp4" || !embed,
                        "bmff" => format == "video/mp4",
                        "boxes" => matches!(format, "image/jpeg" | "image/png"),
                        _ => true,
                    };
                    if !supported {
                        assert!(
                            result.is_err(),
                            "{format}/{binding}/{mode} unexpectedly supported"
                        );
                        assert!(
                            output.writes.is_empty(),
                            "{format}/{binding}/{mode} wrote before rejection"
                        );
                        continue;
                    }
                    let manifest = result
                        .map_err(|error| format!("{format}/{binding}/{mode}: {error}"))
                        .unwrap();
                    assert_valid_manifest(format, &manifest, &mut output.stream);
                    let handler = ::asset_io::HandlerRegistry::builtin()
                        .handler(format)
                        .unwrap()
                        .clone();
                    output.stream.rewind().unwrap();
                    let structure = handler.parse(&mut output.stream).unwrap();
                    assert_eq!(
                        structure
                            .item(::asset_io::ItemKind::C2pa)
                            .unwrap()
                            .is_some(),
                        embed
                    );
                    let xmp = structure.xmp(&mut output.stream).unwrap();
                    let provenance = xmp
                        .and_then(|bytes| extract_provenance(std::str::from_utf8(&bytes).unwrap()));
                    assert_eq!(
                        provenance,
                        mode.contains("remote").then(|| url.replace('&', "&amp;"))
                    );
                    if !embed {
                        assert!(
                            output.reads.is_empty(),
                            "{format}/{binding}/{mode}: output reread"
                        );
                        let mut end = 0;
                        for (offset, len) in output.writes {
                            assert_eq!(offset, end, "{format}/{binding}/{mode}: output rewrite");
                            end += len as u64;
                        }
                        assert_eq!(end, structure.total_size());
                    }
                    let claim = store.provenance_claim().unwrap();
                    match binding {
                        "data" => assert_eq!(
                            DataHash::from_assertion(claim.data_hash_assertions()[0].assertion())
                                .unwrap()
                                .alg
                                .as_deref(),
                            Some("sha384")
                        ),
                        "bmff" => assert_eq!(
                            BmffHash::from_assertion(claim.bmff_hash_assertions()[0].assertion())
                                .unwrap()
                                .alg()
                                .map(String::as_str),
                            Some("sha512")
                        ),
                        "default" if format == "video/mp4" => {
                            assert_eq!(claim.bmff_hash_assertions().len(), 1)
                        }
                        "default" => {
                            assert_eq!(claim.data_hash_assertions().len(), 1)
                        }
                        _ => {}
                    }
                }
            }
        }
    }
}
