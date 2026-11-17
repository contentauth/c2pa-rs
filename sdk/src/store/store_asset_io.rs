use std::{io::SeekFrom, sync::Arc};

use ::asset_io::{
    container_api::{ContainerHandler, WritePlan},
    Chunk, ItemKind, NullSink, Role, SegmentId, Sink, Structure, Updates,
};

use crate::{
    assertions::{
        asset_binding::{
            asset_io_error, binding_from_claim, default_binding, AssetBinding, BuiltAssertion,
            PlannedAsset, SpanHasher,
        },
        DataHash,
    },
    asset_handlers::asset_io_adapter::{store_err, MANIFEST_PLACEHOLDER},
    asset_io::{ReadSeek, ReadWriteSeek},
    claim::{ClaimAssetData, RemoteManifest},
    context::{Context, ProgressPhase},
    dynamic_assertion::{DynamicAssertion, PartialClaim},
    error::{Error, Result},
    store::Store,
    utils::xmp_inmemory_utils::{add_provenance, extract_provenance, remove_provenance, MIN_XMP},
    Signer,
};

/// Most times the manifest is rebuilt for its size to settle. Absolute offsets in
/// a hard binding can change the width of CBOR integers, and so the manifest's
/// size, which moves the offsets again.
const MAX_SETTLE_PASSES: usize = 8;

/// Buffer size for copying an asset no handler understands.
const COPY_BUFFER_LEN: usize = 64 * 1024;

/// What the provenance claim asks of a save.
struct SaveRequest {
    alg: String,
    embed: bool,
    remote_url: Option<String>,
    /// An update manifest, which has no hard binding of its own.
    update: bool,
    /// The claim's own hard binding, if it has one.
    binding: Option<Box<dyn AssetBinding>>,
}

impl SaveRequest {
    fn from_store(store: &Store) -> Result<Self> {
        let claim = store.provenance_claim().ok_or(Error::ClaimEncoding)?;
        let (embed, remote_url) = match claim.remote_manifest() {
            RemoteManifest::NoRemote => (true, None),
            RemoteManifest::SideCar => (false, None),
            RemoteManifest::Remote(url) => (false, Some(url)),
            RemoteManifest::EmbedWithRemote(url) => (true, Some(url)),
        };
        let update = claim.update_manifest();
        let binding = binding_from_claim(claim)?;
        if update && binding.is_some() {
            return Err(Error::UpdateManifestInvalid);
        }
        Ok(Self {
            alg: claim.alg().to_owned(),
            embed,
            remote_url,
            update,
            binding,
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

/// The updates for a save: any existing store removed, `xmp` set if given, and
/// `store` set if given.
fn save_updates(xmp: Option<&[u8]>, store: Option<Vec<u8>>) -> Updates {
    let mut updates = Updates::new().remove_c2pa();
    if let Some(xmp) = xmp {
        updates = updates.set_xmp(xmp.to_vec());
    }
    if let Some(store) = store {
        updates = updates.set_c2pa(store);
    }
    updates
}

/// Fill the placeholder store of `written`, already in `output`, with `store`.
fn patch_store(written: &Structure, output: &mut dyn ReadWriteSeek, store: &[u8]) -> Result<()> {
    output.rewind()?;
    let mut output = output;
    let item = written
        .c2pa_item()
        .map_err(store_err)?
        .ok_or(Error::EmbeddingError)?;
    written
        .patch_exact(&mut output, item, store)
        .map_err(asset_io_error)?;
    output.flush()?;
    output.rewind()?;
    Ok(())
}

impl Store {
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
    pub(crate) fn save_to_stream_asset_io(
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
            return self.save_to_stream(format, input, output, signer, context);
        }

        // Reserve the signer's dynamic assertions before anything is sized; they
        // are written just before signing.
        let dynamic_assertions = signer.dynamic_assertions();
        self.add_dynamic_assertion_placeholders(&dynamic_assertions)?;

        let request = SaveRequest::from_store(self)?;
        let Some(handler) = handler else {
            return self.save_unhandled_sidecar(
                format,
                input,
                output,
                request,
                signer,
                &dynamic_assertions,
                context,
            );
        };
        let structure = open_structure(handler, input)?;
        let xmp = provenance_xmp(&structure, input, request.remote_url.as_deref())?;
        let save = DirectSave {
            format,
            structure: &structure,
            xmp: xmp.as_deref(),
            embed: request.embed,
            signer,
            dynamic_assertions: &dynamic_assertions,
            context,
        };
        if request.update {
            return self.save_update_manifest(&save, input, output);
        }

        let existing = request.binding.is_some();
        let binding = match request.binding {
            Some(binding) => binding,
            None => {
                let claim = self.provenance_claim().ok_or(Error::ClaimEncoding)?;
                default_binding(&structure, context, claim, &request.alg)?
            }
        };
        binding.check_structure(&structure)?;

        // A compressed store's size is only known once it is signed, so only a
        // binding that does not depend on the store's size can bind it. Anything
        // else is saved uncompressed, as `save_to_stream` saves it.
        let claim = self.provenance_claim_mut().ok_or(Error::ClaimEncoding)?;
        if claim.compressed() && binding.depends_on_store_size() {
            claim.set_compressed_manifest(false);
        }
        if claim.compressed() {
            return self.save_unsized_store(&save, input, output, binding, existing, &request.alg);
        }
        self.save_settled_store(&save, input, output, binding, existing, &request.alg)
    }

    /// Save with a store whose size is settled before writing: write and hash in
    /// one pass with a placeholder store, sign, then patch the store in place.
    fn save_settled_store(
        &mut self,
        save: &DirectSave<'_>,
        input: &mut dyn ReadSeek,
        output: &mut dyn ReadWriteSeek,
        mut binding: Box<dyn AssetBinding>,
        existing: bool,
        alg: &str,
    ) -> Result<Vec<u8>> {
        let reserve_size = save.signer.reserve_size();
        let embed = save.embed;
        let placeholder = |store: &[u8]| embed.then(|| store.to_vec());

        // The binding's ranges with the smallest store, to put it in the claim.
        let mut updates = save_updates(save.xmp, placeholder(MANIFEST_PLACEHOLDER));
        {
            let plan = plan_write(save.structure, input, &updates)?;
            binding.plan_hashes(&mut PlannedAsset::new(&plan, &mut *input)?, alg)?;
        }
        self.put_binding(binding.as_ref(), existing)?;

        // Settle the manifest's size before writing, without copying the asset.
        let mut store = self.to_jumbf_internal(reserve_size)?;
        if embed {
            let mut settled = false;
            for _ in 0..MAX_SETTLE_PASSES {
                updates = save_updates(save.xmp, placeholder(&store));
                {
                    let plan = plan_write(save.structure, input, &updates)?;
                    binding.plan_hashes(&mut PlannedAsset::new(&plan, &mut *input)?, alg)?;
                }
                self.put_binding(binding.as_ref(), true)?;
                let next = self.to_jumbf_internal(reserve_size)?;
                settled = next.len() == store.len();
                store = next;
                if settled {
                    break;
                }
            }
            if !settled {
                return Err(Error::JumbfCreationError);
            }
            updates = save_updates(save.xmp, placeholder(&store));
        }
        let store_len = store.len();

        // Write and hash in one pass.
        let plan = plan_write(save.structure, input, &updates)?;
        let spans = binding.plan_hashes(&mut PlannedAsset::new(&plan, &mut *input)?, alg)?;
        let mut hasher = SpanHasher::new(spans, save.context)?;
        save.context.check_progress(ProgressPhase::Writing, 1, 2)?;
        input.rewind()?;
        output.rewind()?;
        plan.execute(input, output, &mut hasher)
            .map_err(asset_io_error)?;
        output.flush()?;
        save.context.check_progress(ProgressPhase::Writing, 2, 2)?;
        binding.set_hashes(hasher.finish());
        self.put_binding(binding.as_ref(), true)?;

        if embed && self.to_jumbf_internal(reserve_size)?.len() != store_len {
            return Err(Error::JumbfCreationError);
        }
        let signed = self.sign_for_save(
            save.signer,
            save.dynamic_assertions,
            save.context,
            embed.then_some(store_len),
        )?;
        if embed {
            patch_store(plan.structure(), output, &signed)?;
            save.context
                .check_progress(ProgressPhase::Embedding, 1, 1)?;
        }
        self.finish_save(save.format, save.embed, output, save.context, signed)
    }

    /// Save with a store whose size is only known once signed (a compressed
    /// store), bound by a binding that does not depend on it: hash the output in a
    /// pass that writes nothing, sign, then write the output with the signed store.
    fn save_unsized_store(
        &mut self,
        save: &DirectSave<'_>,
        input: &mut dyn ReadSeek,
        output: &mut dyn ReadWriteSeek,
        mut binding: Box<dyn AssetBinding>,
        existing: bool,
        alg: &str,
    ) -> Result<Vec<u8>> {
        let store = save.embed.then(|| MANIFEST_PLACEHOLDER.to_vec());
        let updates = save_updates(save.xmp, store);
        let plan = plan_write(save.structure, input, &updates)?;
        let spans = binding.plan_hashes(&mut PlannedAsset::new(&plan, &mut *input)?, alg)?;
        self.put_binding(binding.as_ref(), existing)?;
        let mut hasher = SpanHasher::new(spans, save.context)?;
        input.rewind()?;
        plan.execute(input, &mut std::io::sink(), &mut hasher)
            .map_err(asset_io_error)?;
        binding.set_hashes(hasher.finish());
        self.put_binding(binding.as_ref(), true)?;

        let signed =
            self.sign_for_save(save.signer, save.dynamic_assertions, save.context, None)?;
        self.write_final(save, input, output, &signed)?;
        self.finish_save(save.format, save.embed, output, save.context, signed)
    }

    /// Save an update manifest. It has no hard binding, so it is signed first and
    /// written once. A container that keeps the original store apart (ISO BMFF)
    /// leaves it in place and adds only the update.
    fn save_update_manifest(
        &mut self,
        save: &DirectSave<'_>,
        input: &mut dyn ReadSeek,
        output: &mut dyn ReadWriteSeek,
    ) -> Result<Vec<u8>> {
        let signed =
            self.sign_for_save(save.signer, save.dynamic_assertions, save.context, None)?;
        self.write_final(save, input, output, &signed)?;
        self.finish_save(save.format, save.embed, output, save.context, signed)
    }

    /// Write the output once, with `signed` embedded unless the store is detached.
    fn write_final(
        &self,
        save: &DirectSave<'_>,
        input: &mut dyn ReadSeek,
        output: &mut dyn ReadWriteSeek,
        signed: &[u8],
    ) -> Result<()> {
        let mut updates = save_updates(save.xmp, save.embed.then(|| signed.to_vec()));
        let update = self
            .provenance_claim()
            .is_some_and(|claim| claim.update_manifest());
        if save.embed && update {
            updates = updates.as_update();
        }
        let plan = plan_write(save.structure, input, &updates)?;
        save.context.check_progress(ProgressPhase::Writing, 1, 2)?;
        input.rewind()?;
        output.rewind()?;
        plan.execute(input, output, &mut NullSink)
            .map_err(asset_io_error)?;
        output.flush()?;
        save.context.check_progress(ProgressPhase::Writing, 2, 2)?;
        if save.embed {
            save.context
                .check_progress(ProgressPhase::Embedding, 1, 1)?;
        }
        Ok(())
    }

    /// Record where the store went and verify it if the settings ask for it.
    fn finish_save(
        &mut self,
        format: &str,
        embedded: bool,
        output: &mut dyn ReadWriteSeek,
        context: &Context,
        signed: Vec<u8>,
    ) -> Result<Vec<u8>> {
        self.embedded = embedded;
        self.verify_after_save(output, format, context)?;
        Ok(signed)
    }

    /// Save an asset no handler understands: copied unchanged and hashed whole,
    /// with the manifest returned for a sidecar.
    #[allow(clippy::too_many_arguments)]
    fn save_unhandled_sidecar(
        &mut self,
        format: &str,
        input: &mut dyn ReadSeek,
        output: &mut dyn ReadWriteSeek,
        request: SaveRequest,
        signer: &dyn Signer,
        dynamic_assertions: &[Box<dyn DynamicAssertion>],
        context: &Context,
    ) -> Result<Vec<u8>> {
        if request.remote_url.is_some() {
            return Err(Error::XmpNotSupported);
        }
        if request.embed {
            return Err(Error::UnsupportedType);
        }
        // An update manifest has no hard binding; the asset is only copied.
        let mut binding = match request.binding {
            Some(binding) => Some((binding, true)),
            None if request.update => None,
            None => Some((
                Box::new(DataHash::placeholder(&request.alg, Vec::new())?) as Box<_>,
                false,
            )),
        };
        let mut hasher = match &mut binding {
            Some((binding, _)) => {
                let len = input.seek(SeekFrom::End(0))?;
                Some(SpanHasher::new(
                    binding.plan_unstructured(len, &request.alg)?,
                    context,
                )?)
            }
            None => None,
        };

        let segment = SegmentId::from_index(0).map_err(asset_io_error)?;
        context.check_progress(ProgressPhase::Writing, 1, 2)?;
        input.rewind()?;
        output.rewind()?;
        let mut buffer = vec![0; COPY_BUFFER_LEN];
        let mut offset = 0;
        loop {
            let read = input.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            output.write_all(&buffer[..read])?;
            if let Some(hasher) = &mut hasher {
                hasher
                    .chunk(Chunk::new(segment, Role::Payload, offset, &buffer[..read]))
                    .map_err(asset_io_error)?;
            }
            offset += read as u64;
        }
        output.flush()?;
        context.check_progress(ProgressPhase::Writing, 2, 2)?;
        if let (Some((binding, existing)), Some(hasher)) = (&mut binding, hasher) {
            binding.set_hashes(hasher.finish());
            self.put_binding(binding.as_ref(), *existing)?;
        }

        let manifest = self.sign_for_save(signer, dynamic_assertions, context, None)?;
        self.finish_save(format, false, output, context, manifest)
    }

    /// Write the signer's dynamic assertions into the slots reserved for them,
    /// sign the provenance claim and return the store. With `target_len`, the
    /// store is padded to that length and may not exceed it.
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
            self.write_dynamic_assertions(dynamic_assertions, &mut preliminary_claim)?;
        }
        let claim = self.provenance_claim().ok_or(Error::ClaimEncoding)?;
        let reserve_size = signer.reserve_size();
        let signature = self.sign_claim(claim, signer, reserve_size, context)?;
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
    fn verify_after_save(
        &mut self,
        output: &mut dyn ReadWriteSeek,
        format: &str,
        context: &Context,
    ) -> Result<()> {
        output.rewind()?;
        let verify = &context.settings().verify;
        if verify.verify_after_sign {
            let mut asset = verify
                .verify_after_sign_hash
                .then_some(ClaimAssetData::Stream(output, format));
            self.verify_store_strict(asset.as_mut(), context)?;
            output.rewind()?;
        }
        Ok(())
    }
}

/// What every step of a direct save needs.
struct DirectSave<'a> {
    format: &'a str,
    structure: &'a Structure,
    /// The XMP to write, if it changes.
    xmp: Option<&'a [u8]>,
    embed: bool,
    signer: &'a dyn Signer,
    dynamic_assertions: &'a [Box<dyn DynamicAssertion>],
    context: &'a Context,
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
        bytes.extend(atom(b"mdat", &[42; 256]));
        bytes
    }

    fn assert_valid_manifest(format: &str, manifest: &[u8], output: &mut Cursor<Vec<u8>>) {
        output.rewind().unwrap();
        let reader = Reader::from_context(test_context())
            .with_manifest_data_and_stream(manifest, format, output)
            .unwrap_or_else(|error| panic!("{format}: {error}"));
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
                .save_to_stream_asset_io(
                    format,
                    &mut Cursor::new(source),
                    &mut output,
                    context.signer().unwrap(),
                    &context,
                )
                .unwrap_or_else(|error| panic!("{format}: {error}"));
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
                .save_to_stream_asset_io(
                    format,
                    &mut seed,
                    &mut signed,
                    context.signer().unwrap(),
                    &context,
                )
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
                    .save_to_stream_asset_io(
                        format,
                        &mut signed,
                        &mut output,
                        context.signer().unwrap(),
                        &context,
                    )
                    .unwrap_or_else(|error| panic!("{format}/{mode}: {error}"));
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
                    context.signer().unwrap(),
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
                context.signer().unwrap(),
                &context,
            )
            .unwrap();
        assert_eq!(output.stream.get_ref(), source);
        assert!(output.reads.is_empty());
        assert_valid_manifest("application/octet-stream", &manifest, &mut output.stream);

        for kind in [
            "unknown_embed",
            "unknown_remote",
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
                "unknown_embed" | "unknown_remote" => ("application/octet-stream", source),
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
                context.signer().unwrap(),
                &context,
            );
            assert!(result.is_err(), "{kind}: expected an error");
            let error = result.err().unwrap();
            match kind {
                "unknown_embed" => {
                    assert!(matches!(error, Error::UnsupportedType), "{kind}: {error}")
                }
                // With the `pdf` feature, asset-io embeds in PDFs it can register the
                // store in and declines this one for its structure. Without it, the
                // context has no PDF handler. Either way, before anything is written.
                "pdf" if cfg!(feature = "pdf") => {
                    assert!(matches!(error, Error::NotImplemented(_)), "{kind}: {error}")
                }
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
            .save_to_stream_asset_io(
                format,
                &mut Cursor::new(source),
                &mut output,
                context.signer().unwrap(),
                context,
            )
            .unwrap_or_else(|error| panic!("{format}: {error}"));
        let mut report = StatusTracker::with_error_behavior(ErrorBehavior::StopOnFirstError);
        output.rewind().unwrap();
        let read = Store::from_stream(format, &mut output, &mut report, &test_context())
            .unwrap_or_else(|error| panic!("{format}: {error}"));
        assert!(!report.has_any_error(), "{format}: {report:?}");
        (read, output.into_inner(), report)
    }

    /// A compressed manifest needs a binding that does not depend on the store's
    /// size (a box hash); with any other binding it is saved uncompressed.
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
            .save_to_stream_asset_io(
                "image/jpeg",
                &mut seeded,
                &mut embedded,
                context.signer().unwrap(),
                &context,
            )
            .unwrap();
        let mut detached = unsigned_store(&context);
        detached
            .provenance_claim_mut()
            .unwrap()
            .set_external_manifest();
        let mut output = Cursor::new(Vec::new());
        let manifest = detached
            .save_to_stream_asset_io(
                "image/jpeg",
                &mut embedded,
                &mut output,
                context.signer().unwrap(),
                &context,
            )
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
                    context.signer().unwrap(),
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
            context.signer().unwrap(),
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
                context.signer().unwrap(),
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
                    context.signer().unwrap(),
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
                context.signer().unwrap(),
                &context,
            )
            .unwrap();
        let mut hash = BoxHash::from_assertion(
            first.provenance_claim().unwrap().box_hash_assertions()[0].assertion(),
        )
        .unwrap();
        for entry in &mut hash.boxes {
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
            .save_to_stream_asset_io(
                format,
                &mut Cursor::new(source),
                &mut output,
                context.signer().unwrap(),
                &context,
            )
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
                        context.signer().unwrap(),
                        &context,
                    )
                    .unwrap_or_else(|error| panic!("{format}/{mode}: {error}"));
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
                .save_to_stream_asset_io(
                    format,
                    &mut input,
                    &mut output,
                    context.signer().unwrap(),
                    &context,
                )
                .unwrap_or_else(|error| panic!("{format}: {error}"));
            assert!(!manifest.is_empty(), "{format}: empty manifest");

            output.rewind().unwrap();
            let reader = Reader::from_context(test_context())
                .with_stream(format, &mut output)
                .unwrap_or_else(|error| panic!("{format}: {error}"));
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
                .save_to_stream_asset_io(
                    format,
                    &mut input,
                    &mut output,
                    context.signer().unwrap(),
                    &context,
                )
                .unwrap_or_else(|error| panic!("{format}: {error}"));

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
                .unwrap_or_else(|error| panic!("{format}: {error}"));
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
                .save_to_stream_asset_io(
                    "image/jpeg",
                    &mut input,
                    &mut output,
                    context.signer().unwrap(),
                    &context,
                )
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
                    context.signer().unwrap(),
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
                context.signer().unwrap(),
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
                    let result = store.save_to_stream_asset_io(
                        format,
                        &mut input,
                        &mut output,
                        context.signer().unwrap(),
                        &context,
                    );
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
                    let manifest =
                        result.unwrap_or_else(|error| panic!("{format}/{binding}/{mode}: {error}"));
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
