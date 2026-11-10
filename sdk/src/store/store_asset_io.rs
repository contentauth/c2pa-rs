use std::io::SeekFrom;

use ::asset_io::{HandlerRegistry, Item, ItemKind, Structure, Updates};

use crate::{
    assertions::DataHash,
    asset_io::{ReadSeek, ReadWriteSeek},
    claim::{ClaimAssetData, RemoteManifest},
    context::{Context, ProgressPhase},
    error::{Error, Result},
    hash_utils::HashRange,
    store::Store,
    utils::hash_utils::hash_size_by_alg,
    Signer,
};

const C2PA_STORE_UUID: [u8; 16] = [
    0x63, 0x32, 0x70, 0x61, 0x00, 0x11, 0x00, 0x10, 0x80, 0x00, 0x00, 0xaa, 0x00, 0x38, 0x9b, 0x71,
];
const MANIFEST_PLACEHOLDER: [u8; 8] = [0, 0, 0, 8, b'j', b'u', b'm', b'b'];
const DATA_HASH_NAME: &str = "jumbf manifest";

fn map_asset_io_error(error: ::asset_io::Error) -> Error {
    match error {
        ::asset_io::Error::Io(error) => Error::IoError(error),
        ::asset_io::Error::UserCanceled => Error::OperationCancelled,
        ::asset_io::Error::UnsupportedFormat => Error::UnsupportedType,
        ::asset_io::Error::UnsupportedFeature(feature) => {
            Error::NotImplemented(feature.to_string())
        }
        other => Error::InvalidAsset(other.to_string()),
    }
}

fn item_range(structure: &Structure, item: &Item) -> Result<HashRange> {
    let mut start = u64::MAX;
    let mut end = 0;
    for extent in item.extents() {
        let segment = structure
            .segment(extent.segment())
            .map_err(map_asset_io_error)?;
        let range = segment.range();
        start = start.min(range.offset());
        end = end.max(range.end());
    }
    if start >= end {
        return Err(Error::EmbeddingError);
    }
    Ok(HashRange::new(start, end - start))
}

fn c2pa_item<'a>(structure: &'a Structure, mut input: &mut dyn ReadSeek) -> Result<&'a Item> {
    let mut c2pa_item = None;
    for item in structure.items_of(ItemKind::Jumbf) {
        if structure
            .jumbf_type(&mut input, item)
            .map_err(map_asset_io_error)?
            == Some(C2PA_STORE_UUID)
            && c2pa_item.replace(item).is_some()
        {
            return Err(Error::TooManyManifestStores);
        }
    }
    c2pa_item.ok_or(Error::JumbfNotFound)
}

fn c2pa_item_range(structure: &Structure, input: &mut dyn ReadSeek) -> Result<HashRange> {
    item_range(structure, c2pa_item(structure, input)?)
}

struct DirectAssetIo {
    structure: Structure,
}

impl DirectAssetIo {
    fn open(format: &str, mut input: &mut dyn ReadSeek) -> Result<Self> {
        let registry = HandlerRegistry::builtin();
        let handler = registry.handler(format).ok_or(Error::UnsupportedType)?;
        input.rewind()?;
        let structure = handler
            .clone()
            .parse(&mut input)
            .map_err(map_asset_io_error)?;
        if structure.items_of(ItemKind::Jumbf).next().is_some() {
            return Err(Error::NotImplemented(
                "direct asset-io save currently requires an asset without an existing JUMBF"
                    .to_string(),
            ));
        }
        Ok(Self { structure })
    }

    fn plan_manifest(&self, mut input: &mut dyn ReadSeek) -> Result<HashRange> {
        let planned = self
            .structure
            .plan(
                &mut input,
                &Updates::new().set_jumbf(MANIFEST_PLACEHOLDER.to_vec()),
            )
            .map_err(map_asset_io_error)?;
        let item = planned
            .require_item(ItemKind::Jumbf)
            .map_err(map_asset_io_error)?;
        item_range(&planned, item)
    }

    fn write_manifest(
        &self,
        input: &mut dyn ReadSeek,
        output: &mut dyn ReadWriteSeek,
        store: Vec<u8>,
    ) -> Result<Structure> {
        input.rewind()?;
        output.rewind()?;
        let mut input = input;
        let mut output = output;
        let written = self
            .structure
            .write(
                &mut input,
                &mut output,
                &Updates::new().set_jumbf(store),
                &mut ::asset_io::NullSink,
            )
            .map_err(map_asset_io_error)?;
        output.flush()?;
        Ok(written)
    }

    fn patch_manifest(
        &self,
        written: &Structure,
        output: &mut dyn ReadWriteSeek,
        store: &[u8],
    ) -> Result<()> {
        let item = c2pa_item(written, output)?;
        output.rewind()?;
        let mut output = output;
        written
            .patch_exact(&mut output, item, store)
            .map_err(map_asset_io_error)?;
        output.flush()?;
        output.rewind()?;
        Ok(())
    }
}

fn data_hash_placeholder(alg: &str, exclusion: HashRange) -> Result<DataHash> {
    let mut hash = DataHash::new(DATA_HASH_NAME, alg);
    hash.add_exclusion(exclusion);
    hash.set_hash(vec![0; hash_size_by_alg(alg)?]);
    hash.add_padding(vec![0; 10]);
    Ok(hash)
}

fn generate_data_hash(
    written: &Structure,
    output: &mut dyn ReadWriteSeek,
    alg: &str,
    context: &Context,
) -> Result<DataHash> {
    let exclusion = c2pa_item_range(written, output)?;
    let mut hash = DataHash::new(DATA_HASH_NAME, alg);
    hash.add_exclusion(exclusion);
    let mut progress = |step, total| context.check_progress(ProgressPhase::Hashing, step, total);
    hash.gen_hash_from_stream_with_progress(output, &mut progress)?;
    Ok(hash)
}

impl Store {
    pub(crate) fn save_to_stream_asset_io(
        &mut self,
        format: &str,
        input_stream: &mut dyn ReadSeek,
        output_stream: &mut dyn ReadWriteSeek,
        signer: &dyn Signer,
        context: &Context,
    ) -> Result<Vec<u8>> {
        let alg = {
            let claim = self.provenance_claim().ok_or(Error::ClaimEncoding)?;
            if !matches!(claim.remote_manifest(), RemoteManifest::NoRemote)
                || claim.update_manifest()
                || claim.compressed()
                || !claim.hash_assertions().is_empty()
            {
                return Err(Error::NotImplemented(
                    "direct asset-io save currently supports new, embedded DataHash manifests only"
                        .to_string(),
                ));
            }
            claim.alg().to_owned()
        };

        let asset = DirectAssetIo::open(format, input_stream)?;
        let exclusion = asset.plan_manifest(input_stream)?;
        let placeholder_hash = data_hash_placeholder(&alg, exclusion)?;
        self.provenance_claim_mut()
            .ok_or(Error::ClaimEncoding)?
            .add_assertion(&placeholder_hash)?;

        let reserve_size = signer.reserve_size();
        let placeholder_store = self.to_jumbf_internal(reserve_size)?;
        let placeholder_store_len = placeholder_store.len();

        context.check_progress(ProgressPhase::Writing, 1, 2)?;
        let written_structure =
            asset.write_manifest(input_stream, output_stream, placeholder_store)?;
        context.check_progress(ProgressPhase::Writing, 2, 2)?;

        let data_hash = generate_data_hash(&written_structure, output_stream, &alg, context)?;
        self.provenance_claim_mut()
            .ok_or(Error::ClaimEncoding)?
            .update_data_hash(data_hash)?;

        let jumbf = self.to_jumbf_internal(reserve_size)?;
        if jumbf.len() != placeholder_store_len {
            return Err(Error::JumbfCreationError);
        }
        let signed_jumbf =
            self.sign_manifest_with_signer(context, signer, Some(placeholder_store_len))?;

        asset.patch_manifest(&written_structure, output_stream, &signed_jumbf)?;

        context.check_progress(ProgressPhase::Embedding, 1, 1)?;
        self.embedded = true;
        if context.settings().verify.verify_after_sign {
            let output_len = output_stream.seek(SeekFrom::End(0))?;
            output_stream.rewind()?;
            let validate_hash = context.settings().verify.verify_after_sign_hash;
            let mut asset_data = if output_len > 0 && validate_hash {
                Some(ClaimAssetData::Stream(output_stream, format))
            } else {
                None
            };
            self.verify_store_strict(asset_data.as_mut(), context)?;
            output_stream.rewind()?;
        }

        Ok(signed_jumbf)
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Seek};

    use crate::{
        assertions::{Action, Actions},
        claim::Claim,
        error::Error,
        store::Store,
        utils::{test::test_context, test_signer::test_signer},
        ClaimGeneratorInfo, DigitalSourceType, Reader, SigningAlg, ValidationState,
    };

    #[test]
    fn direct_asset_io_save_embeds_valid_manifests() {
        let fixtures = [
            (
                "image/jpeg",
                include_bytes!("../../tests/fixtures/earth_apollo17.jpg").as_slice(),
            ),
            (
                "image/png",
                include_bytes!("../../tests/fixtures/libpng-test.png").as_slice(),
            ),
        ];
        for (format, source) in fixtures {
            let context = test_context();
            let mut input = Cursor::new(source.to_vec());
            let mut output = Cursor::new(Vec::new());
            let mut store = Store::from_context(&context);

            let mut claim = Claim::new("direct asset-io", Some("direct_asset_io"), 1);
            let actions = Actions::new()
                .add_action(Action::new("c2pa.created").set_source_type(DigitalSourceType::Empty));
            claim.add_assertion(&actions).unwrap();
            claim.add_claim_generator_info(ClaimGeneratorInfo::new("asset_io_save_test"));
            store.commit_claim(claim).unwrap();

            let signer = test_signer(SigningAlg::Ps256);
            let manifest = store
                .save_to_stream_asset_io(format, &mut input, &mut output, signer.as_ref(), &context)
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
    fn direct_asset_io_save_rejects_non_embedded_modes() {
        let context = test_context();
        let mut input =
            Cursor::new(include_bytes!("../../tests/fixtures/earth_apollo17.jpg").to_vec());
        let mut output = Cursor::new(Vec::new());
        let mut store = Store::from_context(&context);
        let mut claim = Claim::new("direct asset-io", Some("direct_asset_io"), 1);
        claim.set_external_manifest();
        claim.add_claim_generator_info(ClaimGeneratorInfo::new("asset_io_save_test"));
        store.commit_claim(claim).unwrap();

        let signer = test_signer(SigningAlg::Ps256);
        let error = store
            .save_to_stream_asset_io(
                "image/jpeg",
                &mut input,
                &mut output,
                signer.as_ref(),
                &context,
            )
            .unwrap_err();
        assert!(matches!(error, Error::NotImplemented(_)));
    }
}
