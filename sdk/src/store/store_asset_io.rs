use std::io::{self, Read, Seek, SeekFrom};

use ::asset_io::{
    container_api::{Step, WritePlan},
    ByteRange, C2paHash, Chunk, HandlerRegistry, Item, Sink, Structure, Updates,
};

use crate::{
    assertion::AssertionBase,
    assertions::{BmffHash, BoxHash, BoxMap, DataHash},
    asset_handlers::asset_io_adapter::{box_map_from_structure, C2PA_STORE_UUID},
    asset_io::{ReadSeek, ReadWriteSeek},
    claim::{ClaimAssetData, RemoteManifest},
    context::{Context, ProgressPhase},
    error::{Error, Result},
    hash_utils::HashRange,
    store::Store,
    utils::{
        hash_utils::{hash_size_by_alg, Hasher},
        xmp_inmemory_utils::{add_provenance, extract_provenance, remove_provenance, MIN_XMP},
    },
};

const MANIFEST_PLACEHOLDER: &[u8] =
    b"\0\0\0\x26jumb\0\0\0\x1ejumd\x63\x32\x70\x61\0\x11\0\x10\x80\0\0\xaa\0\x38\x9b\x71\x03c2pa\0";
const DATA_HASH_NAME: &str = "jumbf manifest";

fn map_asset_io_error(error: ::asset_io::Error) -> Error {
    match error {
        ::asset_io::Error::Io(error) => Error::IoError(error),
        ::asset_io::Error::UserCanceled => Error::OperationCancelled,
        ::asset_io::Error::UnsupportedFormat => Error::UnsupportedType,
        ::asset_io::Error::UnsupportedFeature(feature) => {
            Error::NotImplemented(feature.to_string())
        }
        ::asset_io::Error::Ambiguous {
            what: "C2PA manifest store",
            ..
        } => Error::TooManyManifestStores,
        other => Error::InvalidAsset(other.to_string()),
    }
}

fn data_hash_exclusions(structure: &Structure, item: &Item) -> Result<Vec<HashRange>> {
    let ranges = structure
        .c2pa_data_hash_exclusions(item)
        .map_err(map_asset_io_error)?;
    if ranges.is_empty() {
        return Err(Error::EmbeddingError);
    }
    Ok(ranges
        .into_iter()
        .map(|range| HashRange::new(range.offset(), range.len()))
        .collect())
}

struct DataHashSink<'a> {
    hasher: Hasher,
    exclusions: Vec<ByteRange>,
    context: &'a Context,
    step: u32,
    progress_error: Option<Error>,
    offsets: Vec<u64>,
}

impl<'a> DataHashSink<'a> {
    fn new(alg: &str, context: &'a Context) -> Result<Self> {
        Ok(Self {
            hasher: Hasher::new(alg)?,
            exclusions: Vec::new(),
            context,
            step: 0,
            progress_error: None,
            offsets: Vec::new(),
        })
    }

    #[cfg(test)]
    fn into_data_hash(self, alg: &str) -> DataHash {
        let mut hash = DataHash::new(DATA_HASH_NAME, alg);
        for range in self.exclusions {
            hash.add_exclusion(HashRange::new(range.offset(), range.len()));
        }
        hash.set_hash(Hasher::finalize(self.hasher));
        hash
    }

    fn hash_bytes(&mut self, start: u64, bytes: &[u8]) {
        let end = start + bytes.len() as u64;
        let mut cursor = start;
        for &offset in &self.offsets {
            if offset < start || offset >= end {
                continue;
            }
            self.hasher
                .update(&bytes[(cursor - start) as usize..(offset - start) as usize]);
            self.hasher.update(&offset.to_be_bytes());
            cursor = offset;
        }
        self.hasher.update(&bytes[(cursor - start) as usize..]);
    }
}

impl Sink for DataHashSink<'_> {
    fn chunk(&mut self, chunk: Chunk<'_>) -> ::asset_io::Result<()> {
        self.step = self.step.saturating_add(1);
        if let Err(error) = self
            .context
            .check_progress(ProgressPhase::Hashing, self.step, 0)
        {
            self.progress_error = Some(error);
            return Err(::asset_io::Error::UserCanceled);
        }

        let start = chunk.offset;
        let end = start + chunk.data.len() as u64;
        let mut offset = start;
        let first = self
            .exclusions
            .partition_point(|range| range.end() <= start);
        for i in first..self.exclusions.len() {
            let range = self.exclusions[i];
            if range.offset() >= end {
                break;
            }
            if offset < range.offset() {
                self.hash_bytes(
                    offset,
                    &chunk.data[(offset - start) as usize..(range.offset() - start) as usize],
                );
            }
            offset = range.end().min(end);
        }
        if offset < end {
            self.hash_bytes(offset, &chunk.data[(offset - start) as usize..]);
        }
        Ok(())
    }
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
        Ok(Self { structure })
    }

    fn patch_manifest(
        &self,
        written: &Structure,
        output: &mut dyn ReadWriteSeek,
        store: &[u8],
    ) -> Result<()> {
        output.rewind()?;
        let mut output = output;
        let item = written
            .c2pa_item(&mut output)
            .map_err(map_asset_io_error)?
            .ok_or(Error::EmbeddingError)?;
        written
            .patch_exact(&mut output, item, store)
            .map_err(map_asset_io_error)?;
        output.flush()?;
        output.rewind()?;
        Ok(())
    }
}

fn data_hash_placeholder(alg: &str, exclusions: Vec<HashRange>) -> Result<DataHash> {
    let mut hash = DataHash::new(DATA_HASH_NAME, alg);
    for exclusion in exclusions {
        hash.add_exclusion(exclusion);
    }
    hash.set_hash(vec![0; hash_size_by_alg(alg)?]);
    hash.add_padding(vec![0; 10]);
    Ok(hash)
}

enum Binding {
    Data(DataHash),
    Boxes(BoxHash),
    Bmff(BmffHash),
}

struct HashTarget<'a> {
    range: ByteRange,
    sink: DataHashSink<'a>,
}

struct BindingBox {
    name: String,
    range: ByteRange,
    metadata: Vec<ByteRange>,
}

struct BindingSink<'a> {
    targets: Vec<HashTarget<'a>>,
}

impl Sink for BindingSink<'_> {
    fn chunk(&mut self, chunk: Chunk<'_>) -> ::asset_io::Result<()> {
        let end = chunk.offset + chunk.data.len() as u64;
        for target in &mut self.targets {
            let start = chunk.offset.max(target.range.offset());
            let end = end.min(target.range.end());
            if start < end {
                target.sink.chunk(Chunk::new(
                    chunk.segment,
                    chunk.role,
                    start,
                    &chunk.data[(start - chunk.offset) as usize..(end - chunk.offset) as usize],
                ))?;
            }
        }
        Ok(())
    }
}

impl Binding {
    fn assertion(&self) -> Result<crate::assertion::Assertion> {
        match self {
            Self::Data(hash) => hash.to_assertion(),
            Self::Boxes(hash) => hash.to_assertion(),
            Self::Bmff(hash) => hash.to_assertion(),
        }
    }

    fn prepare<'a>(
        &mut self,
        plan: &WritePlan<'_>,
        input: &mut dyn ReadSeek,
        alg: &str,
        context: &'a Context,
    ) -> Result<BindingSink<'a>> {
        let structure = plan.structure();
        let full = ByteRange::new(0, structure.total_size()).map_err(map_asset_io_error)?;
        let target = |range, alg: &str, exclusions: Vec<ByteRange>, offsets| {
            let mut sink = DataHashSink::new(alg, context)?;
            sink.exclusions = exclusions;
            sink.offsets = offsets;
            Ok::<_, Error>(HashTarget { range, sink })
        };
        let targets = match self {
            Self::Data(hash) => {
                let exclusions = match planned_store(plan, input)? {
                    Some(item) => data_hash_exclusions(structure, item)?,
                    None => Vec::new(),
                };
                hash.exclusions = (!exclusions.is_empty()).then_some(exclusions.clone());
                let alg = hash.alg.as_deref().unwrap_or(alg).to_owned();
                hash.set_hash(vec![0; hash_size_by_alg(&alg)?]);
                vec![target(
                    full,
                    &alg,
                    exclusions
                        .iter()
                        .map(|r| ByteRange::new(r.start(), r.length()).map_err(map_asset_io_error))
                        .collect::<Result<_>>()?,
                    Vec::new(),
                )?]
            }
            Self::Boxes(hash) => {
                let store = planned_store(plan, input)?;
                structure
                    .c2pa_boxes_with(store)
                    .map_err(map_asset_io_error)?;
                let mut reader = PlannedReader {
                    plan,
                    input,
                    position: 0,
                };
                // Reuse the SDK's structural map, including its established
                // overlapping ranges for expanded elements.
                let boxes = box_map_from_structure(structure, &mut reader, store)?
                    .into_iter()
                    .map(|c| {
                        let name = c.names.first().ok_or(Error::EmbeddingError)?.clone();
                        let range = ByteRange::new(c.range_start, c.range_len)
                            .map_err(map_asset_io_error)?;
                        let metadata = c
                            .allowed_exclusions
                            .iter()
                            .map(|ex| {
                                ByteRange::new(c.range_start + ex.start, ex.length)
                                    .map_err(map_asset_io_error)
                            })
                            .collect::<Result<_>>()?;
                        Ok(BindingBox {
                            name,
                            range,
                            metadata,
                        })
                    })
                    .collect::<Result<Vec<_>>>()?;
                if hash.boxes.is_empty() {
                    hash.boxes = boxes
                        .iter()
                        .map(|b| BoxMap {
                            names: vec![b.name.to_string()],
                            ..Default::default()
                        })
                        .collect();
                }
                let mut next = 0;
                let mut targets = Vec::new();
                for entry in &mut hash.boxes {
                    let end = next + entry.names.len();
                    let named = boxes.get(next..end).ok_or_else(|| {
                        Error::NotImplemented(
                            "requested box map does not match output boxes".into(),
                        )
                    })?;
                    if named.is_empty()
                        || !entry
                            .names
                            .iter()
                            .zip(named)
                            .all(|(name, b)| name == &b.name)
                    {
                        return Err(Error::NotImplemented(
                            "requested box map does not match output boxes".into(),
                        ));
                    }
                    let start = named[0].range.offset();
                    let end_offset = named[named.len() - 1].range.end();
                    entry.range_start = start;
                    entry.range_len = end_offset - start;
                    next = end;
                    if entry.names != ["C2PA"] && entry.names.iter().any(|name| name == "C2PA") {
                        return Err(Error::NotImplemented(
                            "the C2PA box must be listed separately".into(),
                        ));
                    }
                    if entry.exclusions.as_ref().is_some_and(Vec::is_empty) {
                        return Err(Error::BadParam("box exclusions must not be empty".into()));
                    }
                    if entry.names == ["C2PA"] || entry.excluded == Some(true) {
                        entry.hash = Vec::new().into();
                        continue;
                    }
                    let mut exclusions = Vec::new();
                    for ex in entry.exclusions.iter().flatten() {
                        let index = ex.box_index.unwrap_or(0);
                        if index < 0 || (ex.box_index.is_none() && named.len() != 1) {
                            return Err(Error::BadParam("invalid box exclusion index".into()));
                        }
                        let b = named
                            .get(index as usize)
                            .ok_or_else(|| Error::BadParam("invalid box exclusion index".into()))?;
                        let offset = b.range.offset().checked_add(ex.start).ok_or_else(|| {
                            Error::BadParam("box exclusion offset overflow".into())
                        })?;
                        let range =
                            ByteRange::new(offset, ex.length).map_err(map_asset_io_error)?;
                        if !b.metadata.iter().any(|m| m.contains(&range)) {
                            return Err(Error::BadParam(
                                "box exclusion must be within asset metadata".into(),
                            ));
                        }
                        exclusions.push(range);
                    }
                    normalize_ranges(&mut exclusions)?;
                    let alg = entry.alg.as_deref().unwrap_or(alg);
                    entry.hash = vec![0; hash_size_by_alg(alg)?].into();
                    targets.push(target(
                        ByteRange::new(start, end_offset - start).map_err(map_asset_io_error)?,
                        alg,
                        exclusions,
                        Vec::new(),
                    )?);
                }
                if next != boxes.len() {
                    return Err(Error::NotImplemented(
                        "requested box map does not cover output boxes".into(),
                    ));
                }
                targets
            }
            Self::Bmff(hash) => {
                let (exclusions, offsets) = bmff_ranges(plan, input, hash)?;
                let alg = hash.alg().map(String::as_str).unwrap_or(alg).to_owned();
                hash.set_hash(vec![0; hash_size_by_alg(&alg)?]);
                vec![target(full, &alg, exclusions, offsets)?]
            }
        };
        Ok(BindingSink { targets })
    }

    fn finish(&mut self, sink: BindingSink<'_>) {
        let mut hashes = sink
            .targets
            .into_iter()
            .map(|target| Hasher::finalize(target.sink.hasher));
        match self {
            Self::Data(hash) => hash.set_hash(hashes.next().unwrap_or_default()),
            Self::Bmff(hash) => hash.set_hash(hashes.next().unwrap_or_default()),
            Self::Boxes(hash) => {
                for entry in &mut hash.boxes {
                    if entry.names != ["C2PA"] && entry.excluded != Some(true) {
                        entry.hash = hashes.next().unwrap_or_default().into();
                    }
                }
            }
        }
    }
}

fn normalize_ranges(ranges: &mut Vec<ByteRange>) -> Result<()> {
    ranges.sort_by_key(ByteRange::offset);
    let mut merged: Vec<ByteRange> = Vec::new();
    for range in ranges.drain(..) {
        if range.is_empty() {
            continue;
        }
        if let Some(last) = merged.last_mut() {
            if range.offset() <= last.end() {
                *last = ByteRange::new(last.offset(), last.end().max(range.end()) - last.offset())
                    .map_err(map_asset_io_error)?;
                continue;
            }
        }
        merged.push(range);
    }
    *ranges = merged;
    Ok(())
}

fn planned_store<'a>(
    plan: &'a WritePlan<'_>,
    input: &mut dyn ReadSeek,
) -> Result<Option<&'a Item>> {
    let mut reader = PlannedReader {
        plan,
        input,
        position: 0,
    };
    plan.structure()
        .c2pa_item(&mut reader)
        .map_err(map_asset_io_error)
}

/// A bounded view of planned bytes for structural walks and selector predicates.
/// Payload is never copied: only the ranges requested by the walker are read.
struct PlannedReader<'a, 'p> {
    plan: &'a WritePlan<'p>,
    input: &'a mut dyn ReadSeek,
    position: u64,
}

impl Read for PlannedReader<'_, '_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut offset = 0;
        for step in self.plan.steps() {
            let end = offset + step.len();
            if self.position < end {
                let relative = self.position - offset;
                let len = (buf.len() as u64).min(end - self.position) as usize;
                let n = match step {
                    Step::Copy { src, .. } | Step::Relocate { src, .. } => {
                        self.input.seek(SeekFrom::Start(src.offset() + relative))?;
                        self.input.read(&mut buf[..len])?
                    }
                    Step::Put { data, .. } => {
                        buf[..len]
                            .copy_from_slice(&data[relative as usize..relative as usize + len]);
                        len
                    }
                    _ => {
                        return Err(io::Error::new(
                            io::ErrorKind::Unsupported,
                            "unsupported write-plan step",
                        ))
                    }
                };
                self.position += n as u64;
                return Ok(n);
            }
            offset = end;
        }
        Ok(0)
    }
}

impl Seek for PlannedReader<'_, '_> {
    fn seek(&mut self, from: SeekFrom) -> io::Result<u64> {
        let position = match from {
            SeekFrom::Start(offset) => i128::from(offset),
            SeekFrom::Current(offset) => i128::from(self.position) + i128::from(offset),
            SeekFrom::End(offset) => {
                i128::from(self.plan.structure().total_size()) + i128::from(offset)
            }
        };
        self.position = u64::try_from(position)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid planned seek"))?;
        Ok(self.position)
    }
}

fn bmff_ranges(
    plan: &WritePlan<'_>,
    input: &mut dyn ReadSeek,
    hash: &BmffHash,
) -> Result<(Vec<ByteRange>, Vec<u64>)> {
    let mut reader = PlannedReader {
        plan,
        input,
        position: 0,
    };
    let mut nodes = Vec::new();
    plan.structure()
        .walk(&mut reader, |node| {
            nodes.push((
                node.path.to_string(),
                node.range,
                node.version,
                node.flags,
                node.depth,
            ));
            Ok(())
        })
        .map_err(map_asset_io_error)?;
    let mut offsets: Vec<u64> = nodes
        .iter()
        .filter(|n| n.4 == 1)
        .map(|n| n.1.offset())
        .collect();
    let mut ranges = Vec::new();
    for ex in hash.exclusions() {
        if ex.xpath.contains('[') {
            return Err(Error::NotImplemented(
                "indexed BMFF exclusion selectors".into(),
            ));
        }
        for (path, range, version, flags, _) in &nodes {
            if path != &ex.xpath
                || ex.length.is_some_and(|len| len != range.len())
                || ex.version.zip(*version).is_some_and(|(a, b)| a != b)
            {
                continue;
            }
            if let Some(want) = &ex.flags {
                let mut bytes = [0; 4];
                if want.len() >= 3 {
                    bytes[..3].copy_from_slice(&want[..3]);
                }
                let want = u32::from_be_bytes(bytes);
                if flags.is_some_and(|actual| {
                    if ex.exact.unwrap_or(true) {
                        actual != want
                    } else {
                        (want | actual) != want
                    }
                }) {
                    continue;
                }
            }
            let mut matches = true;
            for data in ex.data.iter().flatten() {
                let start = range
                    .offset()
                    .checked_add(data.offset)
                    .ok_or_else(|| Error::BadParam("BMFF predicate offset overflow".into()))?;
                let end = start
                    .checked_add(data.value.len() as u64)
                    .ok_or_else(|| Error::BadParam("BMFF predicate length overflow".into()))?;
                if end > plan.structure().total_size() {
                    return Err(Error::BadParam("BMFF predicate past end of asset".into()));
                }
                // Walkers can read ahead across tables without interpreting them.
                // Predicates, however, must not compare stale source offsets.
                let mut offset = 0;
                for step in plan.steps() {
                    let step_end = offset + step.len();
                    if matches!(step, Step::Relocate { .. }) && start < step_end && end > offset {
                        return Err(Error::NotImplemented(
                            "BMFF predicate over relocated offset-table bytes".into(),
                        ));
                    }
                    offset = step_end;
                }
                reader.seek(SeekFrom::Start(start))?;
                let mut actual = vec![0; data.value.len()];
                reader.read_exact(&mut actual)?;
                if actual != data.value {
                    matches = false;
                    break;
                }
            }
            if !matches {
                continue;
            }
            if let Some(subsets) = &ex.subset {
                for subset in subsets {
                    if subset.offset > range.len() {
                        continue;
                    }
                    let available = range.len() - subset.offset;
                    let len = if subset.length == 0 {
                        available
                    } else {
                        available.min(subset.length)
                    };
                    ranges.push(
                        ByteRange::new(range.offset() + subset.offset, len)
                            .map_err(map_asset_io_error)?,
                    );
                }
            } else {
                ranges.push(*range);
                offsets.retain(|offset| *offset != range.offset());
            }
        }
    }
    normalize_ranges(&mut ranges)?;
    if hash.bmff_version() < 2 {
        offsets.clear();
    }
    offsets.sort_unstable();
    Ok((ranges, offsets))
}

impl Store {
    fn save_unhandled_sidecar(
        &mut self,
        format: &str,
        input: &mut dyn ReadSeek,
        output: &mut dyn ReadWriteSeek,
        binding: Option<Binding>,
        context: &Context,
    ) -> Result<Vec<u8>> {
        let claim = self.provenance_claim().ok_or(Error::ClaimEncoding)?;
        let existing = binding.is_some();
        let mut hash = match binding {
            Some(Binding::Data(hash)) => hash,
            None => DataHash::new(DATA_HASH_NAME, claim.alg()),
            _ => {
                return Err(Error::NotImplemented(
                    "unstructured assets require a data hash".into(),
                ))
            }
        };
        hash.exclusions = None;
        let alg = hash.alg.as_deref().unwrap_or(claim.alg());
        let mut sink = DataHashSink::new(alg, context)?;
        let segment = ::asset_io::SegmentId::from_index(0).map_err(map_asset_io_error)?;
        context.check_progress(ProgressPhase::Writing, 1, 2)?;
        input.rewind()?;
        output.rewind()?;
        let mut bytes = vec![0; 64 * 1024];
        let mut offset = 0;
        loop {
            let len = input.read(&mut bytes)?;
            if len == 0 {
                break;
            }
            output.write_all(&bytes[..len])?;
            sink.chunk(Chunk::new(
                segment,
                ::asset_io::Role::Payload,
                offset,
                &bytes[..len],
            ))
            .map_err(|error| {
                sink.progress_error
                    .take()
                    .unwrap_or_else(|| map_asset_io_error(error))
            })?;
            offset += len as u64;
        }
        output.flush()?;
        context.check_progress(ProgressPhase::Writing, 2, 2)?;
        hash.set_hash(Hasher::finalize(sink.hasher));
        let claim = self.provenance_claim_mut().ok_or(Error::ClaimEncoding)?;
        if existing {
            claim.replace_assertion(hash.to_assertion()?)?;
        } else {
            claim.add_assertion(&hash)?;
        }
        let manifest = self.sign_manifest(context, None)?;
        self.embedded = false;
        output.rewind()?;
        if context.settings().verify.verify_after_sign {
            let mut asset = context
                .settings()
                .verify
                .verify_after_sign_hash
                .then_some(ClaimAssetData::Stream(output, format));
            self.verify_store_strict(asset.as_mut(), context)?;
            output.rewind()?;
        }
        Ok(manifest)
    }

    /// Writes and hashes the asset into an empty output in one pass, then signs
    /// with the context's signer. Only embedded stores are patched; detached
    /// manifest bytes are returned for the caller to persist or upload.
    /// Optional post-sign verification may reread the output.
    pub(crate) fn save_to_stream_asset_io(
        &mut self,
        format: &str,
        mut input_stream: &mut dyn ReadSeek,
        mut output_stream: &mut dyn ReadWriteSeek,
        context: &Context,
    ) -> Result<Vec<u8>> {
        let reserve_size = context.signer()?.reserve_size();
        let (alg, embed, remote_url, mut binding, existing) = {
            let claim = self.provenance_claim().ok_or(Error::ClaimEncoding)?;
            if claim.update_manifest() || claim.compressed() {
                return Err(Error::NotImplemented(
                    "direct asset-io save does not support update or compressed manifests".into(),
                ));
            }
            let (embed, remote_url) = match claim.remote_manifest() {
                RemoteManifest::NoRemote => (true, None),
                RemoteManifest::SideCar => (false, None),
                RemoteManifest::Remote(url) => (false, Some(url)),
                RemoteManifest::EmbedWithRemote(url) => (true, Some(url)),
            };
            let hashes = claim.hash_assertions();
            if hashes.len() > 1 {
                return Err(Error::BadParam(
                    "exactly one hard binding is supported".into(),
                ));
            }
            let binding = if let Some(assertion) = claim.data_hash_assertions().first() {
                let hash = DataHash::from_assertion(assertion.assertion())?;
                if hash.is_remote_hash() {
                    return Err(Error::NotImplemented("remote data hash".into()));
                }
                Some(Binding::Data(hash))
            } else if let Some(assertion) = claim.box_hash_assertions().first() {
                Some(Binding::Boxes(BoxHash::from_assertion(
                    assertion.assertion(),
                )?))
            } else if let Some(assertion) = claim.bmff_hash_assertions().first() {
                let hash = BmffHash::from_assertion(assertion.assertion())?;
                if hash.is_remote_hash() || hash.merkle().is_some() {
                    return Err(Error::NotImplemented(
                        "remote or Merkle BMFF binding".into(),
                    ));
                }
                Some(Binding::Bmff(hash))
            } else if hashes.is_empty() {
                None
            } else {
                return Err(Error::NotImplemented("unsupported hard binding".into()));
            };
            (
                claim.alg().to_owned(),
                embed,
                remote_url,
                binding,
                !hashes.is_empty(),
            )
        };

        if HandlerRegistry::builtin().handler(format).is_none() {
            if remote_url.is_some() {
                return Err(Error::XmpNotSupported);
            }
            if embed {
                return Err(Error::UnsupportedType);
            }
            return self.save_unhandled_sidecar(
                format,
                input_stream,
                output_stream,
                binding,
                context,
            );
        }
        let asset = DirectAssetIo::open(format, input_stream)?;
        let recommended = asset.structure.c2pa_hash();
        if embed && recommended.is_none() {
            return Err(Error::UnsupportedType);
        }
        let mut binding = match binding.take() {
            Some(binding) => binding,
            None => match recommended {
                Some(C2paHash::Bmff) => {
                    if context
                        .settings()
                        .core
                        .merkle_tree_chunk_size_in_kb
                        .is_some()
                    {
                        return Err(Error::NotImplemented(
                            "streaming BMFF Merkle generation".into(),
                        ));
                    }
                    let mut hash = BmffHash::new(DATA_HASH_NAME, &alg, None);
                    hash.set_default_exclusions_with_options(context.settings());
                    let claim = self.provenance_claim().ok_or(Error::ClaimEncoding)?;
                    if claim.version() < 2 {
                        hash.set_bmff_version(2);
                    }
                    Binding::Bmff(hash)
                }
                Some(C2paHash::Box) => Binding::Boxes(BoxHash { boxes: Vec::new() }),
                _ => Binding::Data(data_hash_placeholder(&alg, Vec::new())?),
            },
        };
        if matches!(binding, Binding::Bmff(_)) && recommended != Some(C2paHash::Bmff) {
            return Err(Error::NotImplemented(
                "BMFF binding requires a BMFF structure".into(),
            ));
        }
        if matches!(binding, Binding::Boxes(_)) && recommended == Some(C2paHash::Bmff) {
            return Err(Error::NotImplemented(
                "BMFF requires the BMFF hard binding".into(),
            ));
        }

        let mut updates = Updates::new().remove_jumbf_of(C2PA_STORE_UUID);
        let mut expected_xmp = None;
        let xmp = asset
            .structure
            .xmp(&mut input_stream)
            .map_err(map_asset_io_error)?;
        if remote_url.is_some()
            || xmp.as_ref().is_some_and(|xmp| {
                std::str::from_utf8(xmp)
                    .ok()
                    .and_then(extract_provenance)
                    .is_some()
            })
        {
            let packet = match xmp.as_deref() {
                Some(bytes) => {
                    std::str::from_utf8(bytes).map_err(|e| Error::XmpWriteError(e.to_string()))?
                }
                None => MIN_XMP,
            };
            let packet = if let Some(url) = remote_url {
                add_provenance(packet, &url)?
            } else {
                remove_provenance(packet)?
            };
            let packet = packet.into_bytes();
            updates = updates.set_xmp(packet.clone());
            expected_xmp = Some(packet);
        }
        if embed {
            updates = updates.set_jumbf(MANIFEST_PLACEHOLDER.to_vec());
        }
        let plan = asset
            .structure
            .write_plan(&mut input_stream, &updates)
            .map_err(|error| match error {
                ::asset_io::Error::UnsupportedFeature(feature)
                    if expected_xmp.is_some() && feature.to_ascii_lowercase().contains("xmp") =>
                {
                    Error::XmpNotSupported
                }
                ::asset_io::Error::UnsupportedFormat if expected_xmp.is_some() => {
                    Error::XmpNotSupported
                }
                other => map_asset_io_error(other),
            })?;
        if let Some(expected) = expected_xmp {
            let mut reader = PlannedReader {
                plan: &plan,
                input: input_stream,
                position: 0,
            };
            let actual = plan
                .structure()
                .xmp(&mut reader)
                .map_err(map_asset_io_error)?;
            if actual.as_deref() != Some(expected.as_slice()) {
                return Err(Error::XmpNotSupported);
            }
        }
        binding.prepare(&plan, input_stream, &alg, context)?;
        let assertion = binding.assertion()?;
        let claim = self.provenance_claim_mut().ok_or(Error::ClaimEncoding)?;
        if existing {
            claim.replace_assertion(assertion)?;
        } else {
            match &binding {
                Binding::Data(hash) => {
                    claim.add_assertion(hash)?;
                }
                Binding::Boxes(hash) => {
                    claim.add_assertion(hash)?;
                }
                Binding::Bmff(hash) => {
                    claim.add_assertion(hash)?;
                }
            }
        }

        // Absolute DataHash offsets can change CBOR integer widths. Settle the
        // manifest's size before writing, without ever copying the asset.
        let mut placeholder_store = self.to_jumbf_internal(reserve_size)?;
        if embed {
            let mut settled = false;
            for _ in 0..8 {
                updates = updates.set_jumbf(placeholder_store.clone());
                let plan = asset
                    .structure
                    .write_plan(&mut input_stream, &updates)
                    .map_err(map_asset_io_error)?;
                binding.prepare(&plan, input_stream, &alg, context)?;
                self.provenance_claim_mut()
                    .ok_or(Error::ClaimEncoding)?
                    .replace_assertion(binding.assertion()?)?;
                let next = self.to_jumbf_internal(reserve_size)?;
                settled = next.len() == placeholder_store.len();
                placeholder_store = next;
                if settled {
                    break;
                }
            }
            if !settled {
                return Err(Error::JumbfCreationError);
            }
            updates = updates.set_jumbf(placeholder_store.clone());
        }
        let placeholder_store_len = placeholder_store.len();
        let plan = asset
            .structure
            .write_plan(&mut input_stream, &updates)
            .map_err(map_asset_io_error)?;
        let mut sink = binding.prepare(&plan, input_stream, &alg, context)?;

        context.check_progress(ProgressPhase::Writing, 1, 2)?;
        input_stream.rewind()?;
        output_stream.rewind()?;
        plan.execute(&mut input_stream, &mut output_stream, &mut sink)
            .map_err(|error| {
                sink.targets
                    .iter_mut()
                    .find_map(|target| target.sink.progress_error.take())
                    .unwrap_or_else(|| map_asset_io_error(error))
            })?;
        output_stream.flush()?;
        context.check_progress(ProgressPhase::Writing, 2, 2)?;
        binding.finish(sink);
        self.provenance_claim_mut()
            .ok_or(Error::ClaimEncoding)?
            .replace_assertion(binding.assertion()?)?;

        let jumbf = self.to_jumbf_internal(reserve_size)?;
        if embed && jumbf.len() != placeholder_store_len {
            return Err(Error::JumbfCreationError);
        }
        let signed_jumbf = self.sign_manifest(context, embed.then_some(placeholder_store_len))?;

        if embed {
            asset.patch_manifest(plan.structure(), output_stream, &signed_jumbf)?;
            context.check_progress(ProgressPhase::Embedding, 1, 1)?;
        }
        self.embedded = embed;
        output_stream.rewind()?;
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
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};

    use ::asset_io::{ByteRange, Chunk, Role, Sink};

    use super::{data_hash_placeholder, DataHashSink, DirectAssetIo};
    use crate::{
        assertion::AssertionBase,
        assertions::{Action, Actions, BmffHash, BoxHash, DataHash},
        claim::Claim,
        error::Error,
        hash_utils::HashRange,
        store::Store,
        utils::{hash_utils::hash_by_alg, test::test_context, test_signer::test_signer},
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
            .items_of(::asset_io::ItemKind::Jumbf)
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
                .save_to_stream_asset_io(format, &mut Cursor::new(source), &mut output, &context)
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
                    .unwrap_or_else(|error| panic!("{format}/{mode}: {error}"));
                output.stream.rewind().unwrap();
                let structure = handler.clone().parse(&mut output.stream).unwrap();
                assert_forward_write(&output, &structure, embed);
                assert_eq!(
                    structure
                        .item(::asset_io::ItemKind::Jumbf)
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
            "multiple",
            "collection",
            "compressed",
            "update",
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
                "compressed" => claim.set_compressed_manifest(true),
                "update" => claim.set_update_manifest(true),
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
                &context,
            );
            assert!(result.is_err(), "{kind}: expected an error");
            let error = result.err().unwrap();
            match kind {
                "unknown_embed" | "pdf" => {
                    assert!(matches!(error, Error::UnsupportedType), "{kind}: {error}")
                }
                "unknown_remote" => assert!(matches!(error, Error::XmpNotSupported), "{error}"),
                "multiple" => assert!(matches!(error, Error::BadParam(_)), "{error}"),
                _ => assert!(matches!(error, Error::NotImplemented(_)), "{kind}: {error}"),
            }
            assert!(output.writes.is_empty(), "{kind} wrote before rejection");
        }
    }

    #[test]
    fn direct_asset_io_preserves_unrelated_jumbf() {
        let context = test_context().with_signer(test_signer(SigningAlg::Ed25519));
        let mut other = super::MANIFEST_PLACEHOLDER.to_vec();
        other[16..20].copy_from_slice(b"test");
        let mut input = Cursor::new(FIXTURES[0].1);
        let handler = ::asset_io::HandlerRegistry::builtin()
            .handler("image/jpeg")
            .unwrap()
            .clone();
        let structure = handler.clone().parse(&mut input).unwrap();
        let mut seeded = Cursor::new(Vec::new());
        structure
            .write(
                &mut input,
                &mut seeded,
                &::asset_io::Updates::new().set_jumbf(other.clone()),
                &mut ::asset_io::NullSink,
            )
            .unwrap();
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
        assert!(structure.c2pa_item(&mut output).unwrap().is_none());
        let item = structure.require_item(::asset_io::ItemKind::Jumbf).unwrap();
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
                .find(|segment| structure.box_name(segment.name()).as_deref() == Some("free"))
                .unwrap();
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
        use crate::assertions::{DataMap, ExclusionsMap};
        for kind in ["merkle", "indexed", "relocated"] {
            let context = test_context().with_signer(test_signer(SigningAlg::Ed25519));
            let mut store = unsigned_store(&context);
            let mut hash = BmffHash::new("requested", "sha256", None);
            hash.set_default_exclusions_with_options(context.settings());
            match kind {
                "merkle" => hash.set_merkle(Vec::new()),
                "indexed" => {
                    hash.add_exclusions(&mut vec![ExclusionsMap::new("/moov/trak[1]".into())])
                }
                _ => {
                    let mut ex = ExclusionsMap::new("/moov/trak/mdia/minf/stbl/stco".into());
                    ex.data = Some(vec![DataMap {
                        offset: 16,
                        value: vec![0; 4],
                    }]);
                    hash.add_exclusions(&mut vec![ex]);
                }
            }
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
            assert!(matches!(result, Err(Error::NotImplemented(_))), "{kind}");
            assert!(output.writes.is_empty(), "{kind}");
        }
    }

    #[test]
    fn direct_asset_io_requested_box_algorithms_and_excluded_boxes_are_preserved() {
        let context = test_context().with_signer(test_signer(SigningAlg::Ed25519));
        let (format, source) = FIXTURES[0];
        let mut first = unsigned_store(&context);
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
                .save_to_stream_asset_io(format, &mut input, &mut output, &context)
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
                .save_to_stream_asset_io(format, &mut input, &mut output, &context)
                .unwrap_or_else(|error| panic!("{format}: {error}"));

            let handler = ::asset_io::HandlerRegistry::builtin()
                .handler(format)
                .unwrap()
                .clone();
            output.stream.rewind().unwrap();
            let structure = handler.parse(&mut output.stream).unwrap();
            let item = structure.c2pa_item(&mut output.stream).unwrap().unwrap();
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
    fn direct_asset_io_sink_hashes_chunk_boundaries_and_disjoint_exclusions() {
        let handler = ::asset_io::HandlerRegistry::builtin()
            .handler("image/jpeg")
            .unwrap()
            .clone();
        let structure = handler
            .parse(&mut Cursor::new(include_bytes!(
                "../../tests/fixtures/CA.jpg"
            )))
            .unwrap();
        let segment = structure
            .require_item(::asset_io::ItemKind::Jumbf)
            .unwrap()
            .extents()
            .next()
            .unwrap()
            .segment();
        let data: Vec<u8> = (0..40).collect();
        let ranges = [(0, 3), (7, 4), (16, 5), (29, 3)];
        let context = test_context();
        for alg in ["sha256", "sha384", "sha512"] {
            for chunk_size in [1, 3, 7, 40] {
                let mut sink = DataHashSink::new(alg, &context).unwrap();
                sink.exclusions = ranges
                    .iter()
                    .map(|&(start, len)| ByteRange::new(start, len).unwrap())
                    .collect();
                let exclusions = ranges
                    .iter()
                    .map(|&(start, len)| HashRange::new(start, len))
                    .collect();
                for (i, chunk) in data.chunks(chunk_size).enumerate() {
                    sink.chunk(Chunk::new(
                        segment,
                        Role::Payload,
                        (i * chunk_size) as u64,
                        chunk,
                    ))
                    .unwrap();
                }
                let hash = sink.into_data_hash(alg);
                assert_eq!(
                    hash.hash,
                    hash_by_alg(alg, &data, Some(exclusions)),
                    "{alg}: chunk size {chunk_size}"
                );
            }
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

    #[test]
    fn direct_asset_io_rejects_noncontiguous_manifest_segments() {
        let handler = ::asset_io::HandlerRegistry::builtin()
            .handler("image/jpeg")
            .unwrap()
            .clone();
        let mut input = Cursor::new(include_bytes!("../../tests/fixtures/CA.jpg").to_vec());
        let structure = handler.clone().parse(&mut input).unwrap();
        let item = structure.c2pa_item(&mut input).unwrap().unwrap();
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
            DirectAssetIo::open("image/jpeg", &mut input),
            Err(Error::InvalidAsset(message))
                if message.contains("JUMBF APP11 segments are not contiguous")
        ));
    }

    #[test]
    fn direct_asset_io_placeholder_preserves_multiple_exclusions() {
        let exclusions = vec![HashRange::new(10, 10), HashRange::new(30, 10)];
        let mut hash = data_hash_placeholder("sha256", exclusions.clone()).unwrap();
        assert_eq!(hash.exclusions.as_ref(), Some(&exclusions));
        let mut input = Cursor::new(vec![0; 50]);
        hash.gen_hash_from_stream(&mut input).unwrap();
        input.rewind().unwrap();
        hash.verify_stream_hash(&mut input, Some("sha256")).unwrap();
        input.get_mut()[10] ^= 1;
        input.get_mut()[30] ^= 1;
        input.rewind().unwrap();
        hash.verify_stream_hash(&mut input, Some("sha256")).unwrap();
        input.get_mut()[25] ^= 1;
        input.rewind().unwrap();
        assert!(hash.verify_stream_hash(&mut input, Some("sha256")).is_err());
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
                            .item(::asset_io::ItemKind::Jumbf)
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
                        "default" if matches!(format, "image/jpeg" | "image/png") => {
                            assert_eq!(claim.box_hash_assertions().len(), 1)
                        }
                        _ => {}
                    }
                }
            }
        }
    }
}
