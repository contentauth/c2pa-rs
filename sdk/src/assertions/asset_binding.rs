// Copyright 2026 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

// Unless required by applicable law or agreed to in writing,
// this software is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR REPRESENTATIONS OF ANY KIND, either express or
// implied. See the LICENSE-MIT and LICENSE-APACHE files for the
// specific language governing permissions and limitations under
// each license.

//! Hard bindings over an asset-io write plan.
//!
//! Each hard-binding assertion builds itself from the planned output's structure
//! ([`AssetBinding::plan_hashes`]) and reduces to a list of [`HashSpan`]s. One
//! [`SpanHasher`] sink hashes every span while the plan is executed, so the asset
//! is written and hashed in a single pass, and the digests go back to the
//! assertion ([`AssetBinding::set_hashes`]).
//!
//! Nothing here names a binding. Each assertion registers a [`BindingKind`] in its
//! own module; [`BINDINGS`] only lists them in the order a default is chosen.

use ::asset_io::{
    plan::{PlanReader, WritePlan},
    ByteRange, Chunk, Item, Sink, Structure,
};

use crate::{
    assertion::{Assertion, AssertionBase},
    asset_io::ReadSeek,
    claim::Claim,
    context::{Context, ProgressPhase},
    error::{Error, Result},
    maybe_send_sync::MaybeSend,
    utils::hash_utils::Hasher,
};

/// Bytes of the output to hash into one digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HashSpan {
    /// The bytes to hash.
    pub range: ByteRange,
    /// Bytes inside `range` left out of the hash: sorted, disjoint and nonadjacent.
    pub exclusions: Vec<ByteRange>,
    /// Offsets inside `range` whose big-endian 8-byte value is hashed just before
    /// the byte there (BMFF hash v2 hashes each top-level box's offset).
    pub offsets: Vec<u64>,
    /// The hash algorithm.
    pub alg: String,
}

impl HashSpan {
    /// A span hashing all of `range` with `alg`.
    pub fn new(range: ByteRange, alg: &str) -> Self {
        Self {
            range,
            exclusions: Vec::new(),
            offsets: Vec::new(),
            alg: alg.to_owned(),
        }
    }

    /// Leave `exclusions` out of the hash; they are sorted and merged.
    pub fn excluding(mut self, mut exclusions: Vec<ByteRange>) -> Result<Self> {
        normalize_ranges(&mut exclusions)?;
        self.exclusions = exclusions;
        Ok(self)
    }

    /// Hash each of `offsets` before the byte there.
    pub fn with_offsets(mut self, mut offsets: Vec<u64>) -> Self {
        offsets.sort_unstable();
        self.offsets = offsets;
        self
    }
}

/// The planned output of a write, as a binding sees it: its structure, its
/// manifest store, and its bytes, read without writing anything.
pub(crate) struct PlannedAsset<'p, 'a> {
    plan: &'p WritePlan<'a>,
    store: Option<&'p Item>,
    reader: PlanReader<'p, 'a, &'p mut dyn ReadSeek>,
}

impl<'p, 'a> PlannedAsset<'p, 'a> {
    /// The output of `plan`, whose source is `input`.
    pub fn new(plan: &'p WritePlan<'a>, input: &'p mut dyn ReadSeek) -> Result<Self> {
        Ok(Self {
            store: plan
                .structure()
                .c2pa_item()
                .map_err(crate::asset_handlers::asset_io_adapter::store_err)?,
            reader: plan.reader(input),
            plan,
        })
    }

    /// The structure of the output.
    pub fn structure(&self) -> &'p Structure {
        self.plan.structure()
    }

    /// The C2PA manifest store the output holds, if it embeds one.
    pub fn store(&self) -> Option<&'p Item> {
        self.store
    }

    /// The output's bytes. Only what is read is fetched from the source.
    pub fn reader(&mut self) -> &mut PlanReader<'p, 'a, &'p mut dyn ReadSeek> {
        &mut self.reader
    }

    /// The whole output.
    pub fn full_range(&self) -> Result<ByteRange> {
        ByteRange::new(0, self.structure().total_size()).map_err(asset_io_error)
    }
}

/// A hard-binding assertion that can bind an asset-io planned output. It is
/// held across the async signing await, so it must be `Send` where futures are.
pub(crate) trait AssetBinding: MaybeSend {
    /// The assertion as it now stands.
    fn assertion(&self) -> Result<Assertion>;

    /// Fails if this binding cannot bind an asset of this structure. Checked
    /// before anything is planned or written.
    fn check_structure(&self, structure: &Structure) -> Result<()>;

    /// Fill in the ranges this binding records for `asset`, with placeholder
    /// hashes of the final size, and return the spans to hash, in the order
    /// [`set_hashes`](Self::set_hashes) takes their digests.
    fn plan_hashes(
        &mut self,
        asset: &mut PlannedAsset<'_, '_>,
        default_alg: &str,
    ) -> Result<Vec<HashSpan>>;

    /// Store the digests of the spans [`plan_hashes`](Self::plan_hashes) returned.
    fn set_hashes(&mut self, digests: Vec<Vec<u8>>);

    /// Make the assertion exactly `len` bytes, the size it had when the store's
    /// size was fixed. A binding whose size never changes only checks it.
    fn fit_to_size(&mut self, len: usize) -> Result<()> {
        if self.assertion()?.data().len() == len {
            Ok(())
        } else {
            Err(Error::JumbfCreationError)
        }
    }

    /// Whether the hashes depend on where the manifest store is and how large it
    /// is. A binding that does not can be signed with a store of any size, such as
    /// a compressed one, without settling the store's size first.
    fn depends_on_store_size(&self) -> bool {
        true
    }
}

/// A hard binding the caller already computed, signed unchanged as
/// `save_to_stream` signs it: nothing is hashed for it.
pub(crate) struct SuppliedBinding {
    assertion: Assertion,
    depends_on_store_size: bool,
}

impl SuppliedBinding {
    pub fn new(assertion: Assertion, depends_on_store_size: bool) -> Self {
        Self {
            assertion,
            depends_on_store_size,
        }
    }
}

impl AssetBinding for SuppliedBinding {
    fn assertion(&self) -> Result<Assertion> {
        Ok(self.assertion.clone())
    }

    fn check_structure(&self, _structure: &Structure) -> Result<()> {
        Ok(())
    }

    fn plan_hashes(
        &mut self,
        _asset: &mut PlannedAsset<'_, '_>,
        _default_alg: &str,
    ) -> Result<Vec<HashSpan>> {
        Ok(Vec::new())
    }

    fn set_hashes(&mut self, _digests: Vec<Vec<u8>>) {}

    fn depends_on_store_size(&self) -> bool {
        self.depends_on_store_size
    }
}

/// Whether `hash` holds a computed hash rather than a placeholder (empty or all
/// zeros), so its binding is signed as given.
pub(crate) fn is_computed(hash: &[u8]) -> bool {
    hash.iter().any(|&b| b != 0)
}

/// A binding, if one applies.
pub(crate) type MaybeBinding = Result<Option<Box<dyn AssetBinding>>>;

/// How one kind of hard binding is found in a claim and chosen by default. Each
/// assertion defines its own.
pub(crate) struct BindingKind {
    /// The claim's binding of this kind, if it has one, checked for what direct
    /// saving supports.
    pub from_claim: fn(&Claim) -> MaybeBinding,
    /// A new binding of this kind for a structure, using the context's settings,
    /// the claim and the default algorithm, if it is the right default.
    pub default_for: fn(&Structure, &Context, &Claim, &str) -> MaybeBinding,
}

/// Every binding direct saving supports, in the order a default is chosen: the
/// most specific first.
pub(crate) const BINDINGS: &[&BindingKind] = &[
    &crate::assertions::BmffHash::BINDING,
    &crate::assertions::BoxHash::BINDING,
    &crate::assertions::DataHash::BINDING,
];

/// The claim's hard binding, if any. More than one, or one direct saving does not
/// support, is an error.
pub(crate) fn binding_from_claim(claim: &Claim) -> MaybeBinding {
    let count = claim.hash_assertions().len();
    if count > 1 {
        return Err(Error::BadParam(
            "exactly one hard binding is supported".into(),
        ));
    }
    for kind in BINDINGS {
        if let Some(binding) = (kind.from_claim)(claim)? {
            return Ok(Some(binding));
        }
    }
    if count == 0 {
        Ok(None)
    } else {
        Err(Error::NotImplemented("unsupported hard binding".into()))
    }
}

/// The binding to use for `structure` when the claim has none.
pub(crate) fn default_binding(
    structure: &Structure,
    context: &Context,
    claim: &Claim,
    alg: &str,
) -> Result<Box<dyn AssetBinding>> {
    for kind in BINDINGS {
        if let Some(binding) = (kind.default_for)(structure, context, claim, alg)? {
            return Ok(binding);
        }
    }
    Err(Error::UnsupportedType)
}

/// An already-built [`Assertion`], to add to a claim whose binding type is only
/// known at run time.
pub(crate) struct BuiltAssertion {
    assertion: Assertion,
    label: String,
}

impl BuiltAssertion {
    pub fn new(assertion: Assertion) -> Self {
        Self {
            label: assertion.label(),
            assertion,
        }
    }
}

impl AssertionBase for BuiltAssertion {
    fn label(&self) -> &str {
        &self.label
    }

    fn to_assertion(&self) -> Result<Assertion> {
        Ok(self.assertion.clone())
    }

    fn from_assertion(assertion: &Assertion) -> Result<Self> {
        Ok(Self::new(assertion.clone()))
    }
}

/// Bytes streamed between progress reports, as the legacy hasher reports once per
/// buffer it hashes. Chunks are far smaller, so reporting each would slow large
/// assets down.
const PROGRESS_INTERVAL: u64 = 16 * 1024 * 1024;

/// Reports progress in `phase` as a plan streams through it, then passes each
/// chunk to `inner`: once at the start, once per [`PROGRESS_INTERVAL`] and once
/// at the end. A cancel or progress error stops the plan and is returned
/// unchanged by [`asset_io_error`].
pub(crate) struct ProgressSink<'c, S> {
    inner: S,
    context: &'c Context,
    phase: ProgressPhase,
    size: u64,
    step: u32,
    total: u32,
    /// The output offset whose reaching is reported next.
    next: u64,
}

impl<'c, S: Sink> ProgressSink<'c, S> {
    /// Report progress through `context` while streaming `size` bytes.
    pub fn new(inner: S, context: &'c Context, phase: ProgressPhase, size: u64) -> Self {
        let total = u32::try_from(size.div_ceil(PROGRESS_INTERVAL) + 1).unwrap_or(u32::MAX);
        Self {
            inner,
            context,
            phase,
            size,
            step: 0,
            total,
            next: 0,
        }
    }

    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S: Sink> Sink for ProgressSink<'_, S> {
    fn chunk(&mut self, chunk: Chunk<'_>) -> ::asset_io::Result<()> {
        let end = chunk.offset + chunk.data.len() as u64;
        while self.step < self.total && end >= self.next {
            self.step += 1;
            self.context
                .check_progress(self.phase.clone(), self.step, self.total)
                .map_err(::asset_io::Error::callback)?;
            self.next = (self.next + PROGRESS_INTERVAL).min(self.size);
        }
        self.inner.chunk(chunk)
    }
}

/// Hashes [`HashSpan`]s as a write streams through it.
pub(crate) struct SpanHasher {
    spans: Vec<(HashSpan, Hasher)>,
}

impl SpanHasher {
    pub fn new(spans: Vec<HashSpan>) -> Result<Self> {
        let spans = spans
            .into_iter()
            .map(|span| {
                let hasher = Hasher::new(&span.alg)?;
                Ok((span, hasher))
            })
            .collect::<Result<_>>()?;
        Ok(Self { spans })
    }

    /// One digest per span, in order.
    pub fn finish(self) -> Vec<Vec<u8>> {
        self.spans
            .into_iter()
            .map(|(_, hasher)| Hasher::finalize(hasher))
            .collect()
    }

    fn hash(span: &HashSpan, hasher: &mut Hasher, start: u64, data: &[u8]) {
        let end = start + data.len() as u64;
        let mut at = start;
        let first = span.exclusions.partition_point(|r| r.end() <= start);
        for range in &span.exclusions[first..] {
            if range.offset() >= end {
                break;
            }
            if at < range.offset() {
                Self::hash_with_offsets(
                    span,
                    hasher,
                    at,
                    &data[(at - start) as usize..(range.offset() - start) as usize],
                );
            }
            at = range.end().min(end);
        }
        if at < end {
            Self::hash_with_offsets(span, hasher, at, &data[(at - start) as usize..]);
        }
    }

    fn hash_with_offsets(span: &HashSpan, hasher: &mut Hasher, start: u64, bytes: &[u8]) {
        let end = start + bytes.len() as u64;
        let mut cursor = start;
        let first = span.offsets.partition_point(|&o| o < start);
        for &offset in &span.offsets[first..] {
            if offset >= end {
                break;
            }
            hasher.update(&bytes[(cursor - start) as usize..(offset - start) as usize]);
            hasher.update(&offset.to_be_bytes());
            cursor = offset;
        }
        hasher.update(&bytes[(cursor - start) as usize..]);
    }
}

impl Sink for SpanHasher {
    fn chunk(&mut self, chunk: Chunk<'_>) -> ::asset_io::Result<()> {
        let chunk_end = chunk.offset + chunk.data.len() as u64;
        for (span, hasher) in &mut self.spans {
            let start = chunk.offset.max(span.range.offset());
            let end = chunk_end.min(span.range.end());
            if start < end {
                let data =
                    &chunk.data[(start - chunk.offset) as usize..(end - chunk.offset) as usize];
                Self::hash(span, hasher, start, data);
            }
        }
        Ok(())
    }
}

/// Sort `ranges`, drop empty ones and merge those that overlap or touch.
pub(crate) fn normalize_ranges(ranges: &mut Vec<ByteRange>) -> Result<()> {
    ranges.sort_by_key(ByteRange::offset);
    let mut merged: Vec<ByteRange> = Vec::with_capacity(ranges.len());
    for range in ranges.drain(..) {
        if range.is_empty() {
            continue;
        }
        if let Some(last) = merged.last_mut() {
            if range.offset() <= last.end() {
                *last = ByteRange::new(last.offset(), last.end().max(range.end()) - last.offset())
                    .map_err(asset_io_error)?;
                continue;
            }
        }
        merged.push(range);
    }
    *ranges = merged;
    Ok(())
}

/// An asset-io error as an SDK error. A callback's own error (a progress cancel)
/// comes back unchanged.
pub(crate) fn asset_io_error(error: ::asset_io::Error) -> Error {
    match error {
        ::asset_io::Error::Io(error) => Error::IoError(error),
        ::asset_io::Error::UserCanceled => Error::OperationCancelled,
        ::asset_io::Error::Callback(error) => match error.downcast::<Error>() {
            Ok(error) => *error,
            Err(error) => Error::InvalidAsset(error.to_string()),
        },
        ::asset_io::Error::UnsupportedFormat => Error::UnsupportedType,
        ::asset_io::Error::UnsupportedFeature(feature) => {
            Error::NotImplemented(feature.to_string())
        }
        other => Error::InvalidAsset(other.to_string()),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use ::asset_io::{NullSink, Role, SegmentId};

    use super::*;
    use crate::{
        hash_utils::HashRange,
        utils::{hash_utils::hash_by_alg, test::test_context},
    };

    #[test]
    fn span_hasher_handles_chunk_boundaries_exclusions_and_spans() {
        let data: Vec<u8> = (0..40).collect();
        let ranges = [(0, 3), (7, 4), (16, 5), (29, 3)];
        let exclusions: Vec<_> = ranges
            .iter()
            .map(|&(start, len)| ByteRange::new(start, len).unwrap())
            .collect();
        let segment = SegmentId::from_index(0).unwrap();
        for alg in ["sha256", "sha384", "sha512"] {
            for chunk_size in [1, 3, 7, 40] {
                let spans = vec![
                    HashSpan::new(ByteRange::new(0, 40).unwrap(), alg)
                        .excluding(exclusions.clone())
                        .unwrap(),
                    HashSpan::new(ByteRange::new(5, 20).unwrap(), alg),
                ];
                let mut sink = SpanHasher::new(spans).unwrap();
                for (i, chunk) in data.chunks(chunk_size).enumerate() {
                    sink.chunk(Chunk::new(
                        segment,
                        Role::Payload,
                        (i * chunk_size) as u64,
                        chunk,
                    ))
                    .unwrap();
                }
                let digests = sink.finish();
                let excluded = ranges
                    .iter()
                    .map(|&(start, len)| HashRange::new(start, len))
                    .collect();
                assert_eq!(
                    digests[0],
                    hash_by_alg(alg, &data, Some(excluded)),
                    "{alg}: chunk size {chunk_size}"
                );
                assert_eq!(digests[1], hash_by_alg(alg, &data[5..25], None), "{alg}");
            }
        }
    }

    #[test]
    fn span_hasher_hashes_offsets_before_their_bytes() {
        let data: Vec<u8> = (0..20).collect();
        let span = HashSpan::new(ByteRange::new(0, 20).unwrap(), "sha256")
            .excluding(vec![ByteRange::new(4, 2).unwrap()])
            .unwrap()
            .with_offsets(vec![10, 0]);
        let mut sink = SpanHasher::new(vec![span]).unwrap();
        for (i, chunk) in data.chunks(3).enumerate() {
            sink.chunk(Chunk::new(
                SegmentId::from_index(0).unwrap(),
                Role::Payload,
                (i * 3) as u64,
                chunk,
            ))
            .unwrap();
        }
        let mut expected = Vec::new();
        expected.extend_from_slice(&0u64.to_be_bytes());
        expected.extend_from_slice(&data[..4]);
        expected.extend_from_slice(&data[6..10]);
        expected.extend_from_slice(&10u64.to_be_bytes());
        expected.extend_from_slice(&data[10..]);
        assert_eq!(sink.finish()[0], hash_by_alg("sha256", &expected, None));
    }

    #[test]
    fn progress_is_reported_per_interval_not_per_chunk() {
        let steps = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen = steps.clone();
        let context = test_context().with_progress_callback(move |phase, step, total| {
            seen.lock().unwrap().push((phase, step, total));
            true
        });
        let size = 2 * PROGRESS_INTERVAL + PROGRESS_INTERVAL / 2;
        let chunk = vec![0; 64 * 1024];
        let mut sink = ProgressSink::new(NullSink, &context, ProgressPhase::Writing, size);
        let mut offset = 0;
        while offset < size {
            let len = chunk.len().min((size - offset) as usize);
            sink.chunk(Chunk::new(
                SegmentId::from_index(0).unwrap(),
                Role::Payload,
                offset,
                &chunk[..len],
            ))
            .unwrap();
            offset += len as u64;
        }
        let expected: Vec<_> = (1..=4)
            .map(|step| (ProgressPhase::Writing, step, 4))
            .collect();
        assert_eq!(*steps.lock().unwrap(), expected);
    }

    #[test]
    fn a_progress_error_is_returned_unchanged() {
        let context = test_context().with_progress_callback(|_, _, _| false);
        let mut sink = ProgressSink::new(
            SpanHasher::new(vec![HashSpan::new(ByteRange::new(0, 4).unwrap(), "sha256")]).unwrap(),
            &context,
            ProgressPhase::Hashing,
            4,
        );
        let error = sink
            .chunk(Chunk::new(
                SegmentId::from_index(0).unwrap(),
                Role::Payload,
                0,
                &[0; 4],
            ))
            .unwrap_err();
        assert!(matches!(asset_io_error(error), Error::OperationCancelled));
    }
}
