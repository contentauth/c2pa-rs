// The built-in handlers for formats the `asset-io` crate understands, as `AssetIO`
// implementations over its `ContainerHandler`s. Everything format specific lives in
// asset-io; what remains here is what C2PA decides: which JUMBF is the manifest
// store, which asset-io layout becomes which `ObjectLocations` and `BoxMap`, and how
// errors are reported.

use std::sync::Arc;

use ::asset_io as aio;
use aio::{
    container_api::ContainerHandler, ByteRange, HandlerRegistry, ItemKind, Structure, Updates,
};

use crate::{
    asset_io::{
        AllowedExclusion, AssetBoxHash, AssetIO, AssetPatch, BoxMap, C2paReader, C2paWriter,
        ComposedManifestRef, ExclusionKind, ObjectLocations, ObjectType, WriteXmp, C2PA_BOXHASH,
    },
    error::{Error, Result},
    read_seek::{ReadSeek, ReadWriteSeek},
};

/// The smallest C2PA manifest store: a `jumb` superbox whose `jumd` description
/// has the C2PA store type (spec 11.1.4.2) and label `c2pa`, with no manifests.
/// Used to learn where a manifest would go.
pub(crate) const MANIFEST_PLACEHOLDER: &[u8] =
    b"\0\0\0\x26jumb\0\0\0\x1ejumd\x63\x32\x70\x61\0\x11\0\x10\x80\0\0\xaa\0\x38\x9b\x71\x03c2pa\0";

/// The name a box hash gives bytes past the end of the container's structure
/// (C2PA 18.7.2).
const AFTER_BOX: &str = "c2pa.after";

const TIFF_READ_ONLY_TYPES: [&str; 4] = ["arw", "image/x-sony-arw", "nef", "image/x-nikon-nef"];
const MP3_COMPAT_TYPES: [&str; 2] = ["audio/x-mp3", "audio/mpeg3"];

fn is_tiff_read_only_type(asset_type: &str) -> bool {
    matches!(
        asset_type.trim().to_ascii_lowercase().as_str(),
        "arw" | "image/x-sony-arw" | "nef" | "image/x-nikon-nef"
    )
}

fn err(e: aio::Error) -> Error {
    match e {
        aio::Error::Io(e) => Error::IoError(e),
        aio::Error::UserCanceled => Error::OperationCancelled,
        aio::Error::UnsupportedFormat => Error::UnsupportedType,
        aio::Error::UnsupportedFeature(f) => Error::NotImplemented(f.to_string()),
        other => Error::InvalidAsset(other.to_string()),
    }
}

/// [`err`] for a lookup of the C2PA store, where more than one is the asset's
/// fault, not the container's.
pub(crate) fn store_err(e: aio::Error) -> Error {
    match e {
        aio::Error::Ambiguous { .. } => Error::TooManyManifestStores,
        other => err(other),
    }
}

/// An `AssetIO` backed by one asset-io container handler.
#[derive(Clone)]
pub(crate) struct AssetIoAdapter {
    handler: Option<Arc<dyn ContainerHandler>>,
    /// Every extension and media type the handler serves, for `supported_types`.
    types: Vec<&'static str>,
}

impl AssetIoAdapter {
    pub(crate) fn from_handler(handler: Arc<dyn ContainerHandler>) -> Self {
        let mut types: Vec<_> = handler
            .formats()
            .iter()
            .flat_map(|spec| spec.format_strings())
            .collect();
        if handler.id() == aio::containers::tiff::ID {
            types.extend(TIFF_READ_ONLY_TYPES);
        }
        if handler.id() == aio::containers::id3::ID {
            types.extend(MP3_COMPAT_TYPES);
        }
        Self {
            handler: Some(handler),
            types,
        }
    }

    fn handler(&self) -> Result<&Arc<dyn ContainerHandler>> {
        self.handler.as_ref().ok_or(Error::UnsupportedType)
    }

    fn container(&self) -> Option<&'static str> {
        self.handler.as_ref().map(|h| h.id())
    }

    fn parse(&self, input: &mut dyn ReadSeek) -> Result<Structure> {
        let mut input = input;
        let handler = self.handler()?;
        Arc::clone(handler).parse(&mut input).map_err(err)
    }

    /// Whether `asset_type` is read only: camera raw formats served by the TIFF
    /// handler.
    fn is_read_only(&self, asset_type: &str) -> bool {
        self.container() == Some(aio::containers::tiff::ID) && is_tiff_read_only_type(asset_type)
    }

    /// Whether a hash excludes only the manifest's payload, not the whole segment
    /// holding it. SVG tags and ID3 frame headers stay in the hashed asset.
    fn excludes_payload_only(&self) -> bool {
        matches!(
            self.container(),
            Some(aio::containers::svg::ID | aio::containers::id3::ID)
        )
    }
}

/// ISO BMFF options for writing `store`, as the legacy BMFF writer applied them:
/// an update manifest is added as an `update` beside the frozen `original`, and
/// merkle boxes already in the file are carried over to the new layout.
fn bmff_updates(
    s: &Structure,
    src: &mut dyn ReadSeek,
    updates: Updates,
    store: &[u8],
) -> Result<Updates> {
    use aio::containers::bmff::BmffUpdates;

    if is_update_store(store) {
        return Ok(updates.as_update());
    }
    let mut src = src;
    let merkle = s
        .items_labelled(ItemKind::Other, aio::labels::MERKLE)
        .map(|item| s.read_item(&mut src, item).map_err(err))
        .collect::<Result<Vec<_>>>()?;
    Ok(if merkle.is_empty() {
        updates
    } else {
        updates.set_merkle(merkle)
    })
}

/// Whether `store`'s provenance claim is an update manifest.
fn is_update_store(store: &[u8]) -> bool {
    let mut log = crate::status_tracker::StatusTracker::with_error_behavior(
        crate::status_tracker::ErrorBehavior::StopOnFirstError,
    );
    crate::store::Store::from_jumbf_with_context(store, &mut log, &crate::Context::new())
        .ok()
        .and_then(|store| {
            store
                .provenance_claim()
                .map(|claim| claim.update_manifest())
        })
        .unwrap_or(false)
}

/// One adapter per asset-io built-in container this build serves, for the
/// default handler registry. The read-only camera raw handler is folded into the
/// TIFF adapter, and PDF is served only with the `pdf` feature.
pub(crate) fn builtin_adapters() -> Vec<Box<dyn AssetIO>> {
    let mut seen = Vec::new();
    HandlerRegistry::builtin()
        .handlers()
        .filter(|handler| cfg!(feature = "pdf") || handler.id() != aio::containers::pdf::ID)
        .filter(|handler| {
            let new = !seen.contains(&handler.id());
            seen.push(handler.id());
            new
        })
        .map(|handler| Box::new(AssetIoAdapter::from_handler(Arc::clone(handler))) as Box<_>)
        .collect()
}

/// The item holding the asset's C2PA manifest store.
///
/// A container that reserves an element for the store (an SVG `<c2pa:manifest>`,
/// a PNG `caBX` chunk) reports every such element as a store, whatever it holds.
/// When there are several, empty and undecodable ones are ignored (an SVG with a
/// second, injected element), and more than one with content is
/// [`Error::TooManyManifestStores`]. Reading, locating and writing must all agree
/// on it: data-hash verification compares the exclusion with this location.
fn c2pa_store_item<'s>(s: &'s Structure, src: &mut dyn ReadSeek) -> Result<Option<&'s aio::Item>> {
    match s.c2pa_item() {
        Err(aio::Error::Ambiguous { .. }) => {}
        other => return other.map_err(store_err),
    }
    let mut src = src;
    let mut found = None;
    for item in s
        .items_of(ItemKind::C2pa)
        .filter(|item| item.label() != Some(aio::labels::UPDATE))
    {
        let content = match s.read_content(&mut src, item) {
            Ok(content) => content,
            // Not even decodable (bad base64): not a store.
            Err(aio::Error::InvalidFormat(_)) => continue,
            Err(e) => return Err(err(e)),
        };
        if !content.is_empty() && found.replace(item).is_some() {
            return Err(Error::TooManyManifestStores);
        }
    }
    Ok(found)
}

/// How a store fills the placeholder in an asset.
enum Fill<'s> {
    /// The whole store, which asset-io splits across a PDF's revisions or an ISO
    /// BMFF `original` and `update`.
    Store(aio::C2paPatch<'s>),
    /// The one element with content when several reserve a store.
    Item(&'s aio::Item),
}

impl Fill<'_> {
    fn apply(&self, s: &Structure, out: &mut dyn ReadWriteSeek, store: &[u8]) -> Result<()> {
        let mut out = out;
        match self {
            Fill::Store(patch) => patch.apply(&mut out),
            Fill::Item(item) => s.patch_exact(&mut out, item, store),
        }
        .map_err(err)
    }
}

/// How `store` fills the asset's placeholder in place, or `None` if it does not
/// fit (or would rewrite earlier manifests), so the asset must be written instead.
fn placeholder_fill<'s>(
    s: &'s Structure,
    src: &mut dyn ReadSeek,
    store: &[u8],
) -> Result<Option<Fill<'s>>> {
    let Some(item) = c2pa_store_item(s, &mut *src)? else {
        return Ok(None);
    };
    if s.c2pa_item().is_ok() {
        let mut src = src;
        return Ok(s.prepare_c2pa_patch(&mut src, store).ok().map(Fill::Store));
    }
    let stored = item.transfer().encode(store).map_err(err)?;
    Ok((stored.len() as u64 == item.len()).then_some(Fill::Item(item)))
}

impl C2paReader for AssetIoAdapter {
    fn read_c2pa(&self, input_stream: &mut dyn ReadSeek) -> Result<Vec<u8>> {
        let mut input = input_stream;
        let s = self.parse(&mut *input)?;
        let store = match c2pa_store_item(&s, &mut *input)? {
            None => None,
            // `c2pa_store` also joins an ISO BMFF `original` and `update`.
            Some(_) if s.c2pa_item().is_ok() => s.c2pa_store(&mut input).map_err(store_err)?,
            Some(item) => Some(s.read_content(&mut input, item).map_err(err)?),
        };
        match store {
            // A dedicated carrier may hold anything. Its content is returned as it
            // is, for the store's parser to accept or reject: reporting no
            // manifest instead would allow a remote-manifest fallback.
            Some(v) if !v.is_empty() => Ok(v),
            // C2PA boxes that travel only with a store (ISO BMFF merkle boxes) mean
            // the store was removed or retagged. Report tampering rather than an
            // unsigned asset, which would allow a remote-manifest fallback.
            None if s
                .items_labelled(ItemKind::Other, aio::labels::MERKLE)
                .next()
                .is_some() =>
            {
                Err(Error::C2PAValidation(
                    "C2PA box present without a readable manifest".to_string(),
                ))
            }
            _ => Err(Error::JumbfNotFound),
        }
    }

    fn read_xmp(&self, input_stream: &mut dyn ReadSeek) -> Result<Option<String>> {
        let mut input = input_stream;
        let s = self.parse(&mut *input)?;
        let xmp = s.xmp(&mut input).map_err(err)?;
        Ok(xmp.map(|xmp| String::from_utf8_lossy(&xmp).into_owned()))
    }
}

impl C2paWriter for AssetIoAdapter {
    fn write_c2pa(
        &self,
        input_stream: &mut dyn ReadSeek,
        output_stream: &mut dyn ReadWriteSeek,
        store_bytes: &[u8],
    ) -> Result<()> {
        let mut input = input_stream;
        let mut output = output_stream;
        let s = self.parse(&mut *input)?;

        // The sign pipeline writes a placeholder, hashes around it, then writes the
        // final manifest of the same size. Filling the placeholder in place keeps
        // every byte the hash covers where it is, which a rewrite does not promise
        // (a PDF appends a revision instead of replacing the store).
        if let Some(fill) = placeholder_fill(&s, &mut *input, store_bytes)? {
            input.rewind()?;
            output.rewind()?;
            std::io::copy(&mut *input, &mut *output)?;
            // Patching seeks back, which a buffered stream may refuse while it
            // holds unwritten data.
            output.flush()?;
            return fill.apply(&s, &mut output, store_bytes);
        }

        let mut updates = Updates::new().set_c2pa(store_bytes.to_vec());
        if s.container_id() == aio::containers::bmff::ID {
            updates = bmff_updates(&s, &mut *input, updates, store_bytes)?;
        }
        output.rewind()?;
        s.write(&mut input, &mut output, &updates, &mut aio::NullSink)
            .map_err(err)?;
        Ok(())
    }

    fn get_object_locations(
        &self,
        input_stream: &mut dyn ReadSeek,
    ) -> Result<Vec<ObjectLocations>> {
        let mut input = input_stream;
        let s = self.parse(&mut *input)?;
        let existing: Vec<aio::Extent> = c2pa_store_item(&s, &mut *input)?
            .into_iter()
            .flat_map(|e| e.extents().copied())
            .collect();

        // With no manifest, report the layout of the asset as it would be written with
        // one, so the manifest has a location to be excluded at.
        let (layout, manifest) = if existing.is_empty() {
            let planned = s
                .plan(
                    &mut input,
                    &Updates::new().set_c2pa(MANIFEST_PLACEHOLDER.to_vec()),
                )
                .map_err(err)?;
            let ids: Vec<_> = planned
                .c2pa_item()
                .map_err(store_err)?
                .map(|e| e.extents().copied().collect())
                .unwrap_or_default();
            (planned, ids)
        } else {
            (s, existing)
        };

        let mut start = u64::MAX;
        let mut end = 0u64;
        for part in &manifest {
            let x = if self.excludes_payload_only() {
                part.range()
            } else {
                layout.segment(part.segment()).map_err(err)?.range()
            };
            start = start.min(x.offset());
            end = end.max(x.end());
        }
        if start > end {
            return Err(Error::EmbeddingError);
        }

        let xmp_ranges: Vec<_> = layout
            .items_of(ItemKind::Xmp)
            .flat_map(|item| item.extents())
            .map(|extent| {
                layout
                    .segment(extent.segment())
                    .map(|segment| segment.range())
            })
            .collect::<aio::Result<_>>()
            .map_err(err)?;
        let mut out = Vec::new();
        for seg in layout.segments() {
            let x = seg.range();
            if x.is_empty() || (x.offset() >= start && x.end() <= end) {
                continue;
            }
            let htype = if xmp_ranges.contains(&x) {
                ObjectType::Xmp
            } else {
                ObjectType::Other
            };
            // A segment that only partly overlaps the manifest (the tags around an
            // SVG manifest's payload) is reported as what lies outside it.
            for (offset, stop) in [
                (x.offset(), x.end().min(start)),
                (x.offset().max(end), x.end()),
            ] {
                if stop > offset {
                    out.push(ObjectLocations {
                        offset,
                        length: stop - offset,
                        htype,
                    });
                }
            }
        }
        out.push(ObjectLocations {
            offset: start,
            length: end - start,
            htype: ObjectType::C2pa,
        });
        Ok(out)
    }

    fn remove_c2pa(
        &self,
        input_stream: &mut dyn ReadSeek,
        output_stream: &mut dyn ReadWriteSeek,
    ) -> Result<()> {
        // Only the C2PA store: any other JUMBF in the asset is left alone.
        self.apply(input_stream, output_stream, &Updates::new().remove_c2pa())
    }
}

impl AssetIoAdapter {
    fn apply(
        &self,
        input_stream: &mut dyn ReadSeek,
        output_stream: &mut dyn ReadWriteSeek,
        updates: &Updates,
    ) -> Result<()> {
        let mut input = input_stream;
        let mut output = output_stream;
        let s = self.parse(&mut *input)?;
        output.rewind()?;
        s.write(&mut input, &mut output, updates, &mut aio::NullSink)
            .map_err(err)?;
        Ok(())
    }
}

impl WriteXmp for AssetIoAdapter {
    fn write_xmp(
        &self,
        input_stream: &mut dyn ReadSeek,
        output_stream: &mut dyn ReadWriteSeek,
        xmp: &str,
    ) -> Result<()> {
        self.apply(
            input_stream,
            output_stream,
            &Updates::new().set_xmp(xmp.as_bytes().to_vec()),
        )
    }
}

impl AssetPatch for AssetIoAdapter {
    /// Replace the store with one of exactly the same stored length, in place.
    /// `store_bytes` is the whole store; asset-io patches only the part earlier
    /// manifests are not in (a PDF's latest revision, an ISO BMFF `update`).
    fn patch_c2pa(&self, stream: &mut dyn ReadWriteSeek, store_bytes: &[u8]) -> Result<()> {
        let mut stream = stream;
        let s = self.parse(&mut *stream)?;
        let item = c2pa_store_item(&s, &mut *stream)?.ok_or(Error::JumbfNotFound)?;
        if s.c2pa_item().is_ok() {
            s.patch_c2pa_store(&mut stream, store_bytes)
        } else {
            s.patch_exact(&mut stream, item, store_bytes)
        }
        .map_err(err)?;
        stream.flush()?;
        Ok(())
    }
}

impl ComposedManifestRef for AssetIoAdapter {
    fn compose_manifest(&self, manifest_data: &[u8], _format: &str) -> Result<Vec<u8>> {
        self.handler()?
            .compose(ItemKind::C2pa, manifest_data)
            .map_err(err)
    }
}

/// Box map from the layout model alone. The only format knowledge here is the
/// name table; the traversal is the same for every container.
fn box_map_from_layout(s: &Structure, c2pa_store: Option<&aio::Item>) -> Result<Vec<BoxMap>> {
    // Which segments belong to the C2PA Manifest Store (not just any JUMBF).
    let store: Vec<aio::SegmentId> = c2pa_store
        .into_iter()
        .flat_map(|item| item.extents().map(|p| p.segment()))
        .collect();

    // Bytes beyond the container's structure (data after the last chunk, or the
    // images after the first one) are not boxes; they are one `c2pa.after` box.
    let after = s.trailing();

    let mut out: Vec<BoxMap> = Vec::new();
    let mut c2pa: Option<usize> = None;
    let mut last_owner: Option<aio::SegmentId> = None;
    s.elements(|id, e| {
        if after.is_some_and(|t| e.range().offset() >= t.offset()) {
            return Ok(());
        }
        let mut ext = e.range();

        // Compatibility with the existing c2pa-rs box maps (see PR #612): when a
        // segment is expanded into parts, the first part is reported with the
        // whole segment's extent and each later part with only its own header
        // (e.g. a JPEG scan, then the 2-byte RSTn markers inside it). The boxes
        // therefore overlap, as they do today. asset-io itself never overlaps.
        let owner = s.segment(id)?.range();
        if ext != owner {
            ext = if last_owner != Some(id) {
                owner
            } else {
                ByteRange::new(ext.offset(), e.header().len())?
            };
        }
        last_owner = Some(id);
        if store.contains(&id) {
            match c2pa {
                // The store is one box even when it spans several segments.
                Some(i) => out[i].range_len = ext.end() - out[i].range_start,
                None => {
                    out.push(
                        BoxMap::new(vec![C2PA_BOXHASH.to_string()], ext.offset(), ext.len())
                            .with_allowed_exclusions(vec![AllowedExclusion::whole_box(ext.len())]),
                    );
                    c2pa = Some(out.len() - 1);
                }
            }
            return Ok(());
        }
        // Unnamed elements (fill bytes) are not boxes.
        let Some(name) = s.box_name(id, e) else {
            return Ok(());
        };
        let mut bm = BoxMap::new(vec![name.into_owned()], ext.offset(), ext.len());
        if s.items_in(id)
            .any(|item| matches!(item.kind(), ItemKind::Xmp | ItemKind::Exif))
        {
            // Metadata may be excluded after its header; the trailer (e.g. a PNG
            // CRC) changes with the data, so it is excludable too.
            bm = bm.with_allowed_exclusions(vec![AllowedExclusion::after_header(
                e.header().len(),
                ext.len(),
            )]);
        }
        out.push(bm);
        Ok(())
    })
    .map_err(err)?;
    // C2PA 18.7.2: the last box, hashed from the byte after the last box to the end
    // of the file. Only the hard binding of the whole asset has it.
    if let Some(t) = after {
        out.push(BoxMap::new(
            vec![AFTER_BOX.to_string()],
            t.offset(),
            t.len(),
        ));
    }
    Ok(out)
}

pub(crate) fn box_map_from_structure(
    s: &Structure,
    c2pa_store: Option<&aio::Item>,
) -> Result<Vec<BoxMap>> {
    Ok(if s.container_id() == aio::containers::gif::ID {
        s.complete_boxes(c2pa_store.map(|item| (item, C2PA_BOXHASH)), AFTER_BOX)
            .map_err(err)?
            .into_iter()
            .map(|b| {
                let name = b.name.map(|n| n.into_owned()).unwrap_or_default();
                let mut map = BoxMap::new(vec![name], b.range.offset(), b.range.len());
                if map.names == [C2PA_BOXHASH] {
                    map = map
                        .with_allowed_exclusions(vec![AllowedExclusion::whole_box(b.range.len())]);
                } else if !b.metadata.is_empty() {
                    map = map.with_allowed_exclusions(
                        b.metadata
                            .iter()
                            .map(|range| AllowedExclusion {
                                start: range.offset() - b.range.offset(),
                                length: range.len(),
                                kind: ExclusionKind::AssetMetadata,
                            })
                            .collect(),
                    );
                }
                map
            })
            .collect::<Vec<_>>()
    } else {
        return box_map_from_layout(s, c2pa_store);
    })
}

impl AssetBoxHash for AssetIoAdapter {
    fn get_box_map(&self, input_stream: &mut dyn ReadSeek) -> Result<Vec<BoxMap>> {
        let mut input = input_stream;
        let s = self.parse(&mut *input)?;
        let store = c2pa_store_item(&s, &mut *input)?;
        let mut out = box_map_from_structure(&s, store)?;

        // With no manifest, a zero-length excluded placeholder marks where it will
        // go, so the list of boxes matches the file once it is embedded.
        if !out
            .iter()
            .any(|b| b.names.first().is_some_and(|n| n == C2PA_BOXHASH))
        {
            let planned = s
                .plan(
                    &mut input,
                    &Updates::new().set_c2pa(MANIFEST_PLACEHOLDER.to_vec()),
                )
                .map_err(err)?;
            let first = planned
                .c2pa_item()
                .map_err(store_err)?
                .and_then(|e| e.extents().next())
                .ok_or(Error::EmbeddingError)?;
            let at = planned
                .segment(first.segment())
                .map_err(err)?
                .range()
                .offset();
            let index = out
                .iter()
                .position(|b| b.range_start >= at)
                .unwrap_or(out.len());
            out.insert(
                index,
                BoxMap::new(vec![C2PA_BOXHASH.to_string()], at, 0).excluded(),
            );
        }
        Ok(out)
    }
}

impl AssetIO for AssetIoAdapter {
    fn save_c2pa_store(&self, asset_path: &std::path::Path, store_bytes: &[u8]) -> Result<()> {
        // Standalone manifests create or replace a file instead of rewriting an existing asset.
        if self.container() == Some(aio::containers::c2pa::ID) {
            std::fs::write(asset_path, store_bytes).map_err(Error::IoError)
        } else {
            crate::asset_io::save_c2pa_store(self, asset_path, store_bytes)
        }
    }

    fn new(asset_type: &str) -> Self
    where
        Self: Sized,
    {
        let registry = HandlerRegistry::builtin();
        let handler = registry
            .handler(asset_type)
            .or_else(|| {
                if is_tiff_read_only_type(asset_type) {
                    registry.handler("tif")
                } else if MP3_COMPAT_TYPES
                    .contains(&asset_type.trim().to_ascii_lowercase().as_str())
                {
                    registry.handler("mp3")
                } else {
                    None
                }
            })
            .cloned();
        match handler {
            Some(handler) => Self::from_handler(handler),
            None => Self {
                handler: None,
                types: Vec::new(),
            },
        }
    }

    fn get_handler(&self, _asset_type: &str) -> Box<dyn AssetIO> {
        Box::new(self.clone())
    }

    fn get_reader(&self) -> &dyn C2paReader {
        self
    }

    fn get_writer(&self, asset_type: &str) -> Option<Box<dyn C2paWriter>> {
        (!self.is_read_only(asset_type)).then(|| Box::new(self.clone()) as Box<dyn C2paWriter>)
    }

    // Locating only reads, so it works for the read-only camera raw formats too.
    fn object_locations(
        &self,
        _asset_type: &str,
        input: &mut dyn ReadSeek,
    ) -> Result<Vec<ObjectLocations>> {
        C2paWriter::get_object_locations(self, input)
    }

    fn supported_types(&self) -> &[&str] {
        &self.types
    }

    fn mime_type_map(&self) -> Vec<(String, String)> {
        self.handler.as_ref().map_or_else(Vec::new, |h| {
            let mut types: Vec<_> = h
                .formats()
                .iter()
                .flat_map(|spec| {
                    spec.extensions()
                        .chain(spec.media_types())
                        .map(|ext| (ext.to_owned(), spec.media_type.to_owned()))
                })
                .collect();
            if h.id() == aio::containers::tiff::ID {
                types.extend([
                    ("arw".to_owned(), "image/x-sony-arw".to_owned()),
                    ("nef".to_owned(), "image/x-nikon-nef".to_owned()),
                ]);
            }
            if h.id() == aio::containers::id3::ID {
                types.extend(
                    MP3_COMPAT_TYPES
                        .iter()
                        .map(|alias| (alias.to_string(), "audio/mpeg".to_owned())),
                );
            }
            types
        })
    }

    // A C2PA sidecar is the store alone; it has nowhere to put XMP.
    fn asset_patch_ref(&self) -> Option<&dyn AssetPatch> {
        Some(self)
    }

    fn remote_manifest_url_ref(&self) -> Option<&dyn crate::asset_io::RemoteManifestUrl> {
        (self.container() != Some(aio::containers::c2pa::ID)).then_some(self as _)
    }

    fn write_xmp_ref(&self) -> Option<&dyn WriteXmp> {
        (self.container() != Some(aio::containers::c2pa::ID)).then_some(self as _)
    }

    // ISO BMFF is bound by its own BMFF hash.
    fn asset_box_hash_ref(&self) -> Option<&dyn AssetBoxHash> {
        self.handler
            .as_ref()
            .filter(|handler| {
                !matches!(
                    handler.id(),
                    aio::containers::tiff::ID
                        | aio::containers::id3::ID
                        | aio::containers::bmff::ID
                )
            })
            .map(|_| self as &dyn AssetBoxHash)
    }

    fn composed_data_ref(&self) -> Option<&dyn ComposedManifestRef> {
        // A composed placeholder cannot express the payload-only exclusion used
        // by SVG and ID3.
        (!self.excludes_payload_only()).then_some(self as &dyn ComposedManifestRef)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn non_jpeg_input_is_reported_as_invalid() {
        let adapter = AssetIoAdapter::new("jpeg");
        let mut input = std::io::Cursor::new(b"not a JPEG");
        assert!(matches!(
            adapter.read_c2pa(&mut input),
            Err(Error::InvalidAsset(_))
        ));
    }

    #[test]
    fn jpeg_io_errors_are_preserved() {
        struct Unreadable;

        impl std::io::Read for Unreadable {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("test I/O failure"))
            }
        }

        impl std::io::Seek for Unreadable {
            fn seek(&mut self, _: std::io::SeekFrom) -> std::io::Result<u64> {
                Err(std::io::Error::other("test I/O failure"))
            }
        }

        let adapter = AssetIoAdapter::new("jpeg");
        assert!(matches!(
            adapter.read_c2pa(&mut Unreadable),
            Err(Error::IoError(error)) if error.to_string() == "test I/O failure"
        ));
    }

    #[derive(Debug)]
    struct CustomContainer(&'static str);

    impl ContainerHandler for CustomContainer {
        fn id(&self) -> &'static str {
            "custom"
        }

        fn formats(&self) -> &[aio::container_api::FormatSpec] {
            const FORMATS: &[aio::container_api::FormatSpec] =
                &[aio::container_api::FormatSpec::new("image/jpeg", "jpg")
                    .extension_aliases(&["custom", "arw"])
                    .media_type_aliases(&["image/x-custom"])];
            FORMATS
        }

        fn parse_async(
            self: Arc<Self>,
            _io: aio::container_api::Io,
        ) -> aio::container_api::BoxFuture<'static, aio::Result<Structure>> {
            Box::pin(async move { Err(aio::Error::UnsupportedFeature(self.0)) })
        }
    }

    #[test]
    fn custom_container_survives_registration_and_registry_extension() {
        let mut ctx = crate::Context::new().with_io_handler(CustomContainer("first"));
        for format in ["jpg", "image/jpeg", "custom", "image/x-custom"] {
            let mut stream = std::io::Cursor::new(Vec::<u8>::new());
            assert!(matches!(
                ctx.io().reader(format).unwrap().read_c2pa(&mut stream),
                Err(Error::NotImplemented(message)) if message == "first"
            ));
            assert_eq!(ctx.io().mime_for(format), Some("image/jpeg"));
        }
        assert!(ctx.io().reader("png").is_some());
        assert!(ctx.io().writer("arw").is_some());

        ctx.add_io_handler(CustomContainer("second"));
        let mut stream = std::io::Cursor::new(Vec::<u8>::new());
        assert!(matches!(
            ctx.io().reader("custom").unwrap().read_c2pa(&mut stream),
            Err(Error::NotImplemented(message)) if message == "second"
        ));
        let imported = aio::HandlerRegistry::new()
            .with_handler(CustomContainer("third"))
            .with_handler(CustomContainer("last"));
        ctx.io_mut().extend(&imported);
        drop(imported);

        let mut input = std::io::Cursor::new(Vec::<u8>::new());
        let mut output = std::io::Cursor::new(Vec::<u8>::new());
        assert!(matches!(
            ctx.io().reader("custom").unwrap().read_c2pa(&mut input),
            Err(Error::NotImplemented(message)) if message == "last"
        ));
        assert!(matches!(
            ctx.io().writer("custom").unwrap().write_c2pa(&mut input, &mut output, b"store"),
            Err(Error::NotImplemented(message)) if message == "last"
        ));
    }

    #[test]
    fn tiff_camera_raw_formats_are_read_only() {
        let adapter = AssetIoAdapter::new("tif");
        assert!(adapter.get_writer("tif").is_some());

        for asset_type in TIFF_READ_ONLY_TYPES {
            let handler = AssetIoAdapter::new(asset_type);
            assert!(handler.handler.is_some(), "{asset_type}");
            assert!(handler.supported_types().contains(&asset_type));
            assert!(handler.get_writer(asset_type).is_none(), "{asset_type}");
        }
    }

    #[test]
    fn box_hash_is_available_for_registered_handlers() {
        let adapter = AssetIoAdapter::new("jpeg");
        assert!(adapter.asset_box_hash_ref().is_some());
    }

    #[test]
    fn box_hash_is_unavailable_for_tiff() {
        for asset_type in ["tif", "tiff", "dng", "image/tiff", "image/x-adobe-dng"] {
            let adapter = AssetIoAdapter::new(asset_type);
            assert!(adapter.handler.is_some(), "{asset_type}");
            assert!(adapter.asset_box_hash_ref().is_none(), "{asset_type}");
        }
    }

    #[test]
    fn box_hash_is_unavailable_without_a_handler() {
        let adapter = AssetIoAdapter::new("unsupported-format");
        assert!(adapter.asset_box_hash_ref().is_none());
    }

    /// Every container asset-io supports is served through it by default, and
    /// the legacy handlers only for formats it does not cover.
    #[test]
    fn default_registry_serves_asset_io_containers() {
        let context = crate::Context::new();
        for format in [
            "jpg", "png", "gif", "svg", "webp", "wav", "avi", "tif", "dng", "mp3", "flac", "mp4",
            "mov", "heic", "avif", "m4a", "c2pa",
        ] {
            assert!(
                context.io().handler(format).is_some(),
                "{format} is served by asset-io"
            );
        }
        for format in ["jxl", "zip", "docx"] {
            assert!(context.io().handler(format).is_some(), "{format} is served");
        }
        // Read-only camera raw formats are read through the TIFF container.
        assert!(context.io().handler("arw").is_some());
        assert!(context.io().writer("arw").is_none());
        assert_eq!(context.io().handler("pdf").is_some(), cfg!(feature = "pdf"));
    }

    /// C2PA boxes that only travel with a store mean the store was removed or
    /// retagged: tampering, not an unsigned asset that may use a remote manifest.
    #[test]
    fn bmff_merkle_box_without_store_is_tampering() {
        use crate::asset_handlers::bmff_io::{write_c2pa_box, MERKLE};

        let mut data = Vec::new();
        data.extend_from_slice(&20u32.to_be_bytes());
        data.extend_from_slice(b"ftypisom\0\0\0\0isom");
        let unsigned = data.clone();
        write_c2pa_box(&mut data, &[], MERKLE, b"merkle map", 0).unwrap();

        let reader = AssetIoAdapter::new("mp4");
        assert!(matches!(
            reader.read_c2pa(&mut std::io::Cursor::new(&data)),
            Err(Error::C2PAValidation(_))
        ));
        assert!(matches!(
            reader.read_c2pa(&mut std::io::Cursor::new(&unsigned)),
            Err(Error::JumbfNotFound)
        ));
    }
}
