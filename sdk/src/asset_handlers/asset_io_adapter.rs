// EXPERIMENT (local only, do not commit).
//
// The built-in handlers for formats the `asset-io` crate understands, as `AssetIO`
// implementations over its `ContainerHandler`s. Everything format specific lives in
// asset-io; what remains here is what C2PA decides: which JUMBF is the manifest
// store, which asset-io layout becomes which `ObjectLocations` and `BoxMap`, and how
// errors are reported.

use std::{collections::HashSet, io::Read, sync::Arc};

use ::asset_io as aio;
use aio::{
    container_api::{ContainerHandler, DETECT_LEN},
    ByteRange, HandlerRegistry, ItemKind, Structure, Updates,
};

use crate::{
    asset_io::{
        AllowedExclusion, AssetBoxHash, AssetIO, BoxMap, C2paReader, C2paWriter,
        ComposedManifestRef, ExclusionKind, ObjectLocations, ObjectType, WriteXmp, C2PA_BOXHASH,
    },
    error::{Error, Result},
    read_seek::{ReadSeek, ReadWriteSeek},
};

/// JUMBF superbox type UUID of the C2PA Manifest Store ("c2pa"), spec 11.1.4.2.
const C2PA_STORE_UUID: [u8; 16] = [
    0x63, 0x32, 0x70, 0x61, 0x00, 0x11, 0x00, 0x10, 0x80, 0x00, 0x00, 0xaa, 0x00, 0x38, 0x9b, 0x71,
];

/// The smallest JUMBF asset-io accepts, used to learn where a manifest would go.
const PLACEHOLDER: [u8; 8] = [0, 0, 0, 8, b'j', b'u', b'm', b'b'];

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
        aio::Error::Ambiguous { what, .. } if what == ItemKind::Jumbf.as_str() => {
            Error::TooManyManifestStores
        }
        other => Error::InvalidAsset(other.to_string()),
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
        Arc::clone(handler).parse(&mut input).map_err(|e| {
            // `JpegIO` reported input that is not a JPEG at all as unsupported rather
            // than as a malformed asset (`PngIO` did not), and callers rely on that.
            if self.container() == Some(aio::containers::jpeg::ID)
                && !Self::looks_like(handler.as_ref(), &mut *input)
            {
                return Error::UnsupportedType;
            }
            err(e)
        })
    }

    fn looks_like(handler: &dyn ContainerHandler, input: &mut dyn ReadSeek) -> bool {
        let mut header = Vec::with_capacity(DETECT_LEN);
        input.rewind().is_ok()
            && input
                .take(DETECT_LEN as u64)
                .read_to_end(&mut header)
                .is_ok()
            && handler.detect(&header)
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

/// The JUMBF items that are C2PA Manifest Stores.
fn c2pa_items<'s>(s: &'s Structure, src: &mut dyn ReadSeek) -> Result<Vec<&'s aio::Item>> {
    let mut src = src;
    let mut v = Vec::new();
    for e in s.items_of(ItemKind::Jumbf) {
        if s.jumbf_type(&mut src, e).map_err(err)? == Some(C2PA_STORE_UUID) {
            v.push(e);
        }
    }
    Ok(v)
}

impl C2paReader for AssetIoAdapter {
    fn read_c2pa(&self, input_stream: &mut dyn ReadSeek) -> Result<Vec<u8>> {
        let mut input = input_stream;
        let s = self.parse(&mut *input)?;
        let c2pa = c2pa_items(&s, &mut *input)?;
        let store = if c2pa.is_empty() {
            None
        } else if c2pa.len() == s.items_of(ItemKind::Jumbf).count() {
            s.store(&mut input).map_err(err)?
        } else if c2pa.len() == 1 {
            Some(s.read_content(&mut input, c2pa[0]).map_err(err)?)
        } else {
            return Err(Error::TooManyManifestStores);
        };
        match store {
            Some(v) if !v.is_empty() => Ok(v),
            _ => Err(Error::JumbfNotFound),
        }
    }

    fn read_xmp(&self, input_stream: &mut dyn ReadSeek) -> Option<String> {
        let mut input = input_stream;
        let s = self.parse(&mut *input).ok()?;
        let xmp = s.xmp(&mut input).ok()??;
        Some(String::from_utf8_lossy(&xmp).into_owned())
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
        if let [item] = c2pa_items(&s, &mut *input)?.as_slice() {
            let stored = item.transfer().encode(store_bytes).map_err(err)?;
            if stored.len() as u64 == item.len() {
                input.rewind()?;
                output.rewind()?;
                std::io::copy(&mut *input, &mut *output)?;
                // Patching seeks back, which a buffered stream may refuse while it
                // holds unwritten data.
                output.flush()?;
                return s.patch_exact(&mut output, item, store_bytes).map_err(err);
            }
        }

        output.rewind()?;
        s.write(
            &mut input,
            &mut output,
            &Updates::new().set_jumbf(store_bytes.to_vec()),
            &mut aio::NullSink,
        )
        .map_err(err)?;
        Ok(())
    }

    fn get_object_locations(
        &self,
        input_stream: &mut dyn ReadSeek,
    ) -> Result<Vec<ObjectLocations>> {
        let mut input = input_stream;
        let s = self.parse(&mut *input)?;
        let existing: Vec<aio::Extent> = c2pa_items(&s, &mut *input)?
            .iter()
            .flat_map(|e| e.extents().copied())
            .collect();

        // With no manifest, report the layout of the asset as it would be written with
        // one, so the manifest has a location to be excluded at.
        let (layout, manifest) = if existing.is_empty() {
            let planned = s
                .plan(&mut input, &Updates::new().set_jumbf(PLACEHOLDER.to_vec()))
                .map_err(err)?;
            let ids: Vec<_> = planned
                .item(ItemKind::Jumbf)
                .map_err(err)?
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
        self.apply(
            input_stream,
            output_stream,
            &Updates::new().remove_jumbf_of(C2PA_STORE_UUID),
        )
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

impl ComposedManifestRef for AssetIoAdapter {
    fn compose_manifest(&self, manifest_data: &[u8], _format: &str) -> Result<Vec<u8>> {
        self.handler()?
            .compose(ItemKind::Jumbf, manifest_data)
            .map_err(err)
    }
}

/// Box map from the layout model alone. The only format knowledge here is the
/// name table; the traversal is the same for every container.
fn box_map_from_layout(s: &Structure, mut src: &mut dyn ReadSeek) -> Result<Vec<BoxMap>> {
    // Which segments belong to the C2PA Manifest Store (not just any JUMBF).
    let mut store: HashSet<aio::SegmentId> = HashSet::new();
    for e in s.items_of(ItemKind::Jumbf) {
        if s.jumbf_type(&mut src, e).map_err(err)? == Some(C2PA_STORE_UUID) {
            store.extend(e.extents().map(|p| p.segment()));
        }
    }

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
        let Some(name) = s.box_name(e.name()) else {
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
            vec![aio::AFTER_BOX.to_string()],
            t.offset(),
            t.len(),
        ));
    }
    Ok(out)
}

impl AssetBoxHash for AssetIoAdapter {
    fn get_box_map(&self, input_stream: &mut dyn ReadSeek) -> Result<Vec<BoxMap>> {
        let mut input = input_stream;
        let s = self.parse(&mut *input)?;
        let mut out = if self.container() == Some(aio::containers::gif::ID) {
            s.c2pa_boxes(&mut input)
                .map_err(err)?
                .into_iter()
                .map(|b| {
                    let mut map =
                        BoxMap::new(vec![b.name.into_owned()], b.range.offset(), b.range.len());
                    if map.names == [C2PA_BOXHASH] {
                        map = map.with_allowed_exclusions(vec![AllowedExclusion::whole_box(
                            b.range.len(),
                        )]);
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
                .collect()
        } else {
            box_map_from_layout(&s, &mut *input)?
        };

        // With no manifest, a zero-length excluded placeholder marks where it will
        // go, so the list of boxes matches the file once it is embedded.
        if !out
            .iter()
            .any(|b| b.names.first().is_some_and(|n| n == C2PA_BOXHASH))
        {
            let planned = s
                .plan(&mut input, &Updates::new().set_jumbf(PLACEHOLDER.to_vec()))
                .map_err(err)?;
            let first = planned
                .item(ItemKind::Jumbf)
                .map_err(err)?
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
        let read_only = self.container() == Some(aio::containers::tiff::ID)
            && is_tiff_read_only_type(asset_type);
        (!read_only).then(|| Box::new(self.clone()) as Box<dyn C2paWriter>)
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

    fn remote_manifest_url_ref(&self) -> Option<&dyn crate::asset_io::RemoteManifestUrl> {
        Some(self)
    }

    fn write_xmp_ref(&self) -> Option<&dyn WriteXmp> {
        Some(self)
    }

    fn asset_box_hash_ref(&self) -> Option<&dyn AssetBoxHash> {
        self.handler
            .as_ref()
            .filter(|handler| {
                !matches!(
                    handler.id(),
                    aio::containers::tiff::ID | aio::containers::id3::ID
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
}
