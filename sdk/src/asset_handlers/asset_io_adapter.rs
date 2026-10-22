// EXPERIMENT (local only, do not commit).
//
// The built-in handlers for formats the `asset-io` crate understands, as `AssetIO`
// implementations over its `ContainerHandler`s. Everything format specific lives in
// asset-io; what remains here is what C2PA decides: which JUMBF is the manifest
// store, which asset-io layout becomes which `ObjectLocations` and `BoxMap`, and how
// errors are reported.

use std::{collections::HashSet, io::Read, sync::Arc};

use ::asset_io as aio;
use aio::{ByteRange, ContainerHandler, HandlerRegistry, SegmentKind, Structure, Updates};

use crate::{
    asset_io::{
        AllowedExclusion, AssetBoxHash, AssetIO, BoxMap, C2paReader, C2paWriter,
        ComposedManifestRef, ObjectLocations, ObjectType, WriteXmp, C2PA_BOXHASH,
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

fn err(e: aio::Error) -> Error {
    match e {
        aio::Error::Io(e) => Error::IoError(e),
        aio::Error::UserCanceled => Error::OperationCancelled,
        aio::Error::UnsupportedFormat => Error::UnsupportedType,
        aio::Error::Ambiguous { what, .. } if what == SegmentKind::Jumbf.as_str() => {
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
        let mut header = Vec::with_capacity(aio::DETECT_LEN);
        input.rewind().is_ok()
            && input
                .take(aio::DETECT_LEN as u64)
                .read_to_end(&mut header)
                .is_ok()
            && handler.detect(&header)
    }

    /// Whether a hash excludes only the manifest's payload, not the whole segment
    /// holding it. SVG keeps its `<c2pa:manifest>` tags in the hashed asset.
    fn excludes_payload_only(&self) -> bool {
        self.container() == Some(aio::containers::svg::ID)
    }

    /// Whether this container reports `c2pa.hash.boxes` boxes. A decision about
    /// C2PA, not about the container.
    fn supports_box_hash(&self) -> bool {
        use aio::containers::{jpeg, png};
        self.container()
            .is_some_and(|id| id == jpeg::ID || id == png::ID)
    }
}

/// The JUMBF entities that are C2PA Manifest Stores.
fn c2pa_entities<'s>(s: &'s Structure, src: &mut dyn ReadSeek) -> Result<Vec<&'s aio::Entity>> {
    let mut src = src;
    let mut v = Vec::new();
    for e in s.entities(SegmentKind::Jumbf) {
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
        let c2pa = c2pa_entities(&s, &mut *input)?;
        let store = if c2pa.is_empty() {
            None
        } else if c2pa.len() == s.entities(SegmentKind::Jumbf).count() {
            s.store(&mut input).map_err(err)?
        } else if c2pa.len() == 1 {
            Some(s.read_decoded(&mut input, c2pa[0]).map_err(err)?)
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
        self.apply(
            input_stream,
            output_stream,
            &Updates::new().set_jumbf(store_bytes.to_vec()),
        )
    }

    fn get_object_locations(
        &self,
        input_stream: &mut dyn ReadSeek,
    ) -> Result<Vec<ObjectLocations>> {
        let mut input = input_stream;
        let s = self.parse(&mut *input)?;
        let existing: Vec<aio::Part> = c2pa_entities(&s, &mut *input)?
            .iter()
            .flat_map(|e| e.parts().copied())
            .collect();

        // With no manifest, report the layout of the asset as it would be written with
        // one, so the manifest has a location to be excluded at.
        let (layout, manifest) = if existing.is_empty() {
            let planned = s
                .plan(&mut input, &Updates::new().set_jumbf(PLACEHOLDER.to_vec()))
                .map_err(err)?;
            let ids: Vec<_> = planned
                .entity(SegmentKind::Jumbf)
                .map_err(err)?
                .map(|e| e.parts().copied().collect())
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
                layout.segment(part.segment()).map_err(err)?.extent()
            };
            start = start.min(x.offset());
            end = end.max(x.end());
        }
        if start > end {
            return Err(Error::EmbeddingError);
        }

        let mut out = Vec::new();
        for seg in layout.segments() {
            let x = seg.extent();
            if x.is_empty() || (x.offset() >= start && x.end() <= end) {
                continue;
            }
            let htype = if seg.kind() == SegmentKind::Xmp {
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
            .compose(SegmentKind::Jumbf, manifest_data)
            .map_err(err)
    }
}

/// Box map from the layout model alone. The only format knowledge here is the
/// name table; the traversal is the same for every container.
fn box_map_from_layout(s: &Structure, mut src: &mut dyn ReadSeek) -> Result<Vec<BoxMap>> {
    // Which segments belong to the C2PA Manifest Store (not just any JUMBF).
    let mut store: HashSet<aio::SegmentId> = HashSet::new();
    for e in s.entities(SegmentKind::Jumbf) {
        if s.jumbf_type(&mut src, e).map_err(err)? == Some(C2PA_STORE_UUID) {
            store.extend(e.parts().map(|p| p.segment()));
        }
    }

    // Bytes beyond the container's structure (data after the last chunk, or the
    // images after the first one) are not boxes; they are one `c2pa.after` box.
    let after = s.trailing();

    let mut out: Vec<BoxMap> = Vec::new();
    let mut c2pa: Option<usize> = None;
    let mut last_owner: Option<aio::SegmentId> = None;
    s.elements(&mut src, |id, e| {
        if after.is_some_and(|t| e.extent().offset() >= t.offset()) {
            return Ok(());
        }
        let mut ext = e.extent();

        // Compatibility with the existing c2pa-rs box maps (see PR #612): when a
        // segment is expanded into parts, the first part is reported with the
        // whole segment's extent and each later part with only its own header
        // (e.g. a JPEG scan, then the 2-byte RSTn markers inside it). The boxes
        // therefore overlap, as they do today. asset-io itself never overlaps.
        let owner = s.segment(id)?.extent();
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
        if matches!(e.kind(), SegmentKind::Xmp | SegmentKind::Exif) {
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
        let mut out = box_map_from_layout(&s, &mut *input)?;

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
                .entity(SegmentKind::Jumbf)
                .map_err(err)?
                .and_then(|e| e.parts().next())
                .ok_or(Error::EmbeddingError)?;
            let at = planned
                .segment(first.segment())
                .map_err(err)?
                .extent()
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
        let handler = HandlerRegistry::builtin().handler(asset_type).cloned();
        let types = handler.as_ref().map_or_else(Vec::new, |h| {
            h.formats()
                .iter()
                .flat_map(|spec| spec.format_strings())
                .collect()
        });
        AssetIoAdapter { handler, types }
    }

    fn get_handler(&self, asset_type: &str) -> Box<dyn AssetIO> {
        Box::new(AssetIoAdapter::new(asset_type))
    }

    fn get_reader(&self) -> &dyn C2paReader {
        self
    }

    fn get_writer(&self, _asset_type: &str) -> Option<Box<dyn C2paWriter>> {
        Some(Box::new(self.clone()))
    }

    fn supported_types(&self) -> &[&str] {
        &self.types
    }

    fn mime_type_map(&self) -> Vec<(String, String)> {
        self.handler.as_ref().map_or_else(Vec::new, |h| {
            h.formats()
                .iter()
                .flat_map(|spec| {
                    spec.extensions()
                        .map(|ext| (ext.to_owned(), spec.media_type.to_owned()))
                })
                .collect()
        })
    }

    fn remote_manifest_url_ref(&self) -> Option<&dyn crate::asset_io::RemoteManifestUrl> {
        Some(self)
    }

    fn write_xmp_ref(&self) -> Option<&dyn WriteXmp> {
        Some(self)
    }

    fn asset_box_hash_ref(&self) -> Option<&dyn AssetBoxHash> {
        self.supports_box_hash()
            .then_some(self as &dyn AssetBoxHash)
    }

    fn composed_data_ref(&self) -> Option<&dyn ComposedManifestRef> {
        // An SVG manifest is excluded from hashes by its payload, which a composed
        // placeholder (the whole element) cannot say, so SVG does not offer one.
        (!self.excludes_payload_only()).then_some(self as &dyn ComposedManifestRef)
    }
}
