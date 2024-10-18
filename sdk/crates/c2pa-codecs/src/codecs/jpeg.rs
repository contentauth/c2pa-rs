// Copyright 2022 Adobe. All rights reserved.
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

use std::{
    collections::HashMap,
    io::{BufReader, Cursor, Read, Seek, Write},
};

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use img_parts::{
    jpeg::{
        markers::{self, APP0, APP15, COM, DQT, DRI, P, RST0, RST7, SOF0, SOF15, SOS, Z},
        Jpeg, JpegSegment,
    },
    Bytes, DynImage,
};

use crate::{
    xmp::{add_provenance, MIN_XMP},
    BoxSpan, ByteSpan, C2paSpan, CodecError, Decode, DefaultSpan, Embed, Embeddable, Encode,
    NamedByteSpan, Span, Support,
};

const XMP_SIGNATURE: &[u8] = b"http://ns.adobe.com/xap/1.0/";
const XMP_SIGNATURE_BUFFER_SIZE: usize = XMP_SIGNATURE.len() + 1; // skip null or space char at end

const MAX_JPEG_MARKER_SIZE: usize = 64000; // technically it's 64K but a bit smaller is fine

const C2PA_MARKER: [u8; 4] = [0x63, 0x32, 0x70, 0x61];

fn vec_compare(va: &[u8], vb: &[u8]) -> bool {
    (va.len() == vb.len()) &&  // zip stops at the shortest
     va.iter()
       .zip(vb)
       .all(|(a,b)| a == b)
}

// Return contents of APP1 segment if it is an XMP segment.
fn extract_xmp(seg: &JpegSegment) -> Option<String> {
    let contents = seg.contents();
    if contents.starts_with(XMP_SIGNATURE) {
        let rest = contents.slice(XMP_SIGNATURE_BUFFER_SIZE..);
        String::from_utf8(rest.to_vec()).ok()
    } else {
        None
    }
}

// Extract XMP from bytes.
fn xmp_from_bytes(asset_bytes: &[u8]) -> Option<String> {
    if let Ok(jpeg) = Jpeg::from_bytes(Bytes::copy_from_slice(asset_bytes)) {
        let segs = jpeg.segments_by_marker(markers::APP1);
        let xmp: Vec<String> = segs.filter_map(extract_xmp).collect();
        match xmp.is_empty() {
            true => None,
            false => Some(xmp.concat()),
        }
    } else {
        None
    }
}

fn add_required_segs_to_stream(
    mut src: impl Read + Seek,
    mut dst: impl Write,
) -> Result<(), CodecError> {
    let mut buf: Vec<u8> = Vec::new();
    src.rewind()?;
    src.read_to_end(&mut buf)?;
    src.rewind()?;

    let dimg_opt = DynImage::from_bytes(buf.into()).map_err(|err| CodecError::InvalidAsset {
        src: Some(err.to_string()),
        context: "Could not parse input JPEG".to_owned(),
    })?;

    if let Some(DynImage::Jpeg(jpeg)) = dimg_opt {
        // check for JUMBF Seg
        let cai_app11 = get_cai_segments(&jpeg)?; // make sure we only check for C2PA segments

        if cai_app11.is_empty() {
            // create dummy JUMBF seg
            let mut no_bytes: Vec<u8> = vec![0; 50]; // enough bytes to be valid
            no_bytes.splice(16..20, C2PA_MARKER); // cai UUID signature
            let mut aio = JpegCodec::new(src);
            aio.write_c2pa(dst, &no_bytes)?;
        } else {
            // just clone
            src.rewind()?;
            std::io::copy(&mut src, &mut dst)?;
        }
    } else {
        return Err(CodecError::IncorrectFormat);
    }

    Ok(())
}

// all cai specific segments
fn get_cai_segments(jpeg: &img_parts::jpeg::Jpeg) -> Result<Vec<usize>, CodecError> {
    let mut cai_segs: Vec<usize> = Vec::new();

    let segments = jpeg.segments();

    let mut cai_en: Vec<u8> = Vec::new();
    let mut cai_seg_cnt: u32 = 0;

    for (i, segment) in segments.iter().enumerate() {
        let raw_bytes = segment.contents();
        let seg_type = segment.marker();

        if raw_bytes.len() > 16 && seg_type == markers::APP11 {
            // we need at least 16 bytes in each segment for CAI
            let mut raw_vec = raw_bytes.to_vec();
            let _ci = raw_vec.as_mut_slice()[0..2].to_vec();
            let en = raw_vec.as_mut_slice()[2..4].to_vec();
            let mut z_vec = Cursor::new(raw_vec.as_mut_slice()[4..8].to_vec());
            let _z = z_vec.read_u32::<BigEndian>()?;

            let is_cai_continuation = vec_compare(&cai_en, &en);

            if cai_seg_cnt > 0 && is_cai_continuation {
                cai_seg_cnt += 1;
                cai_segs.push(i);
            } else {
                // check if this is a CAI JUMBF block
                let jumb_type = &raw_vec.as_mut_slice()[24..28];
                let is_cai = vec_compare(&C2PA_MARKER, jumb_type);
                if is_cai {
                    cai_segs.push(i);
                    cai_seg_cnt = 1;
                    cai_en.clone_from(&en); // store the identifier
                }
            }
        }
    }

    Ok(cai_segs)
}

// delete cai segments
fn delete_cai_segments(jpeg: &mut img_parts::jpeg::Jpeg) -> Result<bool, CodecError> {
    let cai_segs = get_cai_segments(jpeg)?;
    if cai_segs.is_empty() {
        return Ok(false);
    }

    let jpeg_segs = jpeg.segments_mut();

    // remove cai segments
    for seg in cai_segs.iter().rev() {
        jpeg_segs.remove(*seg);
    }
    Ok(true)
}

#[derive(Debug)]
pub struct JpegCodec<R> {
    src: R,
}

impl<R> JpegCodec<R> {
    pub fn new(src: R) -> Self {
        Self { src }
    }
}

impl Support for JpegCodec<()> {
    const MAX_SIGNATURE_LEN: usize = 3;

    fn supports_signature(signature: &[u8]) -> bool {
        signature[0..3] == [0xff, 0xd8, 0xff]
    }

    fn supports_extension(ext: &str) -> bool {
        matches!(ext, "jpg" | "jpeg")
    }

    fn supports_mime(mime: &str) -> bool {
        matches!(mime, "image/jpeg")
    }
}

impl<R: Read + Seek> Decode for JpegCodec<R> {
    fn read_c2pa(&mut self) -> Result<Option<Vec<u8>>, CodecError> {
        let mut buffer: Vec<u8> = Vec::new();

        let mut manifest_store_cnt = 0;

        // load the bytes
        let mut buf: Vec<u8> = Vec::new();

        self.src.rewind()?;
        self.src.read_to_end(&mut buf)?;

        let dimg_opt =
            DynImage::from_bytes(buf.into()).map_err(|err| CodecError::InvalidAsset {
                src: Some(err.to_string()),
                context: "Could not parse input JPEG".to_string(),
            })?;

        if let Some(dimg) = dimg_opt {
            match dimg {
                DynImage::Jpeg(jpeg) => {
                    let app11 = jpeg.segments_by_marker(markers::APP11);
                    let mut cai_en: Vec<u8> = Vec::new();
                    let mut cai_seg_cnt: u32 = 0;
                    for segment in app11 {
                        let raw_bytes = segment.contents();
                        if raw_bytes.len() > 16 {
                            // we need at least 16 bytes in each segment for CAI
                            let mut raw_vec = raw_bytes.to_vec();
                            let _ci = raw_vec.as_mut_slice()[0..2].to_vec();
                            let en = raw_vec.as_mut_slice()[2..4].to_vec();
                            let mut z_vec = Cursor::new(raw_vec.as_mut_slice()[4..8].to_vec());
                            let z = z_vec.read_u32::<BigEndian>()?;

                            let is_cai_continuation = vec_compare(&cai_en, &en);

                            if cai_seg_cnt > 0 && is_cai_continuation {
                                // make sure this is a cai segment for additional segments,
                                if z <= cai_seg_cnt {
                                    // this a non contiguous segment with same "en" so a bad set of data
                                    // reset and continue to search
                                    cai_en = Vec::new();
                                    continue;
                                }
                                // take out LBox & TBox
                                buffer.append(&mut raw_vec.as_mut_slice()[16..].to_vec());

                                cai_seg_cnt += 1;
                            } else if raw_vec.len() > 28 {
                                // must be at least 28 bytes for this to be a valid JUMBF box
                                // check if this is a CAI JUMBF block
                                let jumb_type = &raw_vec.as_mut_slice()[24..28];
                                let is_cai = vec_compare(&C2PA_MARKER, jumb_type);

                                if is_cai {
                                    if manifest_store_cnt == 1 {
                                        return Err(CodecError::MoreThanOneC2pa);
                                    }

                                    buffer.append(&mut raw_vec.as_mut_slice()[8..].to_vec());
                                    cai_seg_cnt = 1;
                                    cai_en.clone_from(&en); // store the identifier

                                    manifest_store_cnt += 1;
                                }
                            }
                        }
                    }
                }
                _ => {
                    return Err(CodecError::InvalidAsset {
                        src: None,
                        context: "Unknown image format".to_string(),
                    })
                }
            };
        } else {
            return Err(CodecError::IncorrectFormat);
        }

        if buffer.is_empty() {
            return Ok(None);
        }

        Ok(Some(buffer))
    }

    // Get XMP block
    fn read_xmp(&mut self) -> Result<Option<String>, CodecError> {
        // load the bytes
        let mut buf: Vec<u8> = Vec::new();
        self.src.rewind()?;
        self.src.read_to_end(&mut buf)?;
        Ok(xmp_from_bytes(&buf))
    }
}

impl<R: Read + Seek> Encode for JpegCodec<R> {
    fn write_c2pa(&mut self, dst: impl Write, c2pa: &[u8]) -> Result<(), CodecError> {
        let mut buf = Vec::new();
        // read the whole asset
        self.src.rewind()?;
        self.src.read_to_end(&mut buf)?;
        let mut jpeg = Jpeg::from_bytes(buf.into()).map_err(|err| CodecError::InvalidAsset {
            src: Some(err.to_string()),
            context: "TODO".to_string(),
        })?;

        // remove existing CAI segments
        delete_cai_segments(&mut jpeg)?;

        let jumbf_len = c2pa.len();
        let num_segments = (jumbf_len / MAX_JPEG_MARKER_SIZE) + 1;
        let mut seg_chucks = c2pa.chunks(MAX_JPEG_MARKER_SIZE);

        for seg in 1..num_segments + 1 {
            /*
                If the size of the box payload is less than 2^32-8 bytes,
                then all fields except the XLBox field, that is: Le, CI, En, Z, LBox and TBox,
                shall be present in all JPEG XT marker segment representing this box,
                regardless of whether the marker segments starts this box,
                or continues a box started by a former JPEG XT Marker segment.
            */
            // we need to prefix the JUMBF with the JPEG XT markers (ISO 19566-5)
            // CI: JPEG extensions marker - JP
            // En: Box Instance Number  - 0x0001
            //          (NOTE: can be any unique ID, so we pick one that shouldn't conflict)
            // Z: Packet sequence number - 0x00000001...
            let ci = vec![0x4a, 0x50];
            let en = vec![0x02, 0x11];
            let z: u32 = u32::try_from(seg).map_err(|err| CodecError::InvalidAsset {
                src: Some(err.to_string()),
                context: "Too many JUMBF segments".to_string(),
            })?; //seg.to_be_bytes();

            let mut seg_data = Vec::new();
            seg_data.extend(ci);
            seg_data.extend(en);
            seg_data.extend(z.to_be_bytes());
            if seg > 1 {
                // the LBox and TBox are already in the JUMBF
                // but we need to duplicate them in all other segments
                let lbox_tbox = &c2pa[..8];
                seg_data.extend(lbox_tbox);
            }
            if seg_chucks.len() > 0 {
                // make sure we have some...
                if let Some(next_seg) = seg_chucks.next() {
                    seg_data.extend(next_seg);
                }
            } else {
                seg_data.extend(c2pa);
            }

            let seg_bytes = Bytes::from(seg_data);
            let app11_segment = JpegSegment::new_with_contents(markers::APP11, seg_bytes);
            jpeg.segments_mut().insert(seg, app11_segment); // we put this in the beginning...
        }

        jpeg.encoder().write_to(dst)?;

        Ok(())
    }

    fn remove_c2pa(&mut self, dst: impl Write) -> Result<bool, CodecError> {
        let mut buf = Vec::new();
        // read the whole asset
        self.src.rewind()?;
        self.src.read_to_end(&mut buf)?;
        let mut jpeg = Jpeg::from_bytes(buf.into()).map_err(|err| CodecError::InvalidAsset {
            src: Some(err.to_string()),
            context: "TODO".to_string(),
        })?;

        // remove existing CAI segments
        let found = delete_cai_segments(&mut jpeg)?;

        jpeg.encoder().write_to(dst)?;

        Ok(found)
    }

    fn write_xmp(&mut self, dst: impl Write, xmp: &str) -> Result<(), CodecError> {
        let mut buf = Vec::new();
        self.src.rewind()?;
        self.src.read_to_end(&mut buf)?;
        let mut jpeg = Jpeg::from_bytes(buf.into()).map_err(|err| CodecError::InvalidAsset {
            src: Some(err.to_string()),
            context: "TODO".to_string(),
        })?;

        let segments = jpeg.segments_mut();
        let mut xmp_index = None;
        for (i, seg) in segments.iter().enumerate() {
            if seg.marker() == markers::APP1 && seg.contents().starts_with(XMP_SIGNATURE) {
                xmp_index = Some(i);
                break;
            }
        }

        let xmp = format!("http://ns.adobe.com/xap/1.0/\0{}", xmp);
        let segment = JpegSegment::new_with_contents(markers::APP1, Bytes::from(xmp.to_string()));
        match xmp_index {
            Some(i) => segments[i] = segment,
            None => segments.insert(1, segment),
        }

        jpeg.encoder().write_to(dst)?;

        Ok(())
    }

    fn write_xmp_provenance(
        &mut self,
        dst: impl Write,
        provenance: &str,
    ) -> Result<(), CodecError> {
        let mut buf = Vec::new();
        // read the whole asset
        self.src.rewind()?;
        self.src.read_to_end(&mut buf)?;
        let mut jpeg = Jpeg::from_bytes(buf.into()).map_err(|err| CodecError::InvalidAsset {
            src: Some(err.to_string()),
            context: "TODO".to_string(),
        })?;

        // find any existing XMP segment and remember where it was
        let mut xmp = MIN_XMP.to_string(); // default minimal XMP
        let mut xmp_index = None;
        let segments = jpeg.segments_mut();
        for (i, seg) in segments.iter().enumerate() {
            if seg.marker() == markers::APP1 && seg.contents().starts_with(XMP_SIGNATURE) {
                xmp = extract_xmp(seg).unwrap_or_else(|| xmp.clone());
                xmp_index = Some(i);
                break;
            }
        }
        // add provenance and JPEG XMP prefix
        let xmp = format!(
            "http://ns.adobe.com/xap/1.0/\0{}",
            add_provenance(&xmp, provenance)?
        );
        let segment = JpegSegment::new_with_contents(markers::APP1, Bytes::from(xmp));
        // insert or add the segment
        match xmp_index {
            Some(i) => segments[i] = segment,
            None => segments.insert(1, segment),
        }

        jpeg.encoder().write_to(dst)?;

        Ok(())
    }
}

impl<R: Read + Seek> Span for JpegCodec<R> {
    fn span(&mut self) -> Result<DefaultSpan, CodecError> {
        Ok(DefaultSpan::Data(self.c2pa_span()?))
    }

    fn c2pa_span(&mut self) -> Result<C2paSpan, CodecError> {
        let mut cai_en: Vec<u8> = Vec::new();
        let mut cai_seg_cnt: u32 = 0;

        let mut positions: Vec<ByteSpan> = Vec::new();
        let mut curr_offset = 2; // start after JPEG marker

        let output_vec: Vec<u8> = Vec::new();
        let mut output_stream = Cursor::new(output_vec);
        // make sure the file has the required segments so we can generate all the required offsets
        add_required_segs_to_stream(&mut self.src, &mut output_stream)?;

        let buf: Vec<u8> = output_stream.into_inner();

        let dimg = DynImage::from_bytes(buf.into())
            .map_err(|err| CodecError::InvalidAsset {
                src: Some(err.to_string()),
                context: "TODO".to_string(),
            })?
            .ok_or(CodecError::IncorrectFormat)?;

        match dimg {
            DynImage::Jpeg(jpeg) => {
                for seg in jpeg.segments() {
                    match seg.marker() {
                        markers::APP11 => {
                            // JUMBF marker
                            let raw_bytes = seg.contents();

                            if raw_bytes.len() > 16 {
                                // we need at least 16 bytes in each segment for CAI
                                let mut raw_vec = raw_bytes.to_vec();
                                let _ci = raw_vec.as_mut_slice()[0..2].to_vec();
                                let en = raw_vec.as_mut_slice()[2..4].to_vec();

                                let is_cai_continuation = vec_compare(&cai_en, &en);

                                if cai_seg_cnt > 0 && is_cai_continuation {
                                    cai_seg_cnt += 1;

                                    let v = ByteSpan {
                                        start: curr_offset,
                                        len: seg.len_with_entropy() as u64,
                                    };
                                    positions.push(v);
                                } else {
                                    // check if this is a CAI JUMBF block
                                    let jumb_type = raw_vec.as_mut_slice()[24..28].to_vec();
                                    let is_cai = vec_compare(&C2PA_MARKER, &jumb_type);
                                    if is_cai {
                                        cai_seg_cnt = 1;
                                        cai_en.clone_from(&en); // store the identifier

                                        let v = ByteSpan {
                                            start: curr_offset,
                                            len: seg.len_with_entropy() as u64,
                                        };

                                        positions.push(v);
                                        // } else {
                                        //     // save other for completeness sake
                                        //     let v = HashObjectPositions {
                                        //         offset: curr_offset,
                                        //         length: seg.len_with_entropy(),
                                        //         htype: HashBlockObjectType::Other,
                                        //     };
                                        //     positions.push(v);
                                    }
                                }
                            }
                        }
                        markers::APP1 => {
                            // // XMP marker or EXIF or Extra XMP
                            // let v = HashObjectPositions {
                            //     offset: curr_offset,
                            //     length: seg.len_with_entropy(),
                            //     htype: HashBlockObjectType::Xmp,
                            // };
                            // todo: pick the app1 that is the xmp (not crucial as it gets hashed either way)
                            // positions.push(v);
                        }
                        _ => {
                            // // save other for completeness sake
                            // let v = HashObjectPositions {
                            //     offset: curr_offset,
                            //     length: seg.len_with_entropy(),
                            //     htype: HashBlockObjectType::Other,
                            // };

                            // positions.push(v);
                        }
                    }
                    curr_offset += seg.len_with_entropy() as u64;
                }
            }
            _ => return Err(CodecError::IncorrectFormat),
        }

        Ok(C2paSpan { spans: positions })
    }

    fn box_span(&mut self) -> Result<BoxSpan, CodecError> {
        let mut box_maps = make_box_maps(&mut self.src)?;

        for bm in box_maps.iter_mut() {
            if bm.names[0] == "C2PA" {
                continue;
            }

            self.src.seek(std::io::SeekFrom::Start(bm.span.start))?;

            let size = if bm.names[0] == "SOS" {
                let mut size = get_seg_size(&mut self.src)?;

                self.src
                    .seek(std::io::SeekFrom::Start(bm.span.start + size as u64))?;

                size += get_entropy_size(&mut self.src)?;

                size
            } else {
                get_seg_size(&mut self.src)?
            };

            bm.span.start = size as u64;
        }

        Ok(BoxSpan { spans: box_maps })
    }
}

fn in_entropy(marker: u8) -> bool {
    matches!(marker, RST0..=RST7 | Z)
}

// img-parts does not correctly return the true size of the SOS segment.  This utility
// finds the correct break point for single image JPEGs.  We will need a new JPEG decoder
// to handle those.  Also this function can be removed if img-parts ever addresses this issue
// and support MPF JPEGs.
fn get_entropy_size(src: impl Read + Seek) -> Result<usize, CodecError> {
    // Search the entropy data looking for non entropy segment marker.  The first valid seg marker before we hit
    // end of the file.

    let mut buf_reader = BufReader::new(src);

    let mut size = 0;

    loop {
        let curr_byte = buf_reader.read_u8()?;
        if curr_byte == P {
            let next_byte = buf_reader.read_u8()?;

            if !in_entropy(next_byte) {
                break;
            } else {
                size += 1;
            }
        }
        size += 1;
    }

    Ok(size)
}

fn has_length(marker: u8) -> bool {
    matches!(marker, RST0..=RST7 | APP0..=APP15 | SOF0..=SOF15 | SOS | COM | DQT | DRI)
}

fn get_seg_size(mut src: impl Read + Seek) -> Result<usize, CodecError> {
    let p = src.read_u8()?;
    let marker = if p == P {
        src.read_u8()?
    } else {
        return Err(CodecError::InvalidAsset {
            src: None,
            context: "Cannot read segment marker".to_string(),
        });
    };

    if has_length(marker) {
        let val: usize = src.read_u16::<BigEndian>()? as usize;
        Ok(val + 2)
    } else {
        Ok(2)
    }
}

fn make_box_maps(mut src: impl Read + Seek) -> Result<Vec<NamedByteSpan>, CodecError> {
    let segment_names = HashMap::from([
        (0xe0u8, "APP0"),
        (0xe1u8, "APP1"),
        (0xe2u8, "APP2"),
        (0xe3u8, "APP3"),
        (0xe4u8, "APP4"),
        (0xe5u8, "APP5"),
        (0xe6u8, "APP6"),
        (0xe7u8, "APP7"),
        (0xe8u8, "APP8"),
        (0xe9u8, "APP9"),
        (0xeau8, "APP10"),
        (0xebu8, "APP11"),
        (0xecu8, "APP12"),
        (0xedu8, "APP13"),
        (0xeeu8, "APP14"),
        (0xefu8, "APP15"),
        (0xfeu8, "COM"),
        (0xc4u8, "DHT"),
        (0xdbu8, "DQT"),
        (0xddu8, "DRI"),
        (0xd9u8, "EOI"),
        (0xd0u8, "RST0"),
        (0xd1u8, "RST1"),
        (0xd2u8, "RST2"),
        (0xd3u8, "RST3"),
        (0xd4u8, "RST4"),
        (0xd5u8, "RST5"),
        (0xd6u8, "RST6"),
        (0xd7u8, "RST7"),
        (0xc0u8, "SOF0"),
        (0xc1u8, "SOF1"),
        (0xc2u8, "SOF2"),
        (0xd8u8, "SOI"),
        (0xdau8, "SOS"),
        (0xf0u8, "JPG0"),
        (0xf1u8, "JPG1"),
        (0xf2u8, "JPG2"),
        (0xf3u8, "JPG3"),
        (0xf4u8, "JPG4"),
        (0xf5u8, "JPG5"),
        (0xf6u8, "JPG6"),
        (0xf7u8, "JPG7"),
        (0xf8u8, "JPG8"),
        (0xf9u8, "JPG9"),
        (0xfau8, "JPG10"),
        (0xfbu8, "JPG11"),
        (0xfcu8, "JPG12"),
        (0xfdu8, "JPG13"),
    ]);

    let mut box_maps = Vec::new();
    let mut cai_en: Vec<u8> = Vec::new();
    let mut cai_seg_cnt: u32 = 0;
    let mut cai_index = 0;

    src.rewind()?;

    let buf_reader = BufReader::new(src);
    let mut reader = jfifdump::Reader::new(buf_reader).map_err(|err| CodecError::InvalidAsset {
        src: Some(err.to_string()),
        context: "could not read JPEG segments".to_string(),
    })?;

    while let Ok(seg) = reader.next_segment() {
        match seg.kind {
            jfifdump::SegmentKind::Eoi => {
                let bm = NamedByteSpan {
                    names: vec!["EOI".to_string()],
                    span: ByteSpan {
                        start: seg.position as u64,
                        len: 0,
                    },
                };

                box_maps.push(bm);
            }
            jfifdump::SegmentKind::Soi => {
                let bm = NamedByteSpan {
                    names: vec!["SOI".to_string()],
                    span: ByteSpan {
                        start: seg.position as u64,
                        len: 0,
                    },
                };

                box_maps.push(bm);
            }
            jfifdump::SegmentKind::App { nr, data } if nr == 0x0b => {
                let nr = nr | 0xe0;

                // JUMBF marker
                let raw_bytes = data;

                if raw_bytes.len() > 16 {
                    // we need at least 16 bytes in each segment for CAI
                    let mut raw_vec = raw_bytes.to_vec();
                    let _ci = raw_vec.as_mut_slice()[0..2].to_vec();
                    let en = raw_vec.as_mut_slice()[2..4].to_vec();

                    let is_cai_continuation = vec_compare(&cai_en, &en);

                    if cai_seg_cnt > 0 && is_cai_continuation {
                        cai_seg_cnt += 1;

                        let cai_bm = &mut box_maps[cai_index];
                        cai_bm.span.len += raw_bytes.len() as u64 + 4;
                    } else {
                        // check if this is a CAI JUMBF block
                        let jumb_type = raw_vec.as_mut_slice()[24..28].to_vec();
                        let is_cai = vec_compare(&C2PA_MARKER, &jumb_type);
                        if is_cai {
                            cai_seg_cnt = 1;
                            cai_en.clone_from(&en); // store the identifier

                            let c2pa_bm = NamedByteSpan {
                                names: vec!["C2PA".to_string()],
                                span: ByteSpan {
                                    start: seg.position as u64,
                                    len: raw_bytes.len() as u64 + 4,
                                },
                            };

                            box_maps.push(c2pa_bm);
                            cai_index = box_maps.len() - 1;
                        } else {
                            let name = segment_names.get(&nr).ok_or(CodecError::InvalidAsset {
                                src: None,
                                context: "Unknown segment marker".to_owned(),
                            })?;

                            let bm = NamedByteSpan {
                                names: vec![name.to_string()],
                                span: ByteSpan {
                                    start: seg.position as u64,
                                    len: 0,
                                },
                            };

                            box_maps.push(bm);
                        }
                    }
                }
            }
            jfifdump::SegmentKind::App { nr, data } => {
                let nr = nr | 0xe0;
                let _data = data;

                let name = segment_names.get(&nr).ok_or(CodecError::InvalidAsset {
                    src: None,
                    context: "Unknown segment marker".to_owned(),
                })?;

                let bm = NamedByteSpan {
                    names: vec![name.to_string()],
                    span: ByteSpan {
                        start: seg.position as u64,
                        len: 0,
                    },
                };

                box_maps.push(bm);
            }
            jfifdump::SegmentKind::App0Jfif(_) => {
                let bm = NamedByteSpan {
                    names: vec!["APP0".to_string()],
                    span: ByteSpan {
                        start: seg.position as u64,
                        len: 0,
                    },
                };

                box_maps.push(bm);
            }
            jfifdump::SegmentKind::Dqt(_) => {
                let bm = NamedByteSpan {
                    names: vec!["DQT".to_string()],
                    span: ByteSpan {
                        start: seg.position as u64,
                        len: 0,
                    },
                };

                box_maps.push(bm);
            }
            jfifdump::SegmentKind::Dht(_) => {
                let bm = NamedByteSpan {
                    names: vec!["DHT".to_string()],
                    span: ByteSpan {
                        start: seg.position as u64,
                        len: 0,
                    },
                };

                box_maps.push(bm);
            }
            jfifdump::SegmentKind::Dac(_) => {
                let bm = NamedByteSpan {
                    names: vec!["DAC".to_string()],
                    span: ByteSpan {
                        start: seg.position as u64,
                        len: 0,
                    },
                };

                box_maps.push(bm);
            }
            jfifdump::SegmentKind::Frame(f) => {
                let name = segment_names.get(&f.sof).ok_or(CodecError::InvalidAsset {
                    src: None,
                    context: "Unknown segment marker".to_owned(),
                })?;

                let bm = NamedByteSpan {
                    names: vec![name.to_string()],
                    span: ByteSpan {
                        start: seg.position as u64,
                        len: 0,
                    },
                };

                box_maps.push(bm);
            }
            jfifdump::SegmentKind::Scan(_s) => {
                let bm = NamedByteSpan {
                    names: vec!["SOS".to_string()],
                    span: ByteSpan {
                        start: seg.position as u64,
                        len: 0,
                    },
                };

                box_maps.push(bm);
            }
            jfifdump::SegmentKind::Dri(_) => {
                let bm = NamedByteSpan {
                    names: vec!["DRI".to_string()],
                    span: ByteSpan {
                        start: seg.position as u64,
                        len: 0,
                    },
                };

                box_maps.push(bm);
            }
            jfifdump::SegmentKind::Rst(_r) => (),
            jfifdump::SegmentKind::Comment(_) => {
                let bm = NamedByteSpan {
                    names: vec!["COM".to_string()],
                    span: ByteSpan {
                        start: seg.position as u64,
                        len: 0,
                    },
                };

                box_maps.push(bm);
            }
            jfifdump::SegmentKind::Unknown { marker, data: _ } => {
                let name = segment_names.get(&marker).ok_or(CodecError::InvalidAsset {
                    src: None,
                    context: "Unknown segment marker".to_owned(),
                })?;

                let bm = NamedByteSpan {
                    names: vec![name.to_string()],
                    span: ByteSpan {
                        start: seg.position as u64,
                        len: 0,
                    },
                };

                box_maps.push(bm);
            }
        }
    }

    Ok(box_maps)
}

impl<R: Read + Seek> Embed for JpegCodec<R> {
    fn embeddable(bytes: &[u8]) -> Result<Embeddable, CodecError> {
        let jumbf_len = bytes.len();
        let num_segments = (jumbf_len / MAX_JPEG_MARKER_SIZE) + 1;
        let mut seg_chucks = bytes.chunks(MAX_JPEG_MARKER_SIZE);

        let mut segments = Vec::new();

        for seg in 1..num_segments + 1 {
            /*
                If the size of the box payload is less than 2^32-8 bytes,
                then all fields except the XLBox field, that is: Le, CI, En, Z, LBox and TBox,
                shall be present in all JPEG XT marker segment representing this box,
                regardless of whether the marker segments starts this box,
                or continues a box started by a former JPEG XT Marker segment.
            */
            // we need to prefix the JUMBF with the JPEG XT markers (ISO 19566-5)
            // CI: JPEG extensions marker - JP
            // En: Box Instance Number  - 0x0001
            //          (NOTE: can be any unique ID, so we pick one that shouldn't conflict)
            // Z: Packet sequence number - 0x00000001...
            let ci = vec![0x4a, 0x50];
            let en = vec![0x02, 0x11];
            let z: u32 = u32::try_from(seg).map_err(|err| CodecError::InvalidAsset {
                src: Some(err.to_string()),
                context: "Too many JUMBF segments".to_string(),
            })?; //seg.to_be_bytes();

            let mut seg_data = Vec::new();
            seg_data.extend(ci);
            seg_data.extend(en);
            seg_data.extend(z.to_be_bytes());
            if seg > 1 {
                // the LBox and TBox are already in the JUMBF
                // but we need to duplicate them in all other segments
                let lbox_tbox = &bytes[..8];
                seg_data.extend(lbox_tbox);
            }
            if seg_chucks.len() > 0 {
                // make sure we have some...
                if let Some(next_seg) = seg_chucks.next() {
                    seg_data.extend(next_seg);
                }
            } else {
                seg_data.extend(bytes);
            }

            let seg_bytes = Bytes::from(seg_data);
            let app11_segment = JpegSegment::new_with_contents(markers::APP11, seg_bytes);
            segments.push(app11_segment);
        }

        let output = Vec::with_capacity(bytes.len() * 2);
        let mut out_stream = Cursor::new(output);

        // right out segments
        for s in segments {
            // maker
            out_stream.write_u8(markers::P)?;
            out_stream.write_u8(s.marker())?;

            //len
            out_stream.write_u16::<BigEndian>(s.contents().len() as u16 + 2)?;

            // data
            out_stream.write_all(s.contents())?;
        }

        Ok(Embeddable {
            bytes: out_stream.into_inner(),
        })
    }

    fn embed(&mut self, embeddable: Embeddable, dst: impl Write) -> Result<(), CodecError> {
        todo!()
    }
}

#[cfg(test)]
pub mod tests {
    //     #![allow(clippy::unwrap_used)]

    //     use std::io::{Read, Seek};

    //     #[cfg(target_arch = "wasm32")]
    //     use wasm_bindgen_test::*;

    //     use super::*;
    //     #[test]
    //     fn test_extract_xmp() {
    //         let contents = Bytes::from_static(b"http://ns.adobe.com/xap/1.0/\0stuff");
    //         let seg = JpegSegment::new_with_contents(markers::APP1, contents);
    //         let result = extract_xmp(&seg);
    //         assert_eq!(result, Some("stuff".to_owned()));

    //         let contents = Bytes::from_static(b"http://ns.adobe.com/xap/1.0/ stuff");
    //         let seg = JpegSegment::new_with_contents(markers::APP1, contents);
    //         let result = extract_xmp(&seg);
    //         assert_eq!(result, Some("stuff".to_owned()));

    //         let contents = Bytes::from_static(b"tiny");
    //         let seg = JpegSegment::new_with_contents(markers::APP1, contents);
    //         let result = extract_xmp(&seg);
    //         assert_eq!(result, None);
    //     }

    //     #[test]
    //     fn test_remove_c2pa() {
    //         let source = crate::utils::test::fixture_path("CA.jpg");

    //         let temp_dir = tempfile::tempdir().unwrap();
    //         let output = crate::utils::test::temp_dir_path(&temp_dir, "CA_test.jpg");

    //         std::fs::copy(source, &output).unwrap();
    //         let jpeg_io = JpegCodec {};

    //         jpeg_io.remove_cai_store(&output).unwrap();

    //         // read back in asset, JumbfNotFound is expected since it was removed
    //         match jpeg_io.read_cai_store(&output) {
    //             Err(Error::JumbfNotFound) => (),
    //             _ => unreachable!(),
    //         }
    //     }

    //     #[test]
    //     fn test_remove_c2pa_from_stream() {
    //         let source = crate::utils::test::fixture_path("CA.jpg");

    //         let source_bytes = std::fs::read(source).unwrap();
    //         let mut source_stream = Cursor::new(source_bytes);

    //         let jpeg_io = JpegCodec {};
    //         let jpg_writer = jpeg_io.get_writer("jpg").unwrap();

    //         let output_bytes = Vec::new();
    //         let mut output_stream = Cursor::new(output_bytes);

    //         jpg_writer
    //             .remove_cai_store_from_stream(&mut source_stream, &mut output_stream)
    //             .unwrap();

    //         // read back in asset, JumbfNotFound is expected since it was removed
    //         let jpg_reader = jpeg_io.get_reader();
    //         match jpg_reader.read_cai(&mut output_stream) {
    //             Err(Error::JumbfNotFound) => (),
    //             _ => unreachable!(),
    //         }
    //     }

    //     #[test]
    //     fn test_xmp_read_write() {
    //         let source = crate::utils::test::fixture_path("CA.jpg");

    //         let temp_dir = tempfile::tempdir().unwrap();
    //         let output = crate::utils::test::temp_dir_path(&temp_dir, "CA_test.jpg");

    //         std::fs::copy(source, &output).unwrap();

    //         let test_msg = "this some test xmp data";
    //         let handler = JpegCodec::new("");

    //         // write xmp
    //         let assetio_handler = handler.get_handler("jpg");

    //         let remote_ref_handler = assetio_handler.remote_ref_writer_ref().unwrap();

    //         remote_ref_handler
    //             .embed_reference(&output, RemoteRefEmbedType::Xmp(test_msg.to_string()))
    //             .unwrap();

    //         // read back in XMP
    //         let mut file_reader = std::fs::File::open(&output).unwrap();
    //         let read_xmp = assetio_handler
    //             .get_reader()
    //             .read_xmp(&mut file_reader)
    //             .unwrap();

    //         assert!(read_xmp.contains(test_msg));
    //     }

    //     #[cfg_attr(not(target_arch = "wasm32"), actix::test)]
    //     #[cfg_attr(target_arch = "wasm32", wasm_bindgen_test)]
    //     async fn test_xmp_read_write_stream() {
    //         let source_bytes = include_bytes!("../../tests/fixtures/CA.jpg");

    //         let test_msg = "this some test xmp data";
    //         let handler = JpegCodec::new("");

    //         let assetio_handler = handler.get_handler("jpg");

    //         let remote_ref_handler = assetio_handler.remote_ref_writer_ref().unwrap();

    //         let mut source_stream = Cursor::new(source_bytes.to_vec());
    //         let mut output_stream = Cursor::new(Vec::new());
    //         remote_ref_handler
    //             .embed_reference_to_stream(
    //                 &mut source_stream,
    //                 &mut output_stream,
    //                 RemoteRefEmbedType::Xmp(test_msg.to_string()),
    //             )
    //             .unwrap();

    //         output_stream.set_position(0);

    //         // read back in XMP
    //         let read_xmp = assetio_handler
    //             .get_reader()
    //             .read_xmp(&mut output_stream)
    //             .unwrap();

    //         output_stream.set_position(0);

    //         //std::fs::write("../target/xmp_write.jpg", output_stream.into_inner()).unwrap();

    //         assert!(read_xmp.contains(test_msg));
    //     }

    //     #[test]
    //     fn test_embeddable_manifest() {
    //         let jpeg_io = JpegCodec {};

    //         let source = crate::utils::test::fixture_path("CA.jpg");

    //         let ol = jpeg_io.get_object_locations(&source).unwrap();

    //         let cai_loc = ol
    //             .iter()
    //             .find(|o| o.htype == HashBlockObjectType::Cai)
    //             .unwrap();
    //         let curr_manifest = jpeg_io.read_cai_store(&source).unwrap();

    //         let temp_dir = tempfile::tempdir().unwrap();
    //         let output = crate::utils::test::temp_dir_path(&temp_dir, "CA_test.jpg");

    //         std::fs::copy(source, &output).unwrap();

    //         // remove existing
    //         jpeg_io.remove_cai_store(&output).unwrap();

    //         // generate new manifest data
    //         let em = jpeg_io
    //             .composed_data_ref()
    //             .unwrap()
    //             .compose_manifest(&curr_manifest, "jpeg")
    //             .unwrap();

    //         // insert new manifest
    //         let outbuf = Vec::new();
    //         let mut out_stream = Cursor::new(outbuf);

    //         let mut before = vec![0u8; cai_loc.offset];
    //         let mut in_file = std::fs::File::open(&output).unwrap();

    //         // write before
    //         in_file.read_exact(before.as_mut_slice()).unwrap();
    //         out_stream.write_all(&before).unwrap();

    //         // write composed bytes
    //         out_stream.write_all(&em).unwrap();

    //         // write bytes after
    //         let mut after_buf = Vec::new();
    //         in_file.read_to_end(&mut after_buf).unwrap();
    //         out_stream.write_all(&after_buf).unwrap();

    //         // read manifest back in from new in-memory JPEG
    //         out_stream.rewind().unwrap();
    //         let restored_manifest = jpeg_io.read_cai(&mut out_stream).unwrap();

    //         assert_eq!(&curr_manifest, &restored_manifest);
    //     }
}
