// Copyright 2023 Adobe. All rights reserved.
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
    io::{Cursor, Seek, SeekFrom},
    result,
};

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use riff::*;

use crate::{
    asset_io::{
        AssetIO, AssetPatch, C2paReader, C2paWriter, ObjectLocations, ObjectType, ReadSeek,
        ReadWriteSeek, RemoteManifestUrl, WriteXmp,
    },
    error::{Error, Result},
    utils::io_utils::stream_len,
};

static SUPPORTED_TYPES: [&str; 13] = [
    "avi",
    "wav",
    "webp",
    "image/webp",
    "image/x-webp",
    "audio/wav",
    "audio/wave",
    "audio/x-wav",
    "audio/vnd.wave",
    "application/x-troff-msvideo",
    "video/avi",
    "video/msvideo",
    "video/x-msvideo",
];

const MAX_DEPTH: usize = 32; // max depth to search for VP8/VP8L chunks

pub struct RiffIO {
    #[allow(dead_code)]
    riff_format: String, // can be used for specialized RIFF cases
}

const C2PA_CHUNK_ID: ChunkId = ChunkId {
    value: [0x43, 0x32, 0x50, 0x41],
}; // C2PA

const VP8X_ID: ChunkId = ChunkId {
    value: [0x56, 0x50, 0x38, 0x58],
}; // VP8X  chunk to hold auxiliary info

const VP8_ID: ChunkId = ChunkId {
    value: [0x56, 0x50, 0x38, 0x20],
}; // VP8 chunk

const VP8L_ID: ChunkId = ChunkId {
    value: [0x56, 0x50, 0x38, 0x4c],
}; // VP8L chunk

const XMP_CHUNK_ID: ChunkId = ChunkId {
    value: [0x58, 0x4d, 0x50, 0x20],
}; // XMP

const AVIX_ID: ChunkId = ChunkId {
    value: [0x41, 0x56, 0x49, 0x58],
}; // AVIX - AVI extended for files > 1GB

const XMP_FLAG: u32 = 4;

/// Returns the byte offset one past the end of `chunk`'s data
/// (`chunk.offset() + 8 header bytes + chunk.len() data bytes`), or `None` on overflow.
fn chunk_data_end(chunk: &Chunk) -> Option<u64> {
    chunk
        .offset()
        .checked_add(8)?
        .checked_add(chunk.len() as u64)
}

fn get_height_and_width(chunk_contents: &[ChunkContents]) -> Result<(u16, u16)> {
    if let Some(ChunkContents::Data(_id, chunk_data)) = chunk_contents.iter().find(|c| match c {
        ChunkContents::Data(id, _) => *id == VP8L_ID,
        _ => false,
    }) {
        let mut chunk_stream = Cursor::new(chunk_data);
        chunk_stream.seek(SeekFrom::Start(1))?; // skip signature byte

        // width and length are 12 bits packed together
        let first_bytes = chunk_stream.read_u16::<LittleEndian>()?;
        let width = 1 + (first_bytes & 0x3fff); // add 1 for VP8L
        let last_two = (first_bytes & 0xc000) >> 14; // last two bits of first bytes are first 2 of height
        let height = 1 + (((chunk_stream.read_u16::<LittleEndian>()? & 0xfff) << 2) | last_two);

        return Ok((height, width));
    }

    if let Some(ChunkContents::Data(_id, chunk_data)) = chunk_contents.iter().find(|c| match c {
        ChunkContents::Data(id, _) => *id == VP8_ID,
        _ => false,
    }) {
        let mut chunk_stream = Cursor::new(chunk_data);
        chunk_stream.seek(SeekFrom::Start(6))?; // skip frame tag and start code

        let width = chunk_stream.read_u16::<LittleEndian>()? & 0x3fff;
        let height = chunk_stream.read_u16::<LittleEndian>()? & 0x3fff;

        return Ok((height, width));
    }

    Err(Error::InvalidAsset(
        "WEBP missing VP8 or VP8L segment".to_string(),
    ))
}

fn inject_c2pa<T>(
    chunk: &Chunk,
    stream: &mut T,
    data: &[u8],
    xmp_data: Option<&[u8]>,
    format: &str,
    depth: usize,
) -> Result<ChunkContents>
where
    T: Seek + std::io::Read,
{
    let id = chunk.id();
    let is_riff_chunk: bool = id == RIFF_ID;
    stream.rewind()?;

    if depth > MAX_DEPTH {
        return Err(Error::InvalidAsset(
            "RIFF chunk nesting too deep".to_string(),
        ));
    }

    if is_riff_chunk || id == LIST_ID {
        let chunk_type = chunk.read_type(stream).map_err(|_| {
            Error::InvalidAsset("RIFF handler could not parse file format {format}".to_string())
        })?;
        let mut children = chunk
            .iter(stream)
            .collect::<result::Result<Vec<Chunk>, _>>()?;

        let mut children_contents: Vec<ChunkContents> = Vec::new();

        if is_riff_chunk && !data.is_empty() {
            // remove c2pa manifest store in RIFF chunk
            children.retain(|c| c.id() != C2PA_CHUNK_ID);
        }

        if is_riff_chunk && xmp_data.is_some() {
            // remove XMP in RIFF chunk so we can replace
            children.retain(|c| c.id() != XMP_CHUNK_ID);
        }

        // duplicate all top level children
        for child in children {
            children_contents.push(inject_c2pa(
                &child,
                stream,
                data,
                xmp_data,
                format,
                depth + 1,
            )?);
        }

        // add XMP if needed
        if let Some(xmp) = xmp_data {
            if is_riff_chunk && !xmp.is_empty() {
                // if this is a webp doc we must also update VP8X
                if format == "webp" {
                    // if already present we can patch otherwise add
                    if let Some(ChunkContents::Data(_id, chunk_data)) =
                        children_contents.iter_mut().find(|c| match c {
                            ChunkContents::Data(id, _) => *id == VP8X_ID,
                            _ => false,
                        })
                    {
                        let mut chunk_stream = Cursor::new(chunk_data);

                        let mut flags = chunk_stream.read_u32::<LittleEndian>()?;

                        // add in XMP flag
                        flags |= XMP_FLAG;

                        chunk_stream.rewind()?;

                        // write back changes
                        chunk_stream.write_u32::<LittleEndian>(flags)?;
                    } else {
                        // add new VP8X

                        // get height and width from VBL
                        if let Ok((height, width)) = get_height_and_width(&children_contents) {
                            let data: Vec<u8> = Vec::new();
                            let mut chunk_writer = Cursor::new(data);

                            let flags: u32 = XMP_FLAG;
                            let vp8x_height = height as u32 - 1;
                            let vp8x_width = width as u32 - 1;

                            // write flags
                            chunk_writer.write_u32::<LittleEndian>(flags)?;

                            // write width then height
                            chunk_writer.write_u24::<LittleEndian>(vp8x_width)?;
                            chunk_writer.write_u24::<LittleEndian>(vp8x_height)?;

                            // make new VP8X chunk and prepend to children list
                            let mut tmp_vec: Vec<ChunkContents> = Vec::new();
                            tmp_vec.push(ChunkContents::Data(VP8X_ID, chunk_writer.into_inner()));
                            tmp_vec.extend(children_contents);
                            children_contents = tmp_vec;
                        } else {
                            return Err(Error::InvalidAsset(
                                "Could not parse VP8 or VP8L".to_string(),
                            ));
                        }
                    }
                }

                children_contents.push(ChunkContents::Data(XMP_CHUNK_ID, xmp.to_vec()));
            }
        }

        // place at the end for maximum compatibility
        if is_riff_chunk && !data.is_empty() {
            children_contents.push(ChunkContents::Data(C2PA_CHUNK_ID, data.to_vec()));
        }

        Ok(ChunkContents::Children(id, chunk_type, children_contents))
    } else if id == SEQT_ID {
        let children = chunk
            .iter(stream)
            .collect::<result::Result<Vec<Chunk>, _>>()?;

        let mut children_contents: Vec<ChunkContents> = Vec::new();

        for child in children {
            children_contents.push(inject_c2pa(
                &child,
                stream,
                data,
                xmp_data,
                format,
                depth + 1,
            )?);
        }

        Ok(ChunkContents::ChildrenNoType(id, children_contents))
    } else {
        let stream_end = stream.seek(SeekFrom::End(0))?;
        let chunk_end = chunk_data_end(chunk)
            .ok_or_else(|| Error::InvalidAsset("RIFF chunk size overflow".to_string()))?;
        if chunk_end > stream_end {
            return Err(Error::InvalidAsset(
                "RIFF chunk declared size exceeds file size".to_string(),
            ));
        }
        let contents = chunk
            .read_contents(stream)
            .map_err(|_| Error::InvalidAsset("RIFF handler could not parse file".to_string()))?;
        Ok(ChunkContents::Data(id, contents))
    }
}

fn get_manifest_pos(mut reader: &mut dyn ReadSeek) -> Option<(u64, u32)> {
    reader.rewind().ok()?;

    let top_level_chunks = Chunk::read(&mut reader, 0).ok()?;

    if top_level_chunks.id() == RIFF_ID {
        for chunk in top_level_chunks.iter(&mut reader) {
            let chunk = chunk.ok()?;
            if chunk.id() == C2PA_CHUNK_ID {
                return Some((chunk.offset(), chunk.len() + 8)); // 8 is len of data chunk header
            }
        }
    }
    None
}

impl C2paReader for RiffIO {
    fn read_c2pa(&self, mut input_stream: &mut dyn ReadSeek) -> Result<Vec<u8>> {
        let file_len = stream_len(input_stream)?;

        let top_level_chunks = Chunk::read(&mut input_stream, 0)?;

        // Assume C2PA data will be in the first chunk, even for multiple RIFF/AVIX chunk files.
        if top_level_chunks.id() != RIFF_ID {
            return Err(Error::InvalidAsset(format!(
                "invalid header: expected \"{}\", got \"{}\"",
                String::from_utf8_lossy(&RIFF_ID.value),
                String::from_utf8_lossy(&top_level_chunks.id().value),
            )));
        }

        for result in top_level_chunks.iter(&mut input_stream) {
            let chunk =
                result.map_err(|_| Error::InvalidAsset("Invalid RIFF format".to_string()))?;

            if chunk.id() == C2PA_CHUNK_ID {
                let chunk_end = chunk_data_end(&chunk)
                    .ok_or_else(|| Error::InvalidAsset("RIFF chunk size overflow".to_string()))?;
                if chunk_end > file_len {
                    return Err(Error::InvalidAsset(
                        "RIFF chunk declared size exceeds file size".to_string(),
                    ));
                }
                return Ok(chunk.read_contents(&mut input_stream)?);
            }
        }

        Err(Error::JumbfNotFound)
    }

    // Get XMP block
    fn read_xmp(&self, mut input_stream: &mut dyn ReadSeek) -> Option<String> {
        let file_len = stream_len(input_stream).ok()?;
        let top_level_chunks = Chunk::read(&mut input_stream, 0).ok()?;

        if top_level_chunks.id() != RIFF_ID {
            return None;
        }

        for chunk in top_level_chunks.iter(&mut input_stream) {
            let chunk = chunk.ok()?;
            if chunk.id() == XMP_CHUNK_ID {
                let chunk_end = chunk_data_end(&chunk)?;
                if chunk_end > file_len {
                    return None;
                }
                let output = chunk.read_contents(&mut input_stream).ok()?;
                return Some(String::from_utf8_lossy(&output).to_string());
            }
        }

        None
    }
}

impl AssetIO for RiffIO {
    fn new(riff_format: &str) -> Self {
        RiffIO {
            riff_format: riff_format.to_string(),
        }
    }

    fn get_handler(&self, asset_type: &str) -> Box<dyn AssetIO> {
        Box::new(RiffIO::new(asset_type))
    }

    fn get_reader(&self) -> &dyn C2paReader {
        self
    }

    fn get_writer(&self, asset_type: &str) -> Option<Box<dyn C2paWriter>> {
        Some(Box::new(RiffIO::new(asset_type)))
    }

    fn asset_patch_ref(&self) -> Option<&dyn AssetPatch> {
        Some(self)
    }

    fn remote_manifest_url_ref(&self) -> Option<&dyn RemoteManifestUrl> {
        Some(self)
    }

    fn write_xmp_ref(&self) -> Option<&dyn WriteXmp> {
        Some(self)
    }

    fn supported_types(&self) -> &[&str] {
        &SUPPORTED_TYPES
    }

    // RIFF covers three distinct sub-formats (WEBP/WAV/AVI), each needing its own MIME
    // type, so the default single-MIME derivation from `supported_types()` doesn't apply.
    fn mime_type_map(&self) -> Vec<(String, String)> {
        [
            ("webp", "image/webp"),
            ("wav", "audio/wav"),
            ("avi", "video/avi"),
        ]
        .into_iter()
        .map(|(ext, mime)| (ext.to_string(), mime.to_string()))
        .collect()
    }
}

impl C2paWriter for RiffIO {
    fn write_c2pa(
        &self,
        mut input_stream: &mut dyn ReadSeek,
        mut output_stream: &mut dyn ReadWriteSeek,
        store_bytes: &[u8],
    ) -> Result<()> {
        let top_level_chunks = Chunk::read(&mut input_stream, 0)?;

        if top_level_chunks.id() != RIFF_ID {
            return Err(Error::InvalidAsset("Invalid RIFF format".to_string()));
        }

        let first_chunk_size = top_level_chunks.len();

        // replace/add manifest in memory
        let new_contents = inject_c2pa(
            &top_level_chunks,
            &mut input_stream,
            store_bytes,
            None,
            &self.riff_format,
            0,
        )?;

        // save contents
        new_contents
            .write(&mut output_stream)
            .map_err(|_e| Error::EmbeddingError)?;

        // Copy additional RIFF/AVIX chunks for large AVI files
        if self.riff_format == "avi" || self.riff_format == "video/avi" {
            // Ensure input_stream is positioned right after the first chunk
            // Position = 8 bytes (chunk ID + size) + chunk data size
            let position_after_first_chunk = 8 + first_chunk_size as u64;
            input_stream.seek(SeekFrom::Start(position_after_first_chunk))?;

            loop {
                // Check if we're at EOF
                let current_pos = input_stream.stream_position()?;
                let file_size = input_stream.seek(SeekFrom::End(0))?;
                input_stream.seek(SeekFrom::Start(current_pos))?;

                if current_pos >= file_size {
                    break;
                }

                // Manually read chunk header (8 bytes: 4-byte ID + 4-byte size)
                let mut chunk_header = [0u8; 8];
                if input_stream.read_exact(&mut chunk_header).is_err() {
                    break; // EOF
                }

                let chunk_id = ChunkId {
                    value: chunk_header[0..4]
                        .try_into()
                        .map_err(|_e| Error::EmbeddingError)?,
                };
                let chunk_size = u32::from_le_bytes(
                    chunk_header[4..8]
                        .try_into()
                        .map_err(|_e| Error::EmbeddingError)?,
                ) as u64;

                if chunk_id != RIFF_ID && chunk_id != AVIX_ID {
                    break;
                }

                // Write the chunk header
                output_stream.write_all(&chunk_id.value)?;
                output_stream.write_all(&(chunk_size as u32).to_le_bytes())?;

                // Copy the chunk data in 1MB chunks
                let mut remaining = chunk_size;
                let mut buffer = vec![0u8; 1024 * 1024];
                while remaining > 0 {
                    let to_read = remaining.min(buffer.len() as u64) as usize;
                    input_stream.read_exact(&mut buffer[..to_read])?;
                    output_stream.write_all(&buffer[..to_read])?;
                    remaining -= to_read as u64;
                }
            }
        }

        Ok(())
    }

    fn get_object_locations(
        &self,
        input_stream: &mut dyn ReadSeek,
    ) -> Result<Vec<ObjectLocations>> {
        let mut positions: Vec<ObjectLocations> = Vec::new();

        let (manifest_pos, manifest_len, file_end) =
            if let Some((position, len)) = get_manifest_pos(input_stream) {
                let file_end = stream_len(input_stream)?;
                (position, len, file_end)
            } else {
                let mut output_stream = Cursor::new(Vec::new());
                self.write_c2pa(input_stream, &mut output_stream, &[1, 2, 3, 4])?;
                let (position, len) =
                    get_manifest_pos(&mut output_stream).ok_or(Error::EmbeddingError)?;
                let file_end = output_stream.seek(SeekFrom::End(0))?;
                (position, len, file_end)
            };

        positions.push(ObjectLocations {
            offset: manifest_pos,
            length: manifest_len as u64,
            htype: ObjectType::C2pa,
        });

        // add hash of chunks before cai
        positions.push(ObjectLocations {
            offset: 0,
            length: manifest_pos,
            htype: ObjectType::Other,
        });

        // add position from cai to end
        let Some(end) = u64::checked_add(manifest_pos, manifest_len as u64) else {
            return Err(Error::InvalidAsset("value out of range".to_string()));
        };
        positions.push(ObjectLocations {
            offset: end, // len of cai
            length: file_end - end,
            htype: ObjectType::Other,
        });

        Ok(positions)
    }

    fn remove_c2pa(
        &self,
        input_stream: &mut dyn ReadSeek,
        output_stream: &mut dyn ReadWriteSeek,
    ) -> Result<()> {
        self.write_c2pa(input_stream, output_stream, &[])
    }
}

impl AssetPatch for RiffIO {
    fn patch_c2pa(&self, stream: &mut dyn ReadWriteSeek, store_bytes: &[u8]) -> Result<()> {
        let (manifest_pos, manifest_len) = get_manifest_pos(stream).ok_or(Error::EmbeddingError)?;

        if store_bytes.len() + 8 == manifest_len as usize {
            stream.seek(SeekFrom::Start(manifest_pos + 8))?; // skip 8 byte chunk data header
            stream.write_all(store_bytes)?;
            Ok(())
        } else {
            Err(Error::InvalidAsset(
                "patch_cai_store store size mismatch.".to_string(),
            ))
        }
    }
}

impl WriteXmp for RiffIO {
    fn write_xmp(
        &self,
        mut input_stream: &mut dyn ReadSeek,
        mut output_stream: &mut dyn ReadWriteSeek,
        xmp: &str,
    ) -> Result<()> {
        let mut new_xmp = xmp.to_string();
        if new_xmp.len() % 2 == 1 {
            // pad if needed to even length
            new_xmp.push(' ');
        }

        let top_level_chunks = Chunk::read(&mut input_stream, 0)?;

        if top_level_chunks.id() != RIFF_ID {
            return Err(Error::InvalidAsset("Invalid RIFF format".to_string()));
        }

        // replace/add manifest in memory
        let new_contents = inject_c2pa(
            &top_level_chunks,
            &mut input_stream,
            &[],
            Some(new_xmp.as_bytes()),
            &self.riff_format,
            0,
        )?;

        // save contents
        new_contents
            .write(&mut output_stream)
            .map_err(|_e| Error::EmbeddingError)?;
        Ok(())
    }
}

#[cfg(test)]
pub mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    use std::{fs::File, panic, path::Path};

    use super::*;
    use crate::utils::{
        hash_utils::vec_compare,
        io_utils::tempdirectory,
        test::{fixture_path, temp_dir_path},
        xmp_inmemory_utils::extract_provenance,
    };

    // test-only equivalent of the removed file-`Path`-based embed method
    fn write_remote_manifest_url(
        handler: &dyn RemoteManifestUrl,
        path: &Path,
        remote_manifest_url: &str,
    ) -> Result<()> {
        let mut input_stream = File::open(path).map_err(Error::IoError)?;
        let mut output_stream = Cursor::new(Vec::new());
        handler.write_remote_manifest_url(
            &mut input_stream,
            &mut output_stream,
            remote_manifest_url,
        )?;
        std::fs::write(path, output_stream.into_inner()).map_err(Error::IoError)
    }

    #[test]
    fn test_write_wav() {
        let more_data = "some more test data".as_bytes();
        let source = fixture_path("sample1.wav");

        let mut success = false;
        if let Ok(temp_dir) = tempdirectory() {
            let output = temp_dir_path(&temp_dir, "sample1-wav.wav");

            if let Ok(_size) = std::fs::copy(source, &output) {
                let riff_io = RiffIO::new("wav");

                if let Ok(()) = riff_io.save_c2pa_store(&output, more_data) {
                    if let Ok(read_test_data) = riff_io.read_cai_store(&output) {
                        assert!(vec_compare(more_data, &read_test_data));
                        success = true;
                    }
                }
            }
        }
        assert!(success)
    }

    #[test]
    fn test_read_cai_forged_c2pa_chunk_size_returns_error() {
        // A 20-byte RIFF file where the C2PA chunk claims 4 GB of data.
        // Without the fix this causes a process abort from OOM (exit 134).
        let mut data = Vec::new();
        data.extend_from_slice(b"RIFF");
        data.extend_from_slice(&12u32.to_le_bytes()); // RIFF data size (covers type + chunk hdr)
        data.extend_from_slice(b"WAVE");
        data.extend_from_slice(b"C2PA");
        data.extend_from_slice(&u32::MAX.to_le_bytes()); // forged 4 GB declared size

        let riff_io = RiffIO::new("wav");
        let mut source = Cursor::new(data);
        assert!(matches!(
            riff_io.read_c2pa(&mut source),
            Err(Error::InvalidAsset(_))
        ));
    }

    #[test]
    fn test_write_cai_forged_chunk_size_returns_error() {
        // Same forged file fed to write_cai, which calls inject_c2pa internally.
        let mut data = Vec::new();
        data.extend_from_slice(b"RIFF");
        data.extend_from_slice(&12u32.to_le_bytes());
        data.extend_from_slice(b"WAVE");
        data.extend_from_slice(b"DATA");
        data.extend_from_slice(&u32::MAX.to_le_bytes()); // forged 4 GB declared size

        let riff_io = RiffIO::new("wav");
        let mut source = Cursor::new(data);
        let mut dest = Cursor::new(Vec::new());
        assert!(matches!(
            riff_io.write_c2pa(&mut source, &mut dest, b"manifest"),
            Err(Error::InvalidAsset(_))
        ));
    }

    #[test]
    fn test_read_cai_with_incorrect_header_size_does_not_panic() {
        let riff_io = RiffIO::new("wav");

        let panic_result = panic::catch_unwind(|| {
            let mut source = File::open(fixture_path("sample3.invalid.wav")).unwrap();
            assert!(matches!(
                riff_io.read_c2pa(&mut source),
                Err(Error::InvalidAsset(_))
            ));
        });

        assert!(panic_result.is_ok());
    }

    #[test]
    fn test_write_cai_with_large_recursion_does_not_panic() {
        let more_data = "some more test data".as_bytes();

        let riff_io = RiffIO::new("wav");
        if let Ok(temp_dir) = tempdirectory() {
            let output = temp_dir_path(&temp_dir, "sample1-wav.wav");

            let panic_result = panic::catch_unwind(|| {
                let mut output_stream = File::create(&output).unwrap();
                let mut source = File::open(fixture_path("riff_bomb_1000.wav")).unwrap();
                assert!(matches!(
                    riff_io.write_c2pa(&mut source, &mut output_stream, more_data),
                    Err(Error::InvalidAsset(_))
                ));
            });

            assert!(panic_result.is_ok());
        }
    }

    #[test]
    fn test_write_wav_stream() {
        let more_data = "some more test data".as_bytes();
        let mut source = File::open(fixture_path("sample1.wav")).unwrap();

        let riff_io = RiffIO::new("wav");
        if let Ok(temp_dir) = tempdirectory() {
            let output = temp_dir_path(&temp_dir, "sample1-wav.wav");

            let mut output_stream = File::create(&output).unwrap();

            riff_io
                .write_c2pa(&mut source, &mut output_stream, more_data)
                .unwrap();

            let mut source = File::open(output).unwrap();
            let read_test_data = riff_io.read_c2pa(&mut source).unwrap();
            assert!(vec_compare(more_data, &read_test_data));
        }
    }

    #[test]
    fn test_patch_write_wav() {
        let test_data = "some test data".as_bytes();
        let source = fixture_path("sample1.wav");

        let mut success = false;
        if let Ok(temp_dir) = tempdirectory() {
            let output = temp_dir_path(&temp_dir, "sample1-wav.wav");

            if let Ok(_size) = std::fs::copy(source, &output) {
                let riff_io = RiffIO::new("wav");

                if let Ok(()) = riff_io.save_c2pa_store(&output, test_data) {
                    if let Ok(source_data) = riff_io.read_cai_store(&output) {
                        // create replacement data of same size
                        let mut new_data = vec![0u8; source_data.len()];
                        new_data[..test_data.len()].copy_from_slice(test_data);
                        riff_io.patch_c2pa_file(&output, &new_data).unwrap();

                        let replaced = riff_io.read_cai_store(&output).unwrap();

                        assert_eq!(new_data, replaced);

                        success = true;
                    }
                }
            }
        }
        assert!(success)
    }

    #[test]
    fn test_remove_c2pa() {
        let source = fixture_path("sample1.wav");

        let temp_dir = tempdirectory().unwrap();
        let output = temp_dir_path(&temp_dir, "sample1-wav.wav");

        std::fs::copy(source, &output).unwrap();
        let riff_io = RiffIO::new("wav");

        riff_io.remove_c2pa_store(&output).unwrap();

        // read back in asset, JumbfNotFound is expected since it was removed
        match riff_io.read_cai_store(&output) {
            Err(Error::JumbfNotFound) => (),
            _ => unreachable!(),
        }
    }

    #[test]
    fn test_read_xmp() {
        let source = fixture_path("test_xmp.webp");
        let mut reader = File::open(source).unwrap();

        let riff_io = RiffIO::new("webp");

        let xmp = riff_io.read_xmp(&mut reader).unwrap();
        println!("XMP: {xmp}");
    }

    #[test]
    fn test_write_xmp() {
        let more_data = "some more test data";
        let source = fixture_path("test_xmp.webp");

        let mut success = false;
        if let Ok(temp_dir) = tempdirectory() {
            let output = temp_dir_path(&temp_dir, "test_xmp.webp");

            std::fs::copy(source, &output).unwrap();

            let riff_io = RiffIO::new("webp");

            if let Some(embed_handler) = riff_io.remote_manifest_url_ref() {
                if let Ok(()) =
                    write_remote_manifest_url(embed_handler, output.as_path(), more_data)
                {
                    let mut output_stream = File::open(&output).unwrap();

                    // check the xmp
                    if let Some(xmp) = riff_io.read_xmp(&mut output_stream) {
                        println!("XMP: {xmp}");

                        if let Some(xmp_val) = extract_provenance(&xmp) {
                            if xmp_val == more_data {
                                success = true;
                            }
                        }
                    }
                }
            }
        }
        assert!(success)
    }

    #[test]
    fn test_insert_xmp() {
        let more_data = "some more test data";
        let source = fixture_path("test.webp");

        let mut success = false;
        if let Ok(temp_dir) = tempdirectory() {
            let output = temp_dir_path(&temp_dir, "test.webp");

            std::fs::copy(source, &output).unwrap();

            let riff_io = RiffIO::new("webp");

            if let Some(embed_handler) = riff_io.remote_manifest_url_ref() {
                if let Ok(()) =
                    write_remote_manifest_url(embed_handler, output.as_path(), more_data)
                {
                    let mut output_stream = File::open(&output).unwrap();

                    // check the xmp
                    if let Some(xmp) = riff_io.read_xmp(&mut output_stream) {
                        println!("XMP: {xmp}");

                        if let Some(xmp_val) = extract_provenance(&xmp) {
                            if xmp_val == more_data {
                                success = true;
                            }
                        }
                    }
                }
            }
        }
        assert!(success)
    }

    #[test]
    fn test_insert_xmp_lossless() {
        let more_data = "some more test data";
        let source = fixture_path("test_lossless.webp");

        let mut success = false;
        if let Ok(temp_dir) = tempdirectory() {
            let output = temp_dir_path(&temp_dir, "test_lossless.webp");

            std::fs::copy(source, &output).unwrap();

            let riff_io = RiffIO::new("webp");

            if let Some(embed_handler) = riff_io.remote_manifest_url_ref() {
                if let Ok(()) =
                    write_remote_manifest_url(embed_handler, output.as_path(), more_data)
                {
                    let mut output_stream = File::open(&output).unwrap();

                    // check the xmp
                    if let Some(xmp) = riff_io.read_xmp(&mut output_stream) {
                        println!("XMP: {xmp}");

                        if let Some(xmp_val) = extract_provenance(&xmp) {
                            if xmp_val == more_data {
                                success = true;
                            }
                        }
                    }
                }
            }
        }
        assert!(success)
    }

    #[test]
    fn test_avi_support() {
        // Test basic AVI file support
        let source = fixture_path("test.avi");
        let mut f = File::open(source).unwrap();
        let riff_io = RiffIO::new("avi");

        // Should work even though file doesn't have C2PA yet
        assert!(matches!(
            riff_io.read_c2pa(&mut f),
            Err(Error::JumbfNotFound)
        ));
    }

    #[test]
    #[ignore] // Large file test - requires ~4.4GB AVI file
    fn test_large_avi_avix_support() {
        // This test verifies that large AVI files with AVIX chunks work correctly
        // Run with: cargo test test_large_avi_avix_support -- --ignored --nocapture

        use std::{
            io::{BufReader, Write},
            sync::{
                atomic::{AtomicBool, Ordering},
                Arc,
            },
            thread,
            time::Duration,
        };

        use tempfile::NamedTempFile;

        let test_file = "tests/fixtures/bigbunny-3.avi";
        let source_size = std::fs::metadata(test_file).unwrap().len();

        let mut source = File::open(test_file).unwrap();
        let mut dest = NamedTempFile::new().unwrap();

        let riff_io = RiffIO::new("avi");
        let test_data = b"C2PA test data for large AVIX file";

        eprintln!("Writing C2PA data to large AVI...");
        let start = std::time::Instant::now();

        // Set up timeout - fail if write takes more than 15 seconds
        let timeout_flag = Arc::new(AtomicBool::new(false));
        let timeout_flag_clone = timeout_flag.clone();
        thread::spawn(move || {
            thread::sleep(Duration::from_secs(15));
            timeout_flag_clone.store(true, Ordering::SeqCst);
        });

        let write_result = riff_io.write_c2pa(&mut source, &mut dest, test_data);
        let write_duration = start.elapsed();

        assert!(
            !timeout_flag.load(Ordering::SeqCst),
            "Test timed out after 15 seconds"
        );

        if let Err(e) = write_result {
            panic!("write_cai failed: {e:?}");
        }

        eprintln!("Write completed in {write_duration:?}");

        // Verify output size
        dest.flush().unwrap();
        let dest_size = dest.as_file().metadata().unwrap().len();

        // Output should be similar size to input (plus C2PA data)
        assert!(
            dest_size > source_size,
            "Output should be larger than source"
        );
        assert!(
            dest_size < source_size + 1_000_000,
            "Output shouldn't be much larger than source"
        );

        // Read back the C2PA data
        eprintln!("Reading C2PA data back...");
        dest.rewind().unwrap();
        let mut buffered_dest = BufReader::new(dest.as_file());
        let read_data = riff_io.read_c2pa(&mut buffered_dest).unwrap();
        assert_eq!(read_data, test_data);
        eprintln!("✓ Successfully read C2PA data from large AVI file");
    }

    #[test]
    #[ignore] // Large file test - run manually
    fn test_large_avi_write_cai() {
        // This test requires a large AVI file (>1GB with AVIX chunks)
        // Run with: cargo test test_large_avi_write_cai -- --ignored
        use std::io::Cursor;

        let test_file = "tests/fixtures/large_test.avi";
        if !std::path::Path::new(test_file).exists() {
            println!("Skipping test - {test_file} not found");
            return;
        }

        let mut source = File::open(test_file).unwrap();
        let mut dest = Cursor::new(Vec::new());

        let riff_io = RiffIO::new("avi");
        let test_data = b"test C2PA data for large AVI";

        // Write C2PA data
        riff_io
            .write_c2pa(&mut source, &mut dest, test_data)
            .unwrap();

        // Verify output size is reasonable (should be close to source + C2PA data)
        let source_size = std::fs::metadata(test_file).unwrap().len();
        let dest_size = dest.get_ref().len() as u64;

        println!("Source: {source_size} bytes, Dest: {dest_size} bytes");
        assert!(dest_size > source_size); // Should be larger with C2PA
        assert!(dest_size < source_size + 100_000); // But not too much larger

        // Try to read it back
        dest.set_position(0);
        let read_data = riff_io.read_c2pa(&mut dest).unwrap();
        assert_eq!(read_data, test_data);
    }

    #[test]
    #[ignore] // Large file test - run manually
    fn test_large_avi_builder_sign() {
        // Test Builder.sign() with large AVI file
        // Run with: cargo test test_large_avi_builder_sign -- --ignored
        use std::io::Cursor;

        use crate::{utils::test_signer::test_signer, Builder, SigningAlg};

        let test_file = "tests/fixtures/bigbunny-3.avi";

        let manifest_json = r#"{
            "claim_generator": "test_app/1.0",
            "title": "Large AVI Test"
        }"#;

        let mut builder = Builder::default().with_definition(manifest_json).unwrap();
        let mut source = File::open(test_file).unwrap();
        let mut dest = Cursor::new(Vec::new());

        let signer = test_signer(SigningAlg::Ps256);

        // This should complete without hanging
        let start = std::time::Instant::now();
        builder
            .sign(signer.as_ref(), "video/avi", &mut source, &mut dest)
            .unwrap();
        let duration = start.elapsed();

        println!("Signing took {duration:?}");

        // Verify we got output
        assert!(!dest.get_ref().is_empty());

        // Verify the output size
        let source_size = std::fs::metadata(test_file).unwrap().len();
        let dest_size = dest.get_ref().len() as u64;
        println!("Source: {source_size} bytes, Dest: {dest_size} bytes");
        assert!(dest_size > source_size); // Should be larger with C2PA
        assert!(dest_size < source_size + 100_000); // But not too much larger
    }
}
