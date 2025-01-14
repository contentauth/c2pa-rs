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
    collections::{hash_map::Entry::Vacant, HashMap},
    fmt,
    io::{BufReader, Cursor, Read, Seek},
    ops::Deref,
};

use mp4::*;
use serde::{
    de::{SeqAccess, Visitor},
    ser::SerializeSeq,
    Deserialize, Deserializer, Serialize, Serializer,
};
use serde_bytes::ByteBuf;
use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::{
    assertion::{Assertion, AssertionBase, AssertionCbor},
    assertions::labels,
    asset_handlers::bmff_io::{bmff_to_jumbf_exclusions, read_bmff_c2pa_boxes, BoxInfoLite},
    asset_io::CAIRead,
    cbor_types::UriT,
    utils::{
        hash_utils::{
            concat_and_hash, hash_stream_by_alg, vec_compare, verify_stream_by_alg, HashRange,
            Hasher,
        },
        io_utils::stream_len,
        merkle::C2PAMerkleTree,
    },
    Error,
};

const ASSERTION_CREATION_VERSION: usize = 2;

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct ExclusionsMap {
    pub xpath: String,
    pub length: Option<u32>,
    pub data: Option<Vec<DataMap>>,
    pub subset: Option<Vec<SubsetMap>>,
    pub version: Option<u8>,
    pub flags: Option<ByteBuf>,
    pub exact: Option<bool>,
}

impl ExclusionsMap {
    pub fn new(xpath: String) -> Self {
        ExclusionsMap {
            xpath,
            length: None,
            data: None,
            subset: None,
            version: None,
            flags: None,
            exact: None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VecByteBuf(Vec<ByteBuf>);

impl Deref for VecByteBuf {
    type Target = Vec<ByteBuf>;

    fn deref(&self) -> &Vec<ByteBuf> {
        &self.0
    }
}

impl Serialize for VecByteBuf {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(self.0.len()))?;
        for e in &self.0 {
            seq.serialize_element(e)?;
        }
        seq.end()
    }
}

struct VecByteBufVisitor;

impl<'de> Visitor<'de> for VecByteBufVisitor {
    type Value = VecByteBuf;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("Vec<ByteBuf>")
    }

    fn visit_seq<V>(self, mut visitor: V) -> std::result::Result<Self::Value, V::Error>
    where
        V: SeqAccess<'de>,
    {
        let len = std::cmp::min(visitor.size_hint().unwrap_or(0), 4096);
        let mut byte_bufs: Vec<ByteBuf> = Vec::with_capacity(len);

        while let Some(b) = visitor.next_element()? {
            byte_bufs.push(b);
        }

        Ok(VecByteBuf(byte_bufs))
    }
}

impl<'de> Deserialize<'de> for VecByteBuf {
    fn deserialize<D>(deserializer: D) -> std::result::Result<VecByteBuf, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(VecByteBufVisitor {})
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct MerkleMap {
    #[serde(rename = "uniqueId")]
    pub unique_id: u32,

    #[serde(rename = "localId")]
    pub local_id: u32,

    pub count: u32,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,

    #[serde(rename = "initHash", skip_serializing_if = "Option::is_none")]
    pub init_hash: Option<ByteBuf>,

    pub hashes: VecByteBuf,
}

impl MerkleMap {
    pub fn hash_check(&self, indx: u32, merkle_hash: &[u8]) -> bool {
        if let Some(h) = self.hashes.get(indx as usize) {
            vec_compare(h, merkle_hash)
        } else {
            false
        }
    }

    pub fn check_merkle_tree(
        &self,
        alg: &str,
        hash: &[u8],
        location: u32,
        proof: &Option<VecByteBuf>,
    ) -> bool {
        if location >= self.count {
            return false;
        }

        let mut index = location;
        let mut hash = hash.to_vec();
        let layers = C2PAMerkleTree::to_layout(self.count as usize);

        if let Some(hashes) = proof {
            // playback proof
            let mut proof_index = 0;
            for layer in layers {
                let is_right = index % 2 == 1;

                if layer == self.hashes.len() {
                    break;
                }

                if is_right {
                    if index - 1 < layer as u32 {
                        // make sure proof structure is valid
                        if let Some(proof_hash) = hashes.get(proof_index) {
                            hash = concat_and_hash(alg, proof_hash, Some(&hash));
                            proof_index += 1;
                        } else {
                            return false;
                        }
                    }
                } else if index + 1 < layer as u32 {
                    // make sure proof structure is valid
                    if let Some(proof_hash) = hashes.get(proof_index) {
                        hash = concat_and_hash(alg, &hash, Some(proof_hash));
                        proof_index += 1;
                    } else {
                        return false;
                    }
                }

                index /= 2;
            }
        } else {
            //empty proof playback
            for layer in layers {
                if layer == self.hashes.len() {
                    break;
                }
                index /= 2;
            }
        }

        self.hash_check(index, &hash)
    }
}

#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct BmffMerkleMap {
    #[serde(rename = "uniqueId")]
    pub unique_id: u32,

    #[serde(rename = "localId")]
    pub local_id: u32,

    pub location: u32,

    pub hashes: Option<VecByteBuf>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct DataMap {
    pub offset: u32,
    #[serde(with = "serde_bytes")]
    pub value: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct SubsetMap {
    pub offset: u32,
    pub length: u32,
}

/// Helper class to create BmffHash assertion. (These are auto-generated by the SDK.)
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct BmffHash {
    exclusions: Vec<ExclusionsMap>,

    #[serde(skip_serializing_if = "Option::is_none")]
    alg: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    hash: Option<ByteBuf>,

    #[serde(skip_serializing_if = "Option::is_none")]
    merkle: Option<Vec<MerkleMap>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,

    #[serde(skip_serializing)]
    url: Option<UriT>, // deprecated in V2 and not to be used

    #[serde(skip)]
    bmff_version: usize,
}

impl BmffHash {
    pub const LABEL: &'static str = labels::BMFF_HASH;

    pub fn new(name: &str, alg: &str, url: Option<UriT>) -> Self {
        BmffHash {
            exclusions: Vec::new(),
            alg: Some(alg.to_string()),
            hash: None,
            merkle: None,
            name: Some(name.to_string()),
            url,
            bmff_version: ASSERTION_CREATION_VERSION,
        }
    }

    pub fn exclusions(&self) -> &[ExclusionsMap] {
        self.exclusions.as_ref()
    }

    pub fn exclusions_mut(&mut self) -> &mut Vec<ExclusionsMap> {
        &mut self.exclusions
    }

    pub fn alg(&self) -> Option<&String> {
        self.alg.as_ref()
    }

    pub fn hash(&self) -> Option<&Vec<u8>> {
        self.hash.as_deref()
    }

    pub fn merkle(&self) -> Option<&Vec<MerkleMap>> {
        self.merkle.as_ref()
    }

    pub fn set_hash(&mut self, hash: Vec<u8>) {
        self.hash = Some(ByteBuf::from(hash));
    }

    pub fn clear_hash(&mut self) {
        self.hash = None;
    }

    pub fn name(&self) -> Option<&String> {
        self.name.as_ref()
    }

    pub fn url(&self) -> Option<&UriT> {
        self.url.as_ref()
    }

    pub fn bmff_version(&self) -> usize {
        self.bmff_version
    }

    fn set_bmff_version(&mut self, version: usize) {
        self.bmff_version = version;
    }

    /// Returns `true` if this is a remote hash.
    pub fn is_remote_hash(&self) -> bool {
        self.url.is_some()
    }

    pub fn set_merkle(&mut self, merkle: Vec<MerkleMap>) {
        self.merkle = Some(merkle);
    }

    /// Generate the hash value for the asset using the range from the BmffHash.
    #[cfg(feature = "file_io")]
    pub fn gen_hash(&mut self, asset_path: &std::path::Path) -> crate::error::Result<()> {
        let mut file = std::fs::File::open(asset_path)?;
        self.hash = Some(ByteBuf::from(self.hash_from_stream(&mut file)?));
        Ok(())
    }

    /// Generate the hash value for the asset using the range from the BmffHash.
    pub fn gen_hash_from_stream<R>(&mut self, asset_stream: &mut R) -> crate::error::Result<()>
    where
        R: Read + Seek + ?Sized,
    {
        self.hash = Some(ByteBuf::from(self.hash_from_stream(asset_stream)?));
        Ok(())
    }

    /// Generate the asset hash from a file asset using the constructed
    /// start and length values.
    fn hash_from_stream<R>(&mut self, asset_stream: &mut R) -> crate::error::Result<Vec<u8>>
    where
        R: Read + Seek + ?Sized,
    {
        if self.is_remote_hash() {
            return Err(Error::BadParam(
                "asset hash is remote, not yet supported".to_owned(),
            ));
        }

        let alg = match self.alg {
            Some(ref a) => a.clone(),
            None => "sha256".to_string(),
        };

        let bmff_exclusions = &self.exclusions;

        // convert BMFF exclusion map to flat exclusion list
        let exclusions =
            bmff_to_jumbf_exclusions(asset_stream, bmff_exclusions, self.bmff_version > 1)?;

        let hash = hash_stream_by_alg(&alg, asset_stream, Some(exclusions), true)?;

        if hash.is_empty() {
            Err(Error::BadParam("could not generate data hash".to_string()))
        } else {
            Ok(hash)
        }
    }

    #[cfg(feature = "file_io")]
    pub fn update_fragmented_inithash(
        &mut self,
        asset_path: &std::path::Path,
    ) -> crate::error::Result<()> {
        if let Some(mm) = &mut self.merkle {
            let mut init_stream = std::fs::File::open(asset_path)?;
            let mpd_mm = mm.get_mut(0).ok_or(Error::NotFound)?;

            let curr_alg = match &mpd_mm.alg {
                Some(a) => a.clone(),
                None => match &self.alg {
                    Some(a) => a.to_owned(),
                    None => "sha256".to_string(),
                },
            };

            let exclusions = bmff_to_jumbf_exclusions(
                &mut init_stream,
                &self.exclusions,
                self.bmff_version > 1,
            )?;

            init_stream.rewind()?;
            let hash = hash_stream_by_alg(&curr_alg, &mut init_stream, Some(exclusions), true)?;

            mpd_mm.init_hash = Some(ByteBuf::from(hash));

            Ok(())
        } else {
            Err(Error::BadParam("expected MerkleMap object".to_string()))
        }
    }

    pub fn verify_in_memory_hash(
        &self,
        data: &[u8],
        alg: Option<&str>,
    ) -> crate::error::Result<()> {
        let mut reader = Cursor::new(data);

        self.verify_stream_hash(&mut reader, alg)
    }

    // The BMFFMerklMaps are stored contiguous in the file.  Break this Vec into groups based on
    // the MerkleMap it matches.
    fn split_bmff_merkle_map(
        &self,
        bmff_merkle_map: Vec<BmffMerkleMap>,
    ) -> crate::Result<HashMap<u32, Vec<BmffMerkleMap>>> {
        let mut current = bmff_merkle_map;
        let mut output = HashMap::new();
        if let Some(mm) = self.merkle() {
            for m in mm {
                let rest = current.split_off(m.count as usize);

                if current.len() == m.count as usize {
                    output.insert(m.local_id, current.to_owned());
                } else {
                    return Err(Error::HashMismatch("MerkleMap count incorrect".to_string()));
                }
                current = rest;
            }
        } else {
            output.insert(0, current);
        }
        Ok(output)
    }

    // Breaks box runs at fragment boundaries (moof boxes)
    fn split_fragment_boxes(boxes: &[BoxInfoLite]) -> Vec<Vec<BoxInfoLite>> {
        let mut moof_list = Vec::new();

        // start from 1st moof
        if let Some(pos) = boxes.iter().position(|b| b.path == "moof") {
            let mut box_list = vec![boxes[pos].clone()];

            if pos == 0 {
                return moof_list; // this does not contain fragmented content
            }

            for b in boxes[pos + 1..].iter() {
                if b.path == "moof" {
                    moof_list.push(box_list); // save box list
                    box_list = Vec::new(); // start new box list
                }
                box_list.push(b.clone());
            }
            moof_list.push(box_list); // save last list
        }
        moof_list
    }

    #[cfg(feature = "file_io")]
    pub fn verify_hash(
        &self,
        asset_path: &std::path::Path,
        alg: Option<&str>,
    ) -> crate::error::Result<()> {
        let mut data = std::fs::File::open(asset_path)?;
        self.verify_stream_hash(&mut data, alg)
    }

    /* Verifies BMFF hashes from a single file asset.  The following variants are handled
        A single BMFF asset with only a file hash
        A single BMMF asset with Merkle tree hash
            Timed media (Merkle hashes over track chunks)
            Untimed media (Merkle hashes over iloc locations)
        A single BMFF asset containing all fragments (Merkle hashes over moof ranges).
    */
    pub fn verify_stream_hash(
        &self,
        reader: &mut dyn CAIRead,
        alg: Option<&str>,
    ) -> crate::error::Result<()> {
        if self.is_remote_hash() {
            return Err(Error::BadParam(
                "asset hash is remote, not yet supported".to_owned(),
            ));
        }

        reader.rewind()?;
        let size = stream_len(reader)?;

        let curr_alg = match &self.alg {
            Some(a) => a.clone(),
            None => match alg {
                Some(a) => a.to_owned(),
                None => "sha256".to_string(),
            },
        };

        // convert BMFF exclusion map to flat exclusion list
        let exclusions = bmff_to_jumbf_exclusions(reader, &self.exclusions, self.bmff_version > 1)?;

        // handle file level hashing
        if let Some(hash) = self.hash() {
            if !verify_stream_by_alg(&curr_alg, hash, reader, Some(exclusions.clone()), true) {
                return Err(Error::HashMismatch(
                    "BMFF file level hash mismatch".to_string(),
                ));
            }
        }

        // merkle hashed BMFF
        if let Some(mm_vec) = self.merkle() {
            // get merkle boxes from asset
            let c2pa_boxes = read_bmff_c2pa_boxes(reader)?;
            let bmff_merkle = c2pa_boxes.bmff_merkle;
            let box_infos = c2pa_boxes.box_infos;

            let first_moof = box_infos.iter().find(|b| b.path == "moof");
            let is_fragmented = first_moof.is_some();

            // check initialization segments (must do here in separate loop since MP4 will consume the reader)
            for mm in mm_vec {
                let alg = match &mm.alg {
                    Some(a) => a,
                    None => self
                        .alg()
                        .ok_or(Error::HashMismatch("no algorithm found".to_string()))?,
                };

                if let Some(init_hash) = &mm.init_hash {
                    if let Some(moof_box) = first_moof {
                        // add the moof to end exclusion
                        let moof_exclusion = HashRange::new(
                            moof_box.offset as usize,
                            (size - moof_box.offset) as usize,
                        );

                        let mut mm_exclusions = exclusions.clone();
                        mm_exclusions.push(moof_exclusion);

                        if !verify_stream_by_alg(alg, init_hash, reader, Some(mm_exclusions), true)
                        {
                            return Err(Error::HashMismatch(
                                "BMFF file level hash mismatch".to_string(),
                            ));
                        }
                    } else {
                        return Err(Error::HashMismatch(
                            "BMFF inithash must not be present for non-fragmented media".to_owned(),
                        ));
                    }
                }
            }

            // is this a fragmented BMFF
            if is_fragmented {
                for mm in mm_vec {
                    let alg = match &mm.alg {
                        Some(a) => a,
                        None => self
                            .alg()
                            .ok_or(Error::HashMismatch("no algorithm found".to_string()))?,
                    };

                    let moof_chunks = BmffHash::split_fragment_boxes(&box_infos);

                    // make sure there is a 1-1 mapping of moof chunks and Merkle values
                    if moof_chunks.len() != mm.count as usize
                        || bmff_merkle.len() != mm.count as usize
                    {
                        return Err(Error::HashMismatch(
                            "Incorrect number of fragments hashes".to_owned(),
                        ));
                    }

                    // build Merkle tree for the moof chucks minus the excluded ranges
                    for (index, boxes) in moof_chunks.iter().enumerate() {
                        // include just the range of this chunk so exclude boxes before and after
                        let mut curr_exclusions = exclusions.clone();

                        // before box exclusion starts at beginning of file until the start of this chunk
                        let before_box_start = 0;
                        let before_box_len = match boxes.first() {
                            Some(first) => first.offset as usize,
                            None => 0,
                        };
                        let before_box_exclusion = HashRange::new(before_box_start, before_box_len);
                        curr_exclusions.push(before_box_exclusion);

                        // after box exclusion continues to the end of the file
                        let after_box_start = match boxes.last() {
                            Some(last) => last.offset + last.size,
                            None => 0,
                        };
                        let after_box_len = size - after_box_start;
                        let after_box_exclusion =
                            HashRange::new(after_box_start as usize, after_box_len as usize);
                        curr_exclusions.push(after_box_exclusion);

                        // hash the specified range
                        let hash = hash_stream_by_alg(alg, reader, Some(curr_exclusions), true)?;

                        let bmff_mm = &bmff_merkle[index];

                        // check MerkleMap for the hash
                        if !mm.check_merkle_tree(alg, &hash, bmff_mm.location, &bmff_mm.hashes) {
                            return Err(Error::HashMismatch("Fragment not valid".to_string()));
                        }
                    }
                }
                return Ok(());
            } else if box_infos.iter().any(|b| b.path == "moov") {
                // timed media case

                let track_to_bmff_merkle_map = if bmff_merkle.is_empty() {
                    HashMap::new()
                } else {
                    self.split_bmff_merkle_map(bmff_merkle)?
                };

                reader.rewind()?;
                let buf_reader = BufReader::new(reader);
                let mut mp4 = mp4::Mp4Reader::read_header(buf_reader, size)
                    .map_err(|_e| Error::InvalidAsset("Could not parse BMFF".to_string()))?;
                let track_count = mp4.tracks().len();

                for mm in mm_vec {
                    let alg = match &mm.alg {
                        Some(a) => a,
                        None => self
                            .alg()
                            .ok_or(Error::HashMismatch("no algorithm found".to_string()))?,
                    };

                    if track_count > 0 {
                        // timed media case
                        let track = {
                            // clone so we can borrow later
                            let tt = mp4.tracks().get(&mm.local_id).ok_or(Error::HashMismatch(
                                "Merkle location not found".to_owned(),
                            ))?;

                            Mp4Track {
                                trak: tt.trak.clone(),
                                trafs: tt.trafs.clone(),
                                default_sample_duration: tt.default_sample_duration,
                            }
                        };

                        let sample_cnt = track.sample_count();
                        if sample_cnt == 0 {
                            return Err(Error::InvalidAsset("No samples".to_string()));
                        }

                        let track_id = track.track_id();

                        // create sample to chunk mapping
                        // create the Merkle tree per samples in a chunk
                        let mut chunk_hash_map: HashMap<u32, Hasher> = HashMap::new();
                        let stsc = &track.trak.mdia.minf.stbl.stsc;
                        for sample_id in 1..=sample_cnt {
                            let stsc_idx = stsc_index(&track, sample_id)?;

                            let stsc_entry = &stsc.entries[stsc_idx];

                            let first_chunk = stsc_entry.first_chunk;
                            let first_sample = stsc_entry.first_sample;
                            let samples_per_chunk = stsc_entry.samples_per_chunk;

                            let chunk_id =
                                first_chunk + (sample_id - first_sample) / samples_per_chunk;

                            // add chunk Hasher if needed
                            if let Vacant(e) = chunk_hash_map.entry(chunk_id) {
                                // get hasher for algorithm
                                let hasher_enum = match alg.as_str() {
                                    "sha256" => Hasher::SHA256(Sha256::new()),
                                    "sha384" => Hasher::SHA384(Sha384::new()),
                                    "sha512" => Hasher::SHA512(Sha512::new()),
                                    _ => {
                                        return Err(Error::HashMismatch(
                                            "no algorithm found".to_string(),
                                        ))
                                    }
                                };

                                e.insert(hasher_enum);
                            }

                            if let Ok(Some(sample)) = &mp4.read_sample(track_id, sample_id) {
                                let h = chunk_hash_map.get_mut(&chunk_id).ok_or(
                                    Error::HashMismatch(
                                        "Bad Merkle tree sample mapping".to_string(),
                                    ),
                                )?;
                                // add sample data to hash
                                h.update(&sample.bytes);
                            } else {
                                return Err(Error::HashMismatch(
                                    "Merle location not found".to_owned(),
                                ));
                            }
                        }

                        // finalize leaf hashes
                        let mut leaf_hashes = Vec::new();
                        for chunk_bmff_mm in &track_to_bmff_merkle_map[&track_id] {
                            match chunk_hash_map.remove(&(chunk_bmff_mm.location + 1)) {
                                Some(h) => {
                                    let h = Hasher::finalize(h);
                                    leaf_hashes.push(h);
                                }
                                None => {
                                    return Err(Error::HashMismatch(
                                        "Could not generate hash".to_owned(),
                                    ))
                                }
                            }
                        }

                        for chunk_bmff_mm in &track_to_bmff_merkle_map[&track_id] {
                            let hash = &leaf_hashes[chunk_bmff_mm.location as usize];

                            // check MerkleMap for the hash
                            if !mm.check_merkle_tree(
                                alg,
                                hash,
                                chunk_bmff_mm.location,
                                &chunk_bmff_mm.hashes,
                            ) {
                                return Err(Error::HashMismatch("Fragment not valid".to_string()));
                            }
                        }
                    }
                }
            } else {
                // non-timed media so use iloc (awaiting use case/example since the iloc varies by format)
                return Err(Error::HashMismatch(
                    "Merkle iloc not yet supported".to_owned(),
                ));
            }
        }

        Ok(())
    }

    #[cfg(feature = "file_io")]
    pub fn verify_stream_segments(
        &self,
        init_stream: &mut dyn CAIRead,
        fragment_paths: &Vec<std::path::PathBuf>,
        alg: Option<&str>,
    ) -> crate::Result<()> {
        let curr_alg = match &self.alg {
            Some(a) => a.clone(),
            None => match alg {
                Some(a) => a.to_owned(),
                None => "sha256".to_string(),
            },
        };

        // handle file level hashing
        if self.hash().is_some() {
            return Err(Error::HashMismatch(
                "Hash value should not be present for a fragmented BMFF asset".to_string(),
            ));
        }

        // Merkle hashed BMFF
        if let Some(mm_vec) = self.merkle() {
            // inithash cache to prevent duplicate work.
            let mut init_hashes = std::collections::HashSet::new();

            for fp in fragment_paths {
                let mut fragment_stream = std::fs::File::open(fp)?;

                // get merkle boxes from segment
                let c2pa_boxes = read_bmff_c2pa_boxes(&mut fragment_stream)?;
                let bmff_merkle = c2pa_boxes.bmff_merkle;

                if bmff_merkle.is_empty() {
                    return Err(Error::HashMismatch("Fragment had no MerkleMap".to_string()));
                }

                for bmff_mm in bmff_merkle {
                    // find matching MerkleMap for this uniqueId & localId
                    if let Some(mm) = mm_vec.iter().find(|mm| {
                        mm.unique_id == bmff_mm.unique_id && mm.local_id == bmff_mm.local_id
                    }) {
                        let alg = match &mm.alg {
                            Some(a) => a,
                            None => &curr_alg,
                        };

                        // check the inithash (for fragmented MP4 with multiple files this is the hash of the init_segment minus any exclusions)
                        if let Some(init_hash) = &mm.init_hash {
                            let bmff_exclusions = &self.exclusions;

                            let init_hash_str = extfmt::Hexlify(init_hash).to_string();
                            if !init_hashes.contains(&init_hash_str) {
                                // convert BMFF exclusion map to flat exclusion list
                                init_stream.rewind()?;
                                let exclusions = bmff_to_jumbf_exclusions(
                                    init_stream,
                                    bmff_exclusions,
                                    self.bmff_version > 1,
                                )?;

                                if !verify_stream_by_alg(
                                    alg,
                                    init_hash,
                                    init_stream,
                                    Some(exclusions),
                                    true,
                                ) {
                                    return Err(Error::HashMismatch(
                                        "BMFF inithash mismatch".to_string(),
                                    ));
                                }

                                init_hashes.insert(init_hash_str);
                            }

                            // check the segments
                            fragment_stream.rewind()?;
                            let fragment_exclusions = bmff_to_jumbf_exclusions(
                                &mut fragment_stream,
                                bmff_exclusions,
                                self.bmff_version > 1,
                            )?;

                            // hash the entire fragment minus exclusions
                            let hash = hash_stream_by_alg(
                                alg,
                                &mut fragment_stream,
                                Some(fragment_exclusions),
                                true,
                            )?;

                            // check MerkleMap for the hash
                            if !mm.check_merkle_tree(alg, &hash, bmff_mm.location, &bmff_mm.hashes)
                            {
                                return Err(Error::HashMismatch("Fragment not valid".to_string()));
                            }
                        }
                    } else {
                        return Err(Error::HashMismatch("Fragment had no MerkleMap".to_string()));
                    }
                }
            }
        } else {
            return Err(Error::HashMismatch(
                "Merkle value must be present for a fragmented BMFF asset".to_string(),
            ));
        }

        Ok(())
    }

    // Used to verify fragmented BMFF assets spread across multiple file.
    pub fn verify_stream_segment(
        &self,
        init_stream: &mut dyn CAIRead,
        fragment_stream: &mut dyn CAIRead,
        alg: Option<&str>,
    ) -> crate::Result<()> {
        let curr_alg = match &self.alg {
            Some(a) => a.clone(),
            None => match alg {
                Some(a) => a.to_owned(),
                None => "sha256".to_string(),
            },
        };

        // handle file level hashing
        if self.hash().is_some() {
            return Err(Error::HashMismatch(
                "Hash value should not be present for a fragmented BMFF asset".to_string(),
            ));
        }

        // Merkle hashed BMFF
        if let Some(mm_vec) = self.merkle() {
            // get merkle boxes from segment
            let c2pa_boxes = read_bmff_c2pa_boxes(fragment_stream)?;
            let bmff_merkle = c2pa_boxes.bmff_merkle;

            if bmff_merkle.is_empty() {
                return Err(Error::HashMismatch("Fragment had no MerkleMap".to_string()));
            }

            for bmff_mm in bmff_merkle {
                // find matching MerkleMap for this uniqueId & localId
                if let Some(mm) = mm_vec
                    .iter()
                    .find(|mm| mm.unique_id == bmff_mm.unique_id && mm.local_id == bmff_mm.local_id)
                {
                    let alg = match &mm.alg {
                        Some(a) => a,
                        None => &curr_alg,
                    };

                    // check the inithash (for fragmented MP4 with multiple files this is the hash of the init_segment minus any exclusions)
                    if let Some(init_hash) = &mm.init_hash {
                        let bmff_exclusions = &self.exclusions;

                        // convert BMFF exclusion map to flat exclusion list
                        init_stream.rewind()?;
                        let exclusions = bmff_to_jumbf_exclusions(
                            init_stream,
                            bmff_exclusions,
                            self.bmff_version > 1,
                        )?;

                        if !verify_stream_by_alg(
                            alg,
                            init_hash,
                            init_stream,
                            Some(exclusions),
                            true,
                        ) {
                            return Err(Error::HashMismatch("BMFF inithash mismatch".to_string()));
                        }

                        let fragment_exclusions = bmff_to_jumbf_exclusions(
                            fragment_stream,
                            bmff_exclusions,
                            self.bmff_version > 1,
                        )?;

                        // hash the entire fragment minus exclusions
                        let hash = hash_stream_by_alg(
                            alg,
                            fragment_stream,
                            Some(fragment_exclusions),
                            true,
                        )?;

                        // check MerkleMap for the hash
                        if !mm.check_merkle_tree(alg, &hash, bmff_mm.location, &bmff_mm.hashes) {
                            return Err(Error::HashMismatch("Fragment not valid".to_string()));
                        }
                    }
                } else {
                    return Err(Error::HashMismatch("Fragment had no MerkleMap".to_string()));
                }
            }
        } else {
            return Err(Error::HashMismatch(
                "Merkle value must be present for a fragmented BMFF asset".to_string(),
            ));
        }

        Ok(())
    }

    #[cfg(feature = "file_io")]
    pub fn add_merkle_for_fragmented(
        &mut self,
        alg: &str,
        asset_path: &std::path::Path,
        fragment_paths: &Vec<std::path::PathBuf>,
        output_dir: &std::path::Path,
        local_id: u32,
        unique_id: Option<u32>,
    ) -> crate::Result<()> {
        let max_proofs: usize = 4; // todo: calculate (number of hashes to perform vs size of manifest) or allow to be set

        if !output_dir.exists() {
            std::fs::create_dir_all(output_dir)?;
        } else {
            // make sure it is a directory
            if !output_dir.is_dir() {
                return Err(Error::BadParam("output_dir is not a directory".to_string()));
            }
        }

        let mut fragments = Vec::new();

        let unique_id = match unique_id {
            Some(id) => id,
            None => local_id,
        };

        // copy to output folder saving paths to fragments and init segments
        for file_path in fragment_paths {
            fragments.push(file_path.as_path());

            let output_path = output_dir.join(
                file_path
                    .file_name()
                    .ok_or(Error::BadParam("file name not found".to_string()))?,
            );
            std::fs::copy(file_path, output_path)?;
        }
        let output_path = output_dir.join(
            asset_path
                .file_name()
                .ok_or(Error::BadParam("file name not found".to_string()))?,
        );
        std::fs::copy(asset_path, output_path)?;

        // create dummy tree to figure out the layout and proof size
        let dummy_tree = C2PAMerkleTree::dummy_tree(fragments.len(), alg);

        let mut location_to_fragment_map: HashMap<u32, std::path::PathBuf> = HashMap::new();

        // copy to destination and insert placeholder C2PA Merkle box
        for (location, seg) in (0_u32..).zip(fragments.iter()) {
            let mut seg_reader = std::fs::File::open(seg)?;

            let c2pa_boxes = read_bmff_c2pa_boxes(&mut seg_reader)?;
            let box_infos = &c2pa_boxes.box_infos;

            if box_infos.iter().filter(|b| b.path == "moof").count() != 1 {
                return Err(Error::BadParam("expected 1 moof in fragment".to_string()));
            }

            if box_infos.iter().filter(|b| b.path == "mdat").count() != 1 {
                return Err(Error::BadParam("expected 1 mdat in fragment".to_string()));
            }

            // we don't currently support adding to fragments with existing manifests
            if !c2pa_boxes.bmff_merkle.is_empty() {
                return Err(Error::BadParam(
                    "fragment already contains BmffMerkeMap".to_string(),
                ));
            }

            let mut mm = BmffMerkleMap {
                unique_id,
                local_id,
                location,
                hashes: None,
            };

            let proof = dummy_tree.get_proof_by_index(location as usize, max_proofs)?;
            if !proof.is_empty() {
                let mut proof_vec = Vec::new();
                for v in proof {
                    let bb = ByteBuf::from(v);
                    proof_vec.push(bb);
                }
                mm.hashes = Some(VecByteBuf(proof_vec));
            }

            let mm_cbor = serde_cbor::to_vec(&mm)
                .map_err(|_err| Error::AssertionEncoding(_err.to_string()))?;

            // generate the UUID box
            let mut uuid_box_data: Vec<u8> = Vec::with_capacity(mm_cbor.len() * 2);
            crate::asset_handlers::bmff_io::write_c2pa_box(
                &mut uuid_box_data,
                &[],
                false,
                &mm_cbor,
            )?;

            let first_moof = box_infos
                .iter()
                .find(|b| b.path == "moof")
                .ok_or(Error::BadParam("expected 1 moof in fragment".to_string()))?;

            let mut source = std::fs::File::open(seg)?;
            let output_filename = seg
                .file_name()
                .ok_or(Error::NotFound)?
                .to_string_lossy()
                .into_owned();
            let dest_path = output_dir.join(&output_filename);
            let mut dest = std::fs::OpenOptions::new().write(true).open(&dest_path)?;

            // UUID to insert into output asset
            crate::utils::io_utils::insert_data_at(
                &mut source,
                &mut dest,
                first_moof.offset,
                &uuid_box_data,
            )?;

            // save file path for each which location in Merkle tree
            location_to_fragment_map.insert(location, dest_path);
        }

        // fill in actual hashes now that we have inserted the C2PA box.
        let bmff_exclusions = &self.exclusions;
        let mut leaves: Vec<crate::utils::merkle::MerkleNode> = Vec::with_capacity(fragments.len());
        for i in 0..fragments.len() as u32 {
            if let Some(path) = location_to_fragment_map.get(&i) {
                let mut fragment_stream = std::fs::File::open(path)?;

                let fragment_exclusions = bmff_to_jumbf_exclusions(
                    &mut fragment_stream,
                    bmff_exclusions,
                    self.bmff_version > 1,
                )?;

                // hash the entire fragment minus fragment exclusions
                let hash =
                    hash_stream_by_alg(alg, &mut fragment_stream, Some(fragment_exclusions), true)?;

                // add merkle leaf
                leaves.push(crate::utils::merkle::MerkleNode(hash));
            }
        }

        // gen final merkle tree
        let m_tree = C2PAMerkleTree::from_leaves(leaves, alg, false);
        for i in 0..fragments.len() as u32 {
            if let Some(dest_path) = location_to_fragment_map.get(&i) {
                let mut fragment_stream = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(dest_path)?;

                let c2pa_boxes = read_bmff_c2pa_boxes(&mut fragment_stream)?;
                let merkle_box_infos = &c2pa_boxes.bmff_merkle_box_infos;
                let merkle_boxes = &c2pa_boxes.bmff_merkle;

                if merkle_boxes.len() != 1 || merkle_box_infos.len() != 1 {
                    return Err(Error::InvalidAsset(
                        "mp4 fragment Merkle box count wrong".to_string(),
                    ));
                }

                let mut bmff_mm = merkle_boxes[0].clone();
                let bmff_mm_info = &merkle_box_infos[0];

                // get proof for this location and replace temp proof
                let proof = m_tree.get_proof_by_index(bmff_mm.location as usize, max_proofs)?;
                if !proof.is_empty() {
                    let mut proof_vec = Vec::new();
                    for v in proof {
                        let bb = ByteBuf::from(v);
                        proof_vec.push(bb);
                    }

                    bmff_mm.hashes = Some(VecByteBuf(proof_vec));
                }

                let mm_cbor = serde_cbor::to_vec(&bmff_mm)
                    .map_err(|_err| Error::AssertionEncoding(_err.to_string()))?;

                // generate the C2PA Merkle box with final hash
                let mut uuid_box_data: Vec<u8> = Vec::with_capacity(mm_cbor.len() * 2);
                crate::asset_handlers::bmff_io::write_c2pa_box(
                    &mut uuid_box_data,
                    &[],
                    false,
                    &mm_cbor,
                )?;

                // replace temp C2PA Merkle box
                if uuid_box_data.len() == bmff_mm_info.size as usize {
                    fragment_stream.seek(std::io::SeekFrom::Start(bmff_mm_info.offset))?;
                    std::io::Write::write_all(&mut fragment_stream, &uuid_box_data)?;
                } else {
                    return Err(Error::InvalidAsset(
                        "mp4 fragment Merkle box size does not match".to_string(),
                    ));
                }
            }
        }

        // save desired Merkle tree row (for now complete tree)
        let tree_row = std::cmp::min(max_proofs, m_tree.layers.len() - 1);
        let merkle_row = m_tree.layers[tree_row].clone();
        let mut hashes = Vec::new();
        for mn in merkle_row {
            let bb = ByteBuf::from(mn.0);
            hashes.push(bb);
        }

        let mm = MerkleMap {
            unique_id,
            local_id,
            count: fragments.len() as u32,
            alg: Some(alg.to_owned()),
            init_hash: match alg {
                // placeholder init hash to be filled once manifest is inserted
                "sha256" => Some(ByteBuf::from([0u8; 32].to_vec())),
                "sha384" => Some(ByteBuf::from([0u8; 48].to_vec())),
                "sha512" => Some(ByteBuf::from([0u8; 64].to_vec())),
                _ => return Err(Error::UnsupportedType),
            },
            hashes: VecByteBuf(hashes),
        };
        self.merkle = Some(vec![mm]);

        Ok(())
    }
}

impl AssertionCbor for BmffHash {}

impl AssertionBase for BmffHash {
    const LABEL: &'static str = Self::LABEL;
    const VERSION: Option<usize> = Some(ASSERTION_CREATION_VERSION);

    // todo: this mechanism needs to change since a struct could support different versions

    fn to_assertion(&self) -> crate::error::Result<Assertion> {
        Self::to_cbor_assertion(self)
    }

    fn from_assertion(assertion: &Assertion) -> crate::error::Result<Self> {
        let mut bmff_hash = Self::from_cbor_assertion(assertion)?;
        bmff_hash.set_bmff_version(assertion.get_ver());

        Ok(bmff_hash)
    }
}

fn stsc_index(track: &Mp4Track, sample_id: u32) -> crate::Result<usize> {
    if track.trak.mdia.minf.stbl.stsc.entries.is_empty() {
        return Err(Error::InvalidAsset("BMFF has no stsc entries".to_string()));
    }
    for (i, entry) in track.trak.mdia.minf.stbl.stsc.entries.iter().enumerate() {
        if sample_id < entry.first_sample {
            return if i == 0 {
                Err(Error::InvalidAsset("BMFF no sample not found".to_string()))
            } else {
                Ok(i - 1)
            };
        }
    }
    Ok(track.trak.mdia.minf.stbl.stsc.entries.len() - 1)
}

/* we need shippable examples
#[cfg(test)]
pub mod tests {
    #![allow(clippy::expect_used)]
    #![allow(clippy::panic)]
    #![allow(clippy::unwrap_used)]

    //use tempfile::tempdir;

    //use super::*;
    use crate::utils::test::fixture_path;

    #[cfg(not(target_arch = "wasm32"))]
    #[test]
    fn test_fragemented_mp4() {
        use crate::{
            assertions::BmffHash, asset_handlers::bmff_io::BmffIO, asset_io::AssetIO,
            status_tracker::DetailedStatusTracker, store::Store, AssertionBase,
        };

        let init_stream_path = fixture_path("dashinit.mp4");
        let segment_stream_path = fixture_path("dash1.m4s");
        let segment_stream_path10 = fixture_path("dash10.m4s");
        let segment_stream_path11 = fixture_path("dash11.m4s");


        let mut init_stream = std::fs::File::open(init_stream_path).unwrap();
        let mut segment_stream = std::fs::File::open(segment_stream_path).unwrap();
        let mut segment_stream10 = std::fs::File::open(segment_stream_path10).unwrap();
        let mut segment_stream11 = std::fs::File::open(segment_stream_path11).unwrap();


        let mut log = DetailedStatusTracker::default();

        let bmff_io = BmffIO::new("mp4");
        let bmff_handler = bmff_io.get_reader();

        let manifest_bytes = bmff_handler.read_cai(&mut init_stream).unwrap();
        let store = Store::from_jumbf(&manifest_bytes, &mut log).unwrap();

        // get the bmff hashes
        let claim = store.provenance_claim().unwrap();
        for dh_assertion in claim.hash_assertions() {
            if dh_assertion.label_root() == BmffHash::LABEL {
                let bmff_hash = BmffHash::from_assertion(dh_assertion).unwrap();

                bmff_hash
                    .verify_stream_segment(&mut init_stream, &mut segment_stream, None)
                    .unwrap();

                bmff_hash
                    .verify_stream_segment(&mut init_stream, &mut segment_stream10, None)
                    .unwrap();

                bmff_hash
                    .verify_stream_segment(&mut init_stream, &mut segment_stream11, None)
                    .unwrap();
            }
        }
    }
}
*/
