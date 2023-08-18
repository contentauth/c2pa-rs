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
    cmp,
    collections::{hash_map::Entry::Vacant, HashMap},
    fmt, fs,
    io::{BufReader, Cursor, SeekFrom},
    ops::Deref,
    path::{Path, PathBuf},
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
            concat_and_hash, hash_asset_by_alg, hash_stream_by_alg, vec_compare,
            verify_stream_by_alg, HashRange, Hasher,
        },
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
        let len = cmp::min(visitor.size_hint().unwrap_or(0), 4096);
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
        let mut index = location;
        let mut hash = hash.to_vec();

        if let Some(hashes) = proof {
            let layers = C2PAMerkleTree::to_layout(self.count as usize);

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
    pub path: PathBuf,

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
            path: PathBuf::new(),
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
    pub fn gen_hash(&mut self, asset_path: &Path) -> crate::error::Result<()> {
        self.hash = Some(ByteBuf::from(self.hash_from_asset(asset_path)?));
        self.path = PathBuf::from(asset_path);
        Ok(())
    }

    /// Generate the hash again.
    pub fn regen_hash(&mut self) -> crate::error::Result<()> {
        let p = self.path.clone();
        self.hash = Some(ByteBuf::from(self.hash_from_asset(p.as_path())?));
        Ok(())
    }

    /// Generate the asset hash from a file asset using the constructed
    /// start and length values.
    fn hash_from_asset(&mut self, asset_path: &Path) -> crate::error::Result<Vec<u8>> {
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
        let mut data = fs::File::open(asset_path)?;
        let exclusions =
            bmff_to_jumbf_exclusions(&mut data, bmff_exclusions, self.bmff_version > 1)?;

        let hash = hash_asset_by_alg(&alg, asset_path, Some(exclusions))?;

        if hash.is_empty() {
            Err(Error::BadParam("could not generate data hash".to_string()))
        } else {
            Ok(hash)
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

    pub fn verify_hash(&self, asset_path: &Path, alg: Option<&str>) -> crate::error::Result<()> {
        let mut data = fs::File::open(asset_path)?;
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
        bmff_hash.set_bmff_version(assertion.get_ver().unwrap_or(1));

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

fn stream_len(reader: &mut dyn CAIRead) -> crate::Result<u64> {
    let old_pos = reader.stream_position()?;
    let len = reader.seek(SeekFrom::End(0))?;

    if old_pos != len {
        reader.seek(SeekFrom::Start(old_pos))?;
    }

    Ok(len)
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
