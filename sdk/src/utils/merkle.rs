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
    collections::{BTreeMap, HashMap},
    io::Read,
};

use extfmt::Hexlify;
use serde_bytes::ByteBuf;
use sha2::{Digest, Sha256};

use super::hash_utils::{concat_and_hash, hash_by_alg};
use crate::{hash_utils::Hasher, Error, Result};

#[derive(Default, Clone, PartialEq, Debug)]
pub struct MerkleNode(pub Vec<u8>);

// Implements Merkle tree support corresponding to the C2PA spec variant.  The Merkle tree is not reduced and
// all leaves live at the bottom most level.  If the last layer node is an odd index (lacking a matching pair),
// its node value is propagated to parent layer, no cloning or hashing is expected.  Null tree entries do not contribute to the hashes.
pub struct C2PAMerkleTree {
    pub leaves: Vec<MerkleNode>,
    pub layers: Vec<Vec<MerkleNode>>,
}

#[allow(dead_code)]
impl C2PAMerkleTree {
    pub fn from_leaves(leaves: Vec<MerkleNode>, alg: &str, hash_leaves: bool) -> C2PAMerkleTree {
        let leaves = if hash_leaves {
            leaves
                .into_iter()
                .map(|leaf| {
                    let hash = hash_by_alg(alg, &leaf.0, None);
                    MerkleNode(hash)
                })
                .collect()
        } else {
            leaves // this handles the case when the leaves are already hashed
        };

        let layers = C2PAMerkleTree::generate_tree(alg, &leaves);

        C2PAMerkleTree { leaves, layers }
    }

    // create dummy tree to figure out the layout and proof sizes
    pub fn dummy_tree(num_leaves: usize, alg: &str) -> Self {
        let mut leaves: Vec<MerkleNode> = Vec::with_capacity(num_leaves);

        for i in 0..num_leaves {
            let v: u8 = (i % 0xff) as u8;
            let d = vec![v];
            leaves.push(MerkleNode(d));
        }

        C2PAMerkleTree::from_leaves(leaves, alg, true)
    }

    // generate layer layout
    pub fn to_layout(num_leaves: usize) -> Vec<usize> {
        let mut layers = Vec::new();

        layers.push(num_leaves);
        let mut current_layer = layers[0];

        while current_layer > 1 {
            let parent_layer_index = layers.len();
            let mut parent_layer_cnt: usize = 0;

            for i in (0..current_layer).step_by(2) {
                if i + 1 == current_layer {
                    parent_layer_cnt += 1;
                    continue;
                }

                parent_layer_cnt += 1;
            }
            layers.push(parent_layer_cnt);
            current_layer = layers[parent_layer_index];
        }

        layers
    }

    pub fn get_root(&self) -> Option<&Vec<u8>> {
        Some(&self.layers.last()?.first()?.0)
    }

    pub fn leaves_bytebufs(&self) -> Vec<ByteBuf> {
        self.leaves
            .iter()
            .map(|n| ByteBuf::from(n.0.clone()))
            .collect()
    }

    fn generate_tree(alg: &str, leaves: &[MerkleNode]) -> Vec<Vec<MerkleNode>> {
        let mut layers = Vec::new();
        layers.push(leaves.to_vec()); // set layer 0
        let mut current_layer = &layers[0];

        while current_layer.len() > 1 {
            let parent_layer_index = layers.len();
            let mut parent_layer = Vec::new();

            for i in (0..current_layer.len()).step_by(2) {
                if i + 1 == current_layer.len() {
                    // just pass the current hash since last node is unbalanced
                    parent_layer.push(MerkleNode(current_layer[i].0.clone()));
                    continue;
                }
                let left = &current_layer[i];
                let right = if i + 1 == current_layer.len() {
                    left
                } else {
                    &current_layer[i + 1]
                };

                parent_layer.push(MerkleNode(concat_and_hash(alg, &left.0, Some(&right.0))));
            }
            layers.push(parent_layer);
            current_layer = &layers[parent_layer_index];
        }
        layers
    }

    pub fn get_proof_by_index(
        &self,
        leaf_indx: usize,
        max_proof_len: usize,
    ) -> Result<Vec<Vec<u8>>> {
        if self.leaves.is_empty() || leaf_indx >= self.leaves.len() {
            return Err(Error::BadParam(
                "Merkle proof index out of range".to_string(),
            ));
        }

        let mut proofs_left = max_proof_len;
        let mut proof: Vec<Vec<u8>> = Vec::new();
        let mut index = leaf_indx;

        for i in 0..self.layers.len() {
            if proofs_left == 0 {
                break;
            }

            let layer = &self.layers[i];
            let is_right = index % 2 == 1;

            if is_right {
                if index - 1 < layer.len() {
                    proof.push(layer[index - 1].0.clone());
                }
            } else if index + 1 < layer.len() {
                proof.push(layer[index + 1].0.clone());
            }
            index /= 2;
            proofs_left -= 1;
        }
        Ok(proof)
    }

    pub fn num_layers_required(n: u32) -> i32 {
        let f = 1.0 * n as f32;

        f.log2().ceil() as i32
    }

    pub fn tree_dump(&self) {
        for (i, layer) in self.layers.iter().enumerate() {
            println!("Level: {i}");
            for (j, mn) in layer.iter().enumerate() {
                println!("{} (Node: {j})", Hexlify(&mn.0));
            }
        }
    }
}

// Implements a Merkle accumulator to support the C2PA spec variant.  This is used to compute the Merkle
// hashes for the asset content and supports adding mdat boxes in any order and handling large data that
// may need to be processed in chunks.  The accumulator maintains a map of mdat_id to the list of leaf
// hashes and lengths for that mdat, as well as an optional fixed size for the Merkle leaves if needed
// specified.  The add_merkle_leaf method handles adding new leaves to the tree, including
// hashing in chunks if using fixed size leaves.
#[derive(Clone, Debug)]
pub struct MerkleAccumulator {
    pub alg: String,
    pub hasher: Hasher,
    pub merkle_leaves: BTreeMap<usize, Vec<(u64, Vec<u8>)>>,
    pub fixed_size: Option<usize>, // Optional fixed size Merkle leave for the hash output, if needed
    pub fixed_size_remainder: HashMap<usize, Vec<u8>>, // Buffer to hold the fixed size hash remainder if needed for the specified mdat
}

impl Default for MerkleAccumulator {
    fn default() -> Self {
        MerkleAccumulator {
            alg: "sha256".to_string(),
            hasher: Hasher::SHA256(Sha256::new()),
            merkle_leaves: BTreeMap::new(),
            fixed_size: None,
            fixed_size_remainder: HashMap::new(),
        }
    }
}

#[allow(dead_code)]
impl MerkleAccumulator {
    pub fn new(alg: &str) -> Result<MerkleAccumulator> {
        Ok(MerkleAccumulator {
            alg: alg.to_string(),
            hasher: Hasher::new(alg)?,
            merkle_leaves: BTreeMap::new(),
            fixed_size: None,
            fixed_size_remainder: HashMap::new(),
        })
    }

    // update hash value with new data
    pub fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    // consume hasher and return the final digest
    pub fn finalize(hasher_enum: Hasher) -> Vec<u8> {
        Hasher::finalize(hasher_enum)
    }

    pub fn finalize_reset(&mut self) -> Vec<u8> {
        self.hasher.finalize_reset()
    }

    pub fn add_merkle_leaf(&mut self, mdat_id: usize, large_size: bool, data: &[u8]) -> Result<()> {
        let mut hash_start = 0;
        let data_len = data.len() as u64;

        // If this is not large size and we are hashing the first chunk we have to skip the first 8 bytes
        // which are the size field of the mdat box and not included in the Merkle tree according to the
        // spec.
        if !large_size
            && !self.merkle_leaves.contains_key(&mdat_id)
            && !self.fixed_size_remainder.contains_key(&mdat_id)
        {
            // nothing to hash based on Merkle "/mdat" exclusion
            if data_len <= 8 {
                return Ok(());
            }

            hash_start = 8;
        }

        // Are we using fixed size Merkle leaves? If so we have to handle the case where the data is larger than
        // the fixed size and we need to hash in chunks until we fill the fixed size buffer and then compute the
        //leaf hash and add to the tree, repeating this process until we have processed all the data. If we are
        // not using fixed size Merkle leaves then we can just hash the whole chunk and add to the tree as a single leaf.
        if let Some(fixed_size) = &self.fixed_size {
            let mut data_reader = std::io::Cursor::new(&data[hash_start..]);
            let mut data_left = data_len - hash_start as u64;

            // loop processing data as fixed size chunks until we have processed all the data or filled the fixed size buffer
            loop {
                if let Some(fixed_size_buffer) = &mut self.fixed_size_remainder.get_mut(&mdat_id) {
                    // if we have a fixed sized buffer that means we have to use this data first
                    // appending the rest from data until we complete the leaf of size self.fixed_size
                    let to_copy =
                        std::cmp::min(fixed_size - fixed_size_buffer.len(), data_len as usize);

                    let mut remainder = vec![0u8; to_copy];
                    data_reader.read_exact(remainder.as_mut_slice())?;
                    fixed_size_buffer.extend_from_slice(&remainder);
                    data_left -= to_copy as u64;

                    if fixed_size_buffer.len() == *fixed_size {
                        let fragment_hash = hash_by_alg(self.alg.as_str(), fixed_size_buffer, None);
                        self.merkle_leaves
                            .entry(mdat_id)
                            .and_modify(|leaves| {
                                leaves.push((*fixed_size as u64, fragment_hash.clone()))
                            })
                            .or_insert(vec![(*fixed_size as u64, fragment_hash)]);

                        self.fixed_size_remainder.remove(&mdat_id);
                    } else {
                        // we have filled the remainder of the fixed size buffer but we haven't filled a whole leaf yet
                        // so we need to wait for the next chunk to fill the rest of the leaf
                        return Ok(());
                    }
                } else {
                    let to_copy = std::cmp::min(*fixed_size, data_left as usize);
                    if to_copy == 0 {
                        // we have processed all the data
                        return Ok(());
                    }

                    if to_copy < *fixed_size {
                        // there is a remainder so store in the fixed size buffer for the next chunk and break the loop
                        let mut remainder = vec![0u8; to_copy];
                        data_reader.read_exact(remainder.as_mut_slice())?;
                        self.fixed_size_remainder.insert(mdat_id, remainder);
                        return Ok(());
                    } else {
                        let mut to_hash = vec![0u8; to_copy];
                        data_reader.read_exact(to_hash.as_mut_slice())?;

                        if to_hash.len() == *fixed_size {
                            self.fixed_size_remainder.remove(&mdat_id);
                            let fragment_hash = hash_by_alg(self.alg.as_str(), &to_hash, None);
                            self.merkle_leaves
                                .entry(mdat_id)
                                .and_modify(|leaves| {
                                    leaves.push((*fixed_size as u64, fragment_hash.clone()))
                                })
                                .or_insert(vec![(*fixed_size as u64, fragment_hash)]);

                            data_left -= to_copy as u64;
                        } else {
                            return Err(Error::OtherError(format!(
                                "Unexpected error processing Merkle leaves: expected to read {} bytes but only read {} bytes",
                                fixed_size, to_hash.len()
                            ).into()));
                        }
                    }
                }
            }
        } else {
            // compute the leaf hash
            let fragment_hash = hash_by_alg(self.alg.as_str(), &data[hash_start..], None);
            let fragment_length = data_len - hash_start as u64;

            self.merkle_leaves
                .entry(mdat_id)
                .and_modify(|leaves| leaves.push((fragment_length, fragment_hash.clone())))
                .or_insert(vec![(fragment_length, fragment_hash)]);
        }

        Ok(())
    }

    // Set the size of the fixed Merkle leaves in KB (e.g. 4 for 4KB).  This is used when
    // the Merkle tree needs to be computed with fixed size leaves, such as for BMFF hashing.
    // When set, the add_merkle_leaf method will handle hashing the data in chunks of the specified
    // size and adding the resulting leaf hashes to the tree accordingly.  If not set, the
    // add_merkle_leaf method will hash each chunk of data as a single leaf regardless of size.
    pub fn set_fixed_size(&mut self, size: usize) {
        self.fixed_size = Some(size * 1024); // convert from KB to bytes
    }
}
