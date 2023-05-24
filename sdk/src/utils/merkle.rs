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

use extfmt::Hexlify;

use super::hash_utils::{concat_and_hash, hash_by_alg};
use crate::{Error, Result};

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

    pub fn get_proof_by_index(&self, leaf_indx: usize) -> Result<Vec<Vec<u8>>> {
        if self.leaves.is_empty() || leaf_indx >= self.leaves.len() {
            return Err(Error::BadParam(
                "Merkle proof index out of range".to_string(),
            ));
        }

        let mut proof: Vec<Vec<u8>> = Vec::new();
        let mut index = leaf_indx;

        for i in 0..self.layers.len() {
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
