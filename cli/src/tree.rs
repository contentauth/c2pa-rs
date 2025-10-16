// Copyright 2024 Adobe. All rights reserved.
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

use std::path::Path;

use atree::{Arena, Token};
use c2pa::{Reader, Result};
use treeline::Tree;

fn populate_node(
    tree: &mut Arena<String>,
    reader: &Reader,
    manifest_label: &str,
    current_token: &Token,
    name_only: bool,
) -> Result<()> {
    if let Some(manifest) = reader.get_manifest(manifest_label) {
        for assertion in manifest.assertions().iter() {
            let label = assertion.label_with_instance();
            current_token.append(tree, format!("Assertion:{label}"));
        }

        for ingredient in manifest.ingredients().iter() {
            let title = ingredient.title().unwrap_or("Untitled");
            if let Some(label) = ingredient.active_manifest() {
                // create new node
                let data = if name_only {
                    format!("{title}_{label}")
                } else {
                    format!("Asset:{title}, Manifest:{label}")
                };

                let new_token = current_token.append(tree, data);

                populate_node(tree, reader, label, &new_token, name_only)?;
            } else {
                let data = if name_only {
                    title.to_string()
                } else {
                    format!("Asset:{title}")
                };
                current_token.append(tree, data);
            }
        }
    }
    Ok(())
}

fn walk_tree(tree: &Arena<String>, token: &Token) -> Tree<String> {
    let result = token.children_tokens(tree).fold(
        Tree::root(tree[*token].data.clone()),
        |mut root, entry_token| {
            if entry_token.is_leaf(tree) {
                root.push(Tree::root(tree[entry_token].data.clone()));
            } else {
                root.push(walk_tree(tree, &entry_token));
            }
            root
        },
    );

    result
}

/// Prints tree view of manifest store
pub fn tree<P: AsRef<Path>>(path: P) -> Result<String> {
    let os_filename = path
        .as_ref()
        .file_name()
        .ok_or_else(|| crate::Error::BadParam("bad filename".to_string()))?;
    let asset_name = os_filename.to_string_lossy().into_owned();

    let reader = Reader::from_file(path)?;

    // walk through the manifests and show the contents
    Ok(if let Some(manifest_label) = reader.active_label() {
        let data = format!("Asset:{asset_name}, Manifest:{manifest_label}");
        let (mut tree, root_token) = Arena::with_data(data);
        populate_node(&mut tree, &reader, manifest_label, &root_token, false)?;
        // print tree
        format!("Tree View:\n {}", walk_tree(&tree, &root_token))
    } else {
        format!("Tree View:\n Asset:{asset_name}")
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tree() -> Result<()> {
        let result = tree("tests/fixtures/C.jpg")?;
        assert!(result.contains("Tree View:"));
        assert!(result.contains("Assertion:c2pa.actions"));
        Ok(())
    }
}
