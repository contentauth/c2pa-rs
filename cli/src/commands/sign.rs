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

use std::path::{Path, PathBuf};

use anyhow::Result;

use super::{
    add_cli_ingredients, add_manifest_ingredients, configure_remote_sidecar,
    create_builder_from_json, load_ingredient, load_manifest_json, save_archive, sign_to_output,
};

/// Common signing options shared by create, edit, and update commands.
pub struct SignArgs<'a> {
    pub manifest: Option<&'a PathBuf>,
    pub manifest_json: Option<&'a String>,
    pub output: &'a Path,
    pub archive: bool,
    pub sidecar: bool,
    pub remote: Option<&'a String>,
    pub force: bool,
}

pub fn run_create(input: &Path, ingredients: &[PathBuf], args: &SignArgs) -> Result<()> {
    let (json, base_path) = load_manifest_json(args.manifest, args.manifest_json)?;
    let (mut builder, sign_config) = create_builder_from_json(&json, base_path.as_ref())?;

    add_manifest_ingredients(&mut builder, &json, base_path.as_ref())?;
    add_cli_ingredients(&mut builder, ingredients)?;
    configure_remote_sidecar(&mut builder, args.remote, args.sidecar);

    if args.archive {
        save_archive(&mut builder, args.output, args.force)
    } else {
        sign_to_output(
            &mut builder,
            &sign_config,
            input,
            args.output,
            args.sidecar,
            args.force,
        )
    }
}

pub fn run_edit(
    parent: &Path,
    input: Option<&PathBuf>,
    ingredients: &[PathBuf],
    args: &SignArgs,
) -> Result<()> {
    let input_path = input.map(|p| p.as_path()).unwrap_or(parent);

    let (json, base_path) = load_manifest_json(args.manifest, args.manifest_json)?;
    let (mut builder, sign_config) = create_builder_from_json(&json, base_path.as_ref())?;

    add_manifest_ingredients(&mut builder, &json, base_path.as_ref())?;

    let mut parent_ingredient = load_ingredient(parent)?;
    parent_ingredient.set_is_parent();
    builder.add_ingredient(parent_ingredient);

    add_cli_ingredients(&mut builder, ingredients)?;
    configure_remote_sidecar(&mut builder, args.remote, args.sidecar);

    if args.archive {
        save_archive(&mut builder, args.output, args.force)
    } else {
        sign_to_output(
            &mut builder,
            &sign_config,
            input_path,
            args.output,
            args.sidecar,
            args.force,
        )
    }
}

pub fn run_update(input: &Path, args: &SignArgs) -> Result<()> {
    let (json, base_path) = load_manifest_json(args.manifest, args.manifest_json)?;
    let (mut builder, sign_config) = create_builder_from_json(&json, base_path.as_ref())?;

    add_manifest_ingredients(&mut builder, &json, base_path.as_ref())?;

    let mut parent_ingredient = load_ingredient(input)?;
    parent_ingredient.set_is_parent();
    builder.add_ingredient(parent_ingredient);

    configure_remote_sidecar(&mut builder, args.remote, args.sidecar);

    if args.archive {
        save_archive(&mut builder, args.output, args.force)
    } else {
        sign_to_output(
            &mut builder,
            &sign_config,
            input,
            args.output,
            args.sidecar,
            args.force,
        )
    }
}
