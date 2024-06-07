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

#![doc = include_str!("../README.md")]

use std::process;

use anyhow::Result;
use clap::{CommandFactory, Parser};
use commands::{CliArgs, Commands, Trust, View};
use log::LevelFilter;

mod commands;

mod callback_signer;
mod signer;

fn main() -> Result<()> {
    let args = CliArgs::parse();

    // Normally default behavior, but since we mark the input and subcommands as optional
    // clap will require the input arg or else error, which isn't want we want.
    if args.path.is_none() && args.command.is_none() {
        CliArgs::command().print_help()?;
        process::exit(1);
    }

    env_logger::Builder::new()
        .filter_level(match args.verbose {
            0 => LevelFilter::Error,
            1 => LevelFilter::Warn,
            2 => LevelFilter::Info,
            3 => LevelFilter::Debug,
            4.. => LevelFilter::Trace,
        })
        .init();

    // When only an input file is specified with no subcommands, display the
    // user-friendly manifest.
    if let Some(path) = args.path {
        return commands::view(View::Manifest {
            path,
            debug: false,
            // To specify trust, use the explicit command `c2patool view manifest`
            trust: Trust::default(),
        });
    }

    // Safe to unwrap since if no input or command is specified, we exit. If
    // only the input is specified, we populate the command. Otherwise, command
    // is guaranteed to be specified.
    match args.command.unwrap() {
        Commands::Sign(config) => commands::sign(config)?,
        Commands::View(config) => commands::view(config)?,
        Commands::Extract(config) => commands::extract(config)?,
    }

    Ok(())
}

fn load_trust_settings(trust: &Trust) -> Result<()> {
    if let Some(trust_list) = &trust.trust_anchors {
        let data = trust_list.resolve()?;

        let replacement_val = serde_json::Value::String(data).to_string(); // escape string
        let setting = r#"{"trust": { "trust_anchors": replacement_val } }"#
            .replace("replacement_val", &replacement_val);

        c2pa::settings::load_settings_from_str(&setting, "json")?;
    }

    if let Some(allowed_list) = &trust.allowed_list {
        let data = allowed_list.resolve()?;

        let replacement_val = serde_json::Value::String(data).to_string(); // escape string
        let setting = r#"{"trust": { "allowed_list": replacement_val } }"#
            .replace("replacement_val", &replacement_val);

        c2pa::settings::load_settings_from_str(&setting, "json")?;
    }

    if let Some(trust_config) = &trust.trust_config {
        let data = trust_config.resolve()?;

        let replacement_val = serde_json::Value::String(data).to_string(); // escape string
        let setting = r#"{"trust": { "trust_config": replacement_val } }"#
            .replace("replacement_val", &replacement_val);

        c2pa::settings::load_settings_from_str(&setting, "json")?;
    }

    if trust.trust_anchors.is_some() || trust.allowed_list.is_some() || trust.trust_config.is_some()
    {
        c2pa::settings::load_settings_from_str(r#"{"verify": { "verify_trust": true} }"#, "json")?;
    } else {
        c2pa::settings::load_settings_from_str(r#"{"verify": { "verify_trust": false} }"#, "json")?;
    }

    Ok(())
}
