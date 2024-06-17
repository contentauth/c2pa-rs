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
use clap::{error::ErrorKind, CommandFactory, Parser};
use commands::{CliArgs, Commands, Trust, View};
use log::LevelFilter;

mod commands;

mod callback_signer;
mod signer;

fn main() -> Result<()> {
    let args = CliArgs::parse_from(wild::args_os());

    // Normally default behavior, but since we mark the input and subcommands as optional
    // clap will require the input arg or else error, which isn't want we want.
    if args.path.is_none() && args.command.is_none() {
        CliArgs::command().print_help()?;
        process::exit(1);
    } else if args.path.is_some() && args.command.is_some() {
        CliArgs::command()
            .error(
                ErrorKind::UnknownArgument,
                format!(
                    "unexpected argument '{}' found",
                    args.path.unwrap().display()
                ),
            )
            .exit();
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
        return View::Manifest {
            path,
            debug: false,
            // To specify trust, use the explicit command `c2patool view manifest`
            trust: Trust::default(),
        }
        .execute();
    }

    // Safe to unwrap since if no input or command is specified, we exit. If
    // only the input is specified, we populate the command. Otherwise, command
    // is guaranteed to be specified.
    match args.command.unwrap() {
        Commands::Sign(sign) => sign.execute()?,
        Commands::View(view) => view.execute()?,
        Commands::Extract(extract) => extract.execute()?,
    }

    Ok(())
}
