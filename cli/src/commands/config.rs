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

use anyhow::{bail, Result};
use c2pa::settings::Settings;

use crate::ConfigAction;

pub fn run(settings_path: &Path, action: &ConfigAction) -> Result<()> {
    match action {
        ConfigAction::Show => {
            if settings_path.exists() {
                let content = std::fs::read_to_string(settings_path)?;
                println!("{content}");
            } else {
                println!("No settings file found at: {}", settings_path.display());
                println!("Run 'c2patool config init' to create a default settings file.");
            }
        }
        ConfigAction::Init { force } => {
            if settings_path.exists() && !force {
                bail!(
                    "Settings file already exists at: {}\nUse --force to overwrite",
                    settings_path.display()
                );
            }

            if let Some(parent) = settings_path.parent() {
                std::fs::create_dir_all(parent)?;
            }

            let default_settings = serde_json::json!({
                "sign": {
                    "alg": "es256",
                    "private_key": "path/to/private.key",
                    "sign_cert": "path/to/certs.pem",
                    "ta_url": "http://timestamp.digicert.com"
                },
                "verify": {
                    "verify_trust": false
                }
            });

            let settings_str = serde_json::to_string_pretty(&default_settings)?;
            std::fs::write(settings_path, settings_str)?;

            println!(
                "Default settings file created at: {}",
                settings_path.display()
            );
            println!("\nEdit this file to configure your signing credentials and other settings.");
        }
        ConfigAction::Validate => {
            if !settings_path.exists() {
                bail!("Settings file not found at: {}", settings_path.display());
            }

            Settings::from_file(settings_path)?;
            println!("Settings file is valid: {}", settings_path.display());
        }
        ConfigAction::Path => {
            println!("{}", settings_path.display());
            if settings_path.exists() {
                println!("(file exists)");
            } else {
                println!("(file does not exist)");
            }
        }
    }
    Ok(())
}
