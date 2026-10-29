// Copyright 2026 Adobe. All rights reserved.
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

use c2pa::{Context, Result, Settings};

#[test]
fn default_trust_ekus_survive_settings_overlays() -> Result<()> {
    let defaults = include_str!("../src/crypto/cose/valid_eku_oids.cfg");

    // Integration tests exercise production defaults, without cfg(test) trust fixtures.
    for context in [
        Context::new(),
        Context::new().with_settings(Settings::new())?,
        Context::new().with_settings("{}")?,
        Context::new().with_settings(r#"{"trust":{"anchors":[]}}"#)?,
        Context::new().with_settings("[verify]\nocsp_fetch = false")?,
    ] {
        assert_eq!(
            context.settings().trust.trust_config.as_deref(),
            Some(defaults)
        );
        assert!(context
            .settings()
            .trust
            .anchors
            .as_ref()
            .is_none_or(Vec::is_empty));
    }

    Ok(())
}

#[test]
fn explicit_trust_ekus_replace_defaults() -> Result<()> {
    for value in [
        serde_json::json!("1.2.3.4"),
        serde_json::json!(""),
        serde_json::Value::Null,
    ] {
        let context = Context::new().with_settings_value("trust.trust_config", value.clone())?;
        assert_eq!(
            serde_json::to_value(&context.settings().trust.trust_config)?,
            value
        );

        let serialized = serde_json::to_string(context.settings())?;
        let restored = Settings::new().with_json(&serialized)?;
        assert_eq!(
            restored.trust.trust_config,
            context.settings().trust.trust_config
        );
    }

    for config in [
        r#"{"trust":{"trust_config":"1.2.3.4"}}"#,
        "[trust]\ntrust_config = '1.2.3.4'",
    ] {
        let context = Context::new().with_settings(config)?;
        assert_eq!(
            context.settings().trust.trust_config.as_deref(),
            Some("1.2.3.4")
        );
    }

    Ok(())
}
