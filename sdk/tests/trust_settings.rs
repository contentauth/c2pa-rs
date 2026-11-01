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

use std::io::Cursor;

use c2pa::{
    create_signer,
    settings::{TrustAnchor, TrustListKind},
    Builder, BuilderIntent, Context, Reader, Result, Settings, SigningAlg, ValidationState,
};

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
        for settings in [
            restored.with_json(r#"{"trust":{"anchors":[]}}"#)?,
            restored.with_toml("[verify]\nocsp_fetch = false")?,
        ] {
            assert_eq!(
                settings.trust.trust_config,
                context.settings().trust.trust_config
            );
        }
    }

    for (config, expected) in [
        (r#"{"trust":{"trust_config":"1.2.3.4"}}"#, Some("1.2.3.4")),
        ("[trust]\ntrust_config = '1.2.3.4'", Some("1.2.3.4")),
        (r#"{"trust":{"trust_config":null}}"#, None),
        (r#"{"trust":{"trust_config":""}}"#, Some("")),
        ("[trust]\ntrust_config = ''", Some("")),
    ] {
        let context = Context::new().with_settings(config)?;
        assert_eq!(context.settings().trust.trust_config.as_deref(), expected);
    }

    Ok(())
}

#[test]
fn typed_trust_settings_preserve_none_and_manifest_kind() -> Result<()> {
    let mut settings = Settings::new();
    settings.trust.trust_config = None;
    let anchor = TrustAnchor::default();
    assert_eq!(anchor.trust_kind, TrustListKind::Manifest);
    settings.trust.anchors = Some(vec![anchor]);
    let context = Context::new().with_settings(settings)?;
    assert_eq!(context.settings().trust.trust_config, None);
    let serialized = serde_json::to_value(context.settings())?;
    assert!(serialized["trust"].get("trust_kind").is_none());
    assert_eq!(serialized["trust"]["anchors"][0]["trust_kind"], "manifest");
    let restored = Settings::new().with_json(&serialized.to_string())?;
    assert_eq!(restored.trust, context.settings().trust);
    Ok(())
}

const EKU_CERTIFICATES: [(&str, &str, bool, &[u8]); 7] = [
    (
        "document",
        "1.3.6.1.5.5.7.3.36",
        false,
        include_bytes!("fixtures/certs/eku/document.pub"),
    ),
    (
        "document_email",
        "1.3.6.1.5.5.7.3.36",
        true,
        include_bytes!("fixtures/certs/eku/document_email.pub"),
    ),
    (
        "c2pa",
        "1.3.6.1.4.1.62558.2.1",
        false,
        include_bytes!("fixtures/certs/eku/c2pa.pub"),
    ),
    (
        "c2pa_email",
        "1.3.6.1.4.1.62558.2.1",
        true,
        include_bytes!("fixtures/certs/eku/c2pa_email.pub"),
    ),
    (
        "microsoft",
        "1.3.6.1.4.1.311.76.59.1.9",
        false,
        include_bytes!("fixtures/certs/eku/microsoft.pub"),
    ),
    (
        "microsoft_email",
        "1.3.6.1.4.1.311.76.59.1.9",
        true,
        include_bytes!("fixtures/certs/eku/microsoft_email.pub"),
    ),
    (
        "email",
        "1.3.6.1.5.5.7.3.4",
        true,
        include_bytes!("fixtures/certs/eku/email.pub"),
    ),
];

fn eku_settings() -> Settings {
    let mut settings = Settings::new();
    settings.trust.anchors = Some(vec![TrustAnchor {
        trust_anchors: include_str!("fixtures/certs/eku/root.pub").to_owned(),
        ..TrustAnchor::default()
    }]);
    settings
}

fn sign_with_eku_context(context: &std::sync::Arc<Context>, certs: &[u8]) -> Result<Vec<u8>> {
    let signer = create_signer::from_keys(
        certs,
        include_bytes!("fixtures/certs/es256.pem"),
        SigningAlg::Es256,
        None,
    )?;
    let mut builder = Builder::from_shared_context(context);
    builder.set_intent(BuilderIntent::Edit);
    let mut source = Cursor::new(include_bytes!("fixtures/earth_apollo17.jpg"));
    let mut dest = Cursor::new(Vec::new());
    builder.sign(signer.as_ref(), "image/jpeg", &mut source, &mut dest)?;
    Ok(dest.into_inner())
}

#[test]
fn trust_eku_certificates_sign_and_read_with_explicit_policies() -> Result<()> {
    let defaults = Context::new().with_settings(eku_settings())?.into_shared();
    for (name, oid, email, certs) in EKU_CERTIFICATES {
        let pem = x509_parser::pem::Pem::iter_from_buffer(certs)
            .next()
            .unwrap()
            .unwrap();
        let (_, certificate) = x509_parser::parse_x509_certificate(&pem.contents).unwrap();
        let eku = &certificate.extended_key_usage().unwrap().unwrap().value;
        assert_eq!(eku.email_protection, email, "{name}");
        assert_eq!(eku.other.len(), usize::from(name != "email"), "{name}");
        if name != "email" {
            assert_eq!(eku.other[0].to_string(), oid, "{name}");
        }

        assert!(defaults.settings().verify.verify_after_sign);
        let asset = sign_with_eku_context(&defaults, certs)?;
        let reader = Reader::from_shared_context(&defaults)
            .with_stream("image/jpeg", Cursor::new(&asset))?;
        assert_eq!(
            reader.validation_state(),
            ValidationState::Trusted,
            "{name}: {reader}"
        );

        for value in [
            serde_json::json!(oid),
            serde_json::json!("1.2.3.4"),
            serde_json::json!(""),
            serde_json::Value::Null,
        ] {
            let context = Context::new()
                .with_settings(eku_settings().with_value("trust.trust_config", value.clone())?)?
                .into_shared();
            let accepted = email || value.as_str() == Some(oid);
            let signed = sign_with_eku_context(&context, certs);
            assert_eq!(signed.is_ok(), accepted, "{name}, {value}: {signed:?}");
            let reader = Reader::from_shared_context(&context)
                .with_stream("image/jpeg", Cursor::new(&asset))?;
            assert_eq!(
                reader.validation_state(),
                if accepted {
                    ValidationState::Trusted
                } else {
                    ValidationState::Invalid
                },
                "{name}, {value}: {reader}"
            );
            if !accepted {
                assert!(
                    reader.validation_status().unwrap().iter().any(|status| {
                        status.code() == c2pa::validation_status::SIGNING_CREDENTIAL_INVALID
                    }),
                    "{name}, {value}: {reader}"
                );
            }
        }
    }
    Ok(())
}

#[test]
fn trust_eku_contexts_are_isolated_across_signing_and_reading() -> Result<()> {
    let defaults = Context::new().with_settings(eku_settings())?.into_shared();
    let cleared = Context::new()
        .with_settings(eku_settings().with_value("trust.trust_config", serde_json::Value::Null)?)?
        .into_shared();
    let certs = EKU_CERTIFICATES[0].3;
    let asset = sign_with_eku_context(&defaults, certs)?;
    std::thread::scope(|scope| {
        scope.spawn(|| {
            for _ in 0..3 {
                assert!(sign_with_eku_context(&defaults, certs).is_ok());
                let reader = Reader::from_shared_context(&defaults)
                    .with_stream("image/jpeg", Cursor::new(&asset))
                    .unwrap();
                assert_eq!(reader.validation_state(), ValidationState::Trusted);
            }
        });
        scope.spawn(|| {
            for _ in 0..3 {
                assert!(sign_with_eku_context(&cleared, certs).is_err());
                let reader = Reader::from_shared_context(&cleared)
                    .with_stream("image/jpeg", Cursor::new(&asset))
                    .unwrap();
                assert_eq!(reader.validation_state(), ValidationState::Invalid);
            }
        });
    });
    assert_eq!(
        defaults.settings().trust.trust_config.as_deref(),
        Some(include_str!("../src/crypto/cose/valid_eku_oids.cfg"))
    );
    assert_eq!(cleared.settings().trust.trust_config, None);
    Ok(())
}
