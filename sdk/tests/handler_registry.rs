// Copyright 2026 Adobe. All rights reserved.
// This file is licensed to you under the Apache License,
// Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
// or the MIT license (http://opensource.org/licenses/MIT),
// at your option.

#![cfg(feature = "asset_io")]

use c2pa::{Context, HandlerRegistry};

#[test]
fn context_registry_is_public() {
    let mut context = Context::new();
    let registry: &HandlerRegistry = context.io();
    assert_eq!(registry.mime_for("jpg"), Some("image/jpeg"));
    assert!(registry
        .reader_mime_types()
        .contains(&"image/png".to_owned()));
    let registry: &mut HandlerRegistry = context.io_mut();
    assert_eq!(registry.mime_for("png"), Some("image/png"));
}

#[test]
fn public_registry_accepts_asset_io_handlers() {
    use std::sync::Arc;

    use asset_io::container_api::{BoxFuture, ContainerHandler, FormatSpec, Io};

    #[derive(Debug)]
    struct CustomContainer;

    impl ContainerHandler for CustomContainer {
        fn id(&self) -> &'static str {
            "custom"
        }

        fn formats(&self) -> &[FormatSpec] {
            const FORMATS: &[FormatSpec] = &[FormatSpec::new("application/x-custom", "custom")];
            FORMATS
        }

        fn parse_async(
            self: Arc<Self>,
            _io: Io,
        ) -> BoxFuture<'static, asset_io::Result<asset_io::Structure>> {
            Box::pin(async { Err(asset_io::Error::UnsupportedFormat) })
        }
    }

    let mut registry = HandlerRegistry::new().with_handler(CustomContainer);
    registry.add_handler(CustomContainer);
    assert_eq!(registry.mime_for("CUSTOM"), Some("application/x-custom"));
    registry.extend(&asset_io::HandlerRegistry::builtin());
    assert_eq!(registry.mime_for("jpg"), Some("image/jpeg"));
    assert_eq!(registry.mime_for("png"), Some("image/png"));
    assert_eq!(registry.mime_for("custom"), Some("application/x-custom"));

    let mut context = Context::new().with_io_handler(CustomContainer);
    context.add_io_handler(CustomContainer);
    context.io_mut().add_handler(CustomContainer);
    context
        .io_mut()
        .extend(&asset_io::HandlerRegistry::new().with_handler(CustomContainer));
    assert_eq!(
        context.io().mime_for("custom"),
        Some("application/x-custom")
    );
    assert_eq!(context.io().mime_for("png"), Some("image/png"));
}
