use std::io::Cursor;

use js_sys::{Array, Uint8Array};
use wasm_bindgen::prelude::*;
use web_sys::console;

/// Initialize the panic hook for better error reporting in the browser
#[wasm_bindgen(start)]
pub fn main() {
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

/// A WASM-compatible wrapper around the C2PA Reader
#[wasm_bindgen]
pub struct C2paReader {
    reader: c2pa::Reader,
}

#[wasm_bindgen]
impl C2paReader {
    /// Create a new C2PA reader from a byte array and format
    ///
    /// # Arguments
    /// * `data` - The asset data as a Uint8Array
    /// * `format` - The MIME type or file extension (e.g., "image/jpeg", "jpg")
    ///
    /// # Returns
    /// A new C2paReader instance
    ///
    /// # Errors
    /// Returns a JsError if the data cannot be parsed or no C2PA data is found
    #[wasm_bindgen(constructor)]
    pub fn new(data: &Uint8Array, format: &str) -> Result<C2paReader, JsError> {
        let bytes = data.to_vec();
        let cursor = Cursor::new(bytes);

        let reader = c2pa::Reader::from_stream(format, cursor)
            .map_err(|e| JsError::new(&format!("Failed to create reader: {}", e)))?;

        Ok(C2paReader { reader })
    }

    /// Get the manifest store as a JSON string
    ///
    /// # Returns
    /// A JSON string representation of the manifest store
    #[wasm_bindgen]
    pub fn json(&self) -> String {
        self.reader.json()
    }

    /// Get the validation status as a JSON string
    ///
    /// # Returns
    /// A JSON string representation of the validation status, or null if none
    #[wasm_bindgen]
    pub fn validation_status(&self) -> Option<String> {
        self.reader
            .validation_status()
            .map(|status| serde_json::to_string(status).unwrap_or_else(|_| "[]".to_string()))
    }

    /// Get the validation state as a string
    ///
    /// # Returns
    /// A string representation of the validation state ("valid", "invalid", "trusted")
    #[wasm_bindgen]
    pub fn validation_state(&self) -> String {
        match self.reader.validation_state() {
            c2pa::ValidationState::Valid => "valid".to_string(),
            c2pa::ValidationState::Invalid => "invalid".to_string(),
            c2pa::ValidationState::Trusted => "trusted".to_string(),
        }
    }

    /// Get the active manifest label
    ///
    /// # Returns
    /// The label of the active manifest, or null if none
    #[wasm_bindgen]
    pub fn active_label(&self) -> Option<String> {
        self.reader.active_label().map(|s| s.to_string())
    }

    /// Get the list of supported MIME types
    ///
    /// # Returns
    /// A JavaScript array of supported MIME types
    #[wasm_bindgen]
    pub fn supported_mime_types() -> Array {
        let mime_types = c2pa::Reader::supported_mime_types();
        let array = Array::new();
        for mime_type in mime_types {
            array.push(&JsValue::from_str(&mime_type));
        }
        array
    }

    /// Check if there is an active manifest
    ///
    /// # Returns
    /// True if there is an active manifest, false otherwise
    #[wasm_bindgen]
    pub fn has_active_manifest(&self) -> bool {
        self.reader.active_manifest().is_some()
    }

    /// Get the title of the active manifest
    ///
    /// # Returns
    /// The title of the active manifest, or null if none
    #[wasm_bindgen]
    pub fn get_title(&self) -> Option<String> {
        self.reader
            .active_manifest()
            .and_then(|m| m.title().map(|s| s.to_string()))
    }

    /// Get the format of the active manifest
    ///
    /// # Returns
    /// The format of the active manifest, or null if none
    #[wasm_bindgen]
    pub fn get_format(&self) -> Option<String> {
        self.reader
            .active_manifest()
            .and_then(|m| m.format().map(|s| s.to_string()))
    }

    /// Get the instance ID of the active manifest
    ///
    /// # Returns
    /// The instance ID of the active manifest, or null if none
    #[wasm_bindgen]
    pub fn get_instance_id(&self) -> Option<String> {
        self.reader
            .active_manifest()
            .map(|m| m.instance_id().to_string())
    }

    /// Get the claim generator information
    ///
    /// # Returns
    /// A JSON string representation of the claim generator info, or null if none
    #[wasm_bindgen]
    pub fn get_claim_generator(&self) -> Option<String> {
        self.reader
            .active_manifest()
            .and_then(|m| m.claim_generator())
            .and_then(|cg| serde_json::to_string(cg).ok())
    }

    /// Get the thumbnail reference
    ///
    /// # Returns
    /// A JSON string representation of the thumbnail reference, or null if none
    #[wasm_bindgen]
    pub fn get_thumbnail_ref(&self) -> Option<String> {
        self.reader
            .active_manifest()
            .and_then(|m| m.thumbnail_ref())
            .and_then(|tr| serde_json::to_string(tr).ok())
    }

    /// Get the list of ingredients
    ///
    /// # Returns
    /// A JSON string representation of the ingredients list
    #[wasm_bindgen]
    pub fn get_ingredients(&self) -> Option<String> {
        self.reader.active_manifest().map(|m| {
            let ingredients: Vec<_> = m.ingredients().into_iter().collect();
            serde_json::to_string(&ingredients).unwrap_or_else(|_| "[]".to_string())
        })
    }

    /// Get the list of assertions
    ///
    /// # Returns
    /// A JSON string representation of the assertions list
    #[wasm_bindgen]
    pub fn get_assertions(&self) -> Option<String> {
        self.reader.active_manifest().map(|m| {
            let assertions: Vec<_> = m.assertions().into_iter().collect();
            serde_json::to_string(&assertions).unwrap_or_else(|_| "[]".to_string())
        })
    }

    /// Get the signature info
    ///
    /// # Returns
    /// A JSON string representation of the signature info, or null if none
    #[wasm_bindgen]
    pub fn get_signature_info(&self) -> Option<String> {
        self.reader
            .active_manifest()
            .and_then(|m| m.signature_info())
            .and_then(|si| serde_json::to_string(si).ok())
    }
}

/// Utility function to create a C2PA reader from a File object
///
/// # Arguments
/// * `file` - A JavaScript File object
///
/// # Returns
/// A Promise that resolves to a C2paReader instance
#[wasm_bindgen]
pub async fn read_from_file(file: &web_sys::File) -> Result<C2paReader, JsError> {
    let file_name = file.name();
    let format = c2pa::format_from_path(std::path::Path::new(&file_name))
        .ok_or_else(|| JsError::new("Unsupported file format"))?;

    let array_buffer = wasm_bindgen_futures::JsFuture::from(file.array_buffer())
        .await
        .map_err(|e| JsError::new(&format!("Failed to read file: {:?}", e)))?;

    let uint8_array = Uint8Array::new(&array_buffer);
    C2paReader::new(&uint8_array, &format)
}

/// Check if a file format is supported
///
/// # Arguments
/// * `format` - The MIME type or file extension
///
/// # Returns
/// True if the format is supported, false otherwise
#[wasm_bindgen]
pub fn is_format_supported(format: &str) -> bool {
    c2pa::Reader::supported_mime_types().contains(&format.to_string())
}

/// Get the SDK version
///
/// # Returns
/// The version string of the C2PA SDK
#[wasm_bindgen]
pub fn version() -> String {
    c2pa::VERSION.to_string()
}

/// Get the SDK name
///
/// # Returns
/// The name of the C2PA SDK
#[wasm_bindgen]
pub fn name() -> String {
    c2pa::NAME.to_string()
}

/// Log a message to the console (for debugging)
#[wasm_bindgen]
pub fn log(message: &str) {
    console::log_1(&message.into());
}
