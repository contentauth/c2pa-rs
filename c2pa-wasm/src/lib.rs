use std::io::Cursor;
use std::io::{Read, Seek, SeekFrom, Write};

use js_sys::{Array, Uint8Array, Function};
use wasm_bindgen::prelude::*;
use web_sys::console;

/// Initialize the panic hook for better error reporting in the browser
#[wasm_bindgen(start)]
pub fn main() {
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();
}

/// Seek mode for JavaScript streaming callbacks
#[wasm_bindgen]
#[derive(Clone, Copy, Debug)]
pub enum SeekMode {
    /// Seek from the start of the stream
    Start = 0,
    /// Seek from the current position
    Current = 1,
    /// Seek from the end of the stream
    End = 2,
}

/// Interface for JavaScript streaming callbacks
/// This allows true streaming from JavaScript without loading everything into memory
#[wasm_bindgen]
pub struct JsStreamCallbacks {
    read_callback: Function,
    seek_callback: Function,
    write_callback: Option<Function>,
    flush_callback: Option<Function>,
}

#[wasm_bindgen]
impl JsStreamCallbacks {
    /// Create a new JavaScript stream callbacks object
    ///
    /// # Arguments
    /// * `read_callback` - JavaScript function that takes (buffer_size: number) and returns Promise<Uint8Array>
    /// * `seek_callback` - JavaScript function that takes (offset: number, mode: SeekMode) and returns Promise<number>
    /// * `write_callback` - Optional JavaScript function that takes (data: Uint8Array) and returns Promise<number>
    /// * `flush_callback` - Optional JavaScript function that takes () and returns Promise<void>
    #[wasm_bindgen(constructor)]
    pub fn new(
        read_callback: Function,
        seek_callback: Function,
        write_callback: Option<Function>,
        flush_callback: Option<Function>,
    ) -> JsStreamCallbacks {
        JsStreamCallbacks {
            read_callback,
            seek_callback,
            write_callback,
            flush_callback,
        }
    }
}

/// An async-compatible stream that works with JavaScript callbacks
/// This bridges JavaScript async callbacks with Rust's sync streaming traits
/// 
/// LIMITATION: This implementation requires JavaScript callbacks to work synchronously 
/// or provide pre-loaded data. True async streaming would require the C2PA SDK to 
/// support async traits natively.
/// 
/// For now, this serves as a foundation that can be extended when async trait support
/// is added to the C2PA SDK.
pub struct JsCallbackStream {
    callbacks: JsStreamCallbacks,
    position: u64,
    // Buffer for efficient small reads
    buffer: Vec<u8>,
    buffer_pos: usize,
    buffer_end: usize,
    // Flag to indicate if we've hit EOF
    eof: bool,
}

impl JsCallbackStream {
    pub fn new(callbacks: JsStreamCallbacks) -> Self {
        JsCallbackStream {
            callbacks,
            position: 0,
            buffer: vec![0; 8192], // 8KB buffer
            buffer_pos: 0,
            buffer_end: 0,
            eof: false,
        }
    }

    /// Fill the internal buffer by reading from JavaScript
    /// Note: This currently requires synchronous JavaScript callbacks
    /// In a future version with async C2PA SDK, this could be truly async
    fn fill_buffer(&mut self) -> std::io::Result<()> {
        if self.eof {
            return Ok(());
        }

        // Call the JavaScript read callback for buffer size
        let result = self.callbacks.read_callback.call1(&JsValue::NULL, &JsValue::from(self.buffer.len() as u32))
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("Read callback error: {:?}", e)))?;

        // For now, we expect the JavaScript callback to return a Uint8Array directly
        // or a resolved promise. In a future async version, we'd await the promise here.
        let uint8_array = if let Ok(array) = result.clone().dyn_into::<js_sys::Uint8Array>() {
            array
        } else if let Ok(_promise) = result.dyn_into::<js_sys::Promise>() {
            // If it's a promise, we can't properly wait for it in sync context
            // For now, we'll try to extract the result if it's already resolved
            // This is a limitation that would be fixed with async C2PA SDK
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "Async promises not supported in sync context. Use pre-loaded data or sync JavaScript callbacks."
            ));
        } else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "JavaScript callback must return Uint8Array or Promise<Uint8Array>"
            ));
        };

        let data = uint8_array.to_vec();
        
        // If we got no data, we're at EOF
        if data.is_empty() {
            self.eof = true;
            self.buffer_end = 0;
            return Ok(());
        }
        
        // Copy data to our buffer
        let bytes_to_copy = std::cmp::min(data.len(), self.buffer.len());
        self.buffer[..bytes_to_copy].copy_from_slice(&data[..bytes_to_copy]);
        
        self.buffer_pos = 0;
        self.buffer_end = bytes_to_copy;
        
        Ok(())
    }

    /// Seek using JavaScript callbacks
    fn seek_sync(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let (offset, mode) = match pos {
            SeekFrom::Start(offset) => (offset as i64, SeekMode::Start),
            SeekFrom::Current(offset) => (offset, SeekMode::Current),
            SeekFrom::End(offset) => (offset, SeekMode::End),
        };

        // Call the JavaScript seek callback
        let result = self.callbacks.seek_callback.call2(
            &JsValue::NULL,
            &JsValue::from(offset as f64),
            &JsValue::from(mode as u32)
        ).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("Seek callback error: {:?}", e)))?;

        // Convert result to position
        let new_position = result.as_f64().unwrap_or(0.0) as u64;
        self.position = new_position;
        
        // Invalidate buffer on seek and reset EOF flag
        self.buffer_pos = 0;
        self.buffer_end = 0;
        self.eof = false;
        
        Ok(new_position)
    }

    /// Write using JavaScript callbacks
    fn write_sync(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if let Some(write_callback) = &self.callbacks.write_callback {
            let uint8_array = Uint8Array::from(buf);
            
            let result = write_callback.call1(&JsValue::NULL, &uint8_array)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("Write callback error: {:?}", e)))?;

            let bytes_written = result.as_f64().unwrap_or(0.0) as usize;
            self.position += bytes_written as u64;
            Ok(bytes_written)
        } else {
            Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "Write not supported"))
        }
    }

    /// Flush using JavaScript callbacks
    fn flush_sync(&mut self) -> std::io::Result<()> {
        if let Some(flush_callback) = &self.callbacks.flush_callback {
            let _result = flush_callback.call0(&JsValue::NULL)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("Flush callback error: {:?}", e)))?;
        }
        Ok(())
    }
}

// Implement the standard sync traits that the C2PA SDK expects
impl Read for JsCallbackStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        // If we don't have data in buffer, try to fill it
        if self.buffer_pos >= self.buffer_end {
            self.fill_buffer()?;
            
            // If still no data after fill, we're at EOF
            if self.buffer_end == 0 {
                return Ok(0);
            }
        }

        // Copy from buffer to output
        let bytes_available = self.buffer_end - self.buffer_pos;
        let bytes_to_copy = std::cmp::min(bytes_available, buf.len());
        
        buf[..bytes_to_copy].copy_from_slice(&self.buffer[self.buffer_pos..self.buffer_pos + bytes_to_copy]);
        
        self.buffer_pos += bytes_to_copy;
        self.position += bytes_to_copy as u64;
        
        Ok(bytes_to_copy)
    }
}

impl Seek for JsCallbackStream {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        self.seek_sync(pos)
    }
}

impl Write for JsCallbackStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.write_sync(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.flush_sync()
    }
}

// Mark the stream as Send + Sync for C2PA compatibility
// Note: This is safe in WASM single-threaded contexts but would not be safe in multi-threaded environments
unsafe impl Send for JsCallbackStream {}
unsafe impl Sync for JsCallbackStream {}

/// A more practical async streaming reader that chunks data from JavaScript
/// This provides a better bridge between async JavaScript and sync Rust
#[wasm_bindgen]
pub struct C2paAsyncReader {
    callbacks: JsStreamCallbacks,
}

#[wasm_bindgen]
impl C2paAsyncReader {
    /// Create a new async reader with JavaScript callbacks
    #[wasm_bindgen(constructor)]
    pub fn new(callbacks: JsStreamCallbacks) -> C2paAsyncReader {
        C2paAsyncReader { callbacks }
    }

    /// Read C2PA data from the stream asynchronously in chunks
    /// This provides a more practical approach to async streaming
    #[wasm_bindgen]
    pub async fn read_c2pa_chunked(self, format: &str) -> Result<C2paReader, JsError> {
        let mut all_data = Vec::new();
        let mut _position = 0u64;
        
        // Read the stream in chunks
        loop {
            // Call the JavaScript read callback for a chunk
            let promise = self.callbacks.read_callback.call1(&JsValue::NULL, &JsValue::from(8192u32))
                .map_err(|e| JsError::new(&format!("Read callback error: {:?}", e)))?;

            // Convert promise to future and await it
            let future = wasm_bindgen_futures::JsFuture::from(js_sys::Promise::from(promise));
            let result = future.await
                .map_err(|e| JsError::new(&format!("Read callback promise error: {:?}", e)))?;

            // Convert result to Uint8Array
            let uint8_array = Uint8Array::from(result);
            let chunk = uint8_array.to_vec();
            
            // If we got no data, we're done
            if chunk.is_empty() {
                break;
            }
            
            all_data.extend_from_slice(&chunk);
            _position += chunk.len() as u64;
        }

        // Now create a reader from the collected data
        let cursor = Cursor::new(all_data);
        let reader = c2pa::Reader::from_stream(format, cursor)
            .map_err(|e| JsError::new(&format!("Failed to create reader from stream: {}", e)))?;

        Ok(C2paReader { reader })
    }
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

    /// Create a new C2PA reader from streaming data asynchronously
    ///
    /// # Arguments
    /// * `data` - The asset data as a Uint8Array (can be from a stream)
    /// * `format` - The MIME type or file extension (e.g., "image/jpeg", "jpg")
    ///
    /// # Returns
    /// A Promise that resolves to a C2paReader instance
    ///
    /// # Errors
    /// Returns a JsError if the data cannot be parsed or no C2PA data is found
    #[wasm_bindgen]
    pub async fn from_stream(data: &Uint8Array, format: &str) -> Result<C2paReader, JsError> {
        let bytes = data.to_vec();
        let cursor = Cursor::new(bytes);

        let reader = c2pa::Reader::from_stream(format, cursor)
            .map_err(|e| JsError::new(&format!("Failed to create reader from stream: {}", e)))?;

        Ok(C2paReader { reader })
    }

    /// Create a new C2PA reader from a JavaScript ReadableStream
    ///
    /// # Arguments
    /// * `stream` - A JavaScript ReadableStream containing the asset data
    /// * `format` - The MIME type or file extension (e.g., "image/jpeg", "jpg")
    ///
    /// # Returns
    /// A Promise that resolves to a C2paReader instance
    ///
    /// # Errors
    /// Returns a JsError if the stream cannot be read or no C2PA data is found
    #[wasm_bindgen]
    pub async fn from_readable_stream(
        stream: &web_sys::ReadableStream,
        format: &str,
    ) -> Result<C2paReader, JsError> {
        // Convert ReadableStream to Response to get ArrayBuffer
        let response = web_sys::Response::new_with_opt_readable_stream(Some(stream))
            .map_err(|e| JsError::new(&format!("Failed to create response from stream: {:?}", e)))?;

        let array_buffer_promise = response.array_buffer()
            .map_err(|e| JsError::new(&format!("Failed to get array buffer promise: {:?}", e)))?;
        
        let array_buffer = wasm_bindgen_futures::JsFuture::from(array_buffer_promise)
            .await
            .map_err(|e| JsError::new(&format!("Failed to read stream data: {:?}", e)))?;

        let uint8_array = Uint8Array::new(&array_buffer);
        Self::from_stream(&uint8_array, format).await
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
    C2paReader::from_stream(&uint8_array, &format).await
}

/// Utility function to create a C2PA reader from a Blob object
///
/// # Arguments
/// * `blob` - A JavaScript Blob object
/// * `format` - The MIME type or file extension
///
/// # Returns
/// A Promise that resolves to a C2paReader instance
#[wasm_bindgen]
pub async fn read_from_blob(blob: &web_sys::Blob, format: &str) -> Result<C2paReader, JsError> {
    let array_buffer = wasm_bindgen_futures::JsFuture::from(blob.array_buffer())
        .await
        .map_err(|e| JsError::new(&format!("Failed to read blob: {:?}", e)))?;

    let uint8_array = Uint8Array::new(&array_buffer);
    C2paReader::from_stream(&uint8_array, format).await
}

/// Utility function to create a C2PA reader from an ArrayBuffer
///
/// # Arguments
/// * `buffer` - A JavaScript ArrayBuffer
/// * `format` - The MIME type or file extension
///
/// # Returns
/// A Promise that resolves to a C2paReader instance
#[wasm_bindgen]
pub async fn read_from_buffer(buffer: &js_sys::ArrayBuffer, format: &str) -> Result<C2paReader, JsError> {
    let uint8_array = Uint8Array::new(buffer);
    C2paReader::from_stream(&uint8_array, format).await
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

/// A WASM-compatible streaming reader that uses JavaScript callbacks
/// This provides true streaming support without loading entire files into memory
#[wasm_bindgen]
pub struct C2paStreamReader {
    stream: JsCallbackStream,
}

#[wasm_bindgen]
impl C2paStreamReader {
    /// Create a new streaming reader with JavaScript callbacks
    ///
    /// # Arguments
    /// * `callbacks` - JavaScript callbacks for read/seek/write/flush operations
    #[wasm_bindgen(constructor)]
    pub fn new(callbacks: JsStreamCallbacks) -> C2paStreamReader {
        C2paStreamReader {
            stream: JsCallbackStream::new(callbacks),
        }
    }

    /// Read C2PA data from the stream and return a C2paReader
    ///
    /// # Arguments  
    /// * `format` - The MIME type or file extension (e.g., "image/jpeg", "jpg")
    ///
    /// # Returns
    /// A Promise that resolves to a C2paReader instance
    ///
    /// # Errors
    /// Returns a JsError if the stream cannot be read or no C2PA data is found
    #[wasm_bindgen]
    pub async fn read_c2pa(self, format: &str) -> Result<C2paReader, JsError> {
        // Use the JsCallbackStream directly with the C2PA SDK
        // Note: This is a workaround adaptation layer. The stream implements sync traits
        // but JavaScript callbacks are async. This works in WASM single-threaded contexts
        // but is not ideal. A future version should refactor the C2PA SDK to use async traits.
        let reader = c2pa::Reader::from_stream(format, self.stream)
            .map_err(|e| JsError::new(&format!("Failed to create reader from stream: {}", e)))?;

        Ok(C2paReader { reader })
    }

    /// Get the current position in the stream
    #[wasm_bindgen]
    pub fn position(&self) -> u64 {
        self.stream.position
    }
}
