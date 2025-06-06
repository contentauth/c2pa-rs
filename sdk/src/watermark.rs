use crate::{assertions::SoftBinding, CAIRead, CAIReadWrite, Result};

/// Trait for watermarking files such as images, video, or audio assets.
///
/// Implementors of this trait provide algorithms to embed watermarks
/// into supported media types.
/// The trait exposes methods to query supported MIME types, apply the watermark
/// and identify the algorithm.
pub trait Watermarker {
    /// Returns a slice of MIME types supported by this watermarking algorithm.
    ///
    /// This allows consumers to determine if a given file type can be watermarked
    /// by this implementation.
    fn supported_mime_types(&self) -> &[&str];

    /// Applies the watermarking algorithm to the provided stream.
    ///
    /// # Arguments
    /// * `value` - A string representing the value to be watermarked.
    /// * `format` - A string representing the format of the stream.
    /// * `source` - A reference to the input stream implementing `CAIRead`.
    /// * `dest` - A mutable reference to the output, watermarked stream implementing `CAIReadWrite`.
    ///
    /// # Returns
    /// * `Ok(SoftBinding)` if watermarking succeeds.
    /// * `Err(crate::Error)` if watermarking fails.
    fn watermark(
        &self,
        value: &str,
        format: &str,
        source: &dyn CAIRead,
        dest: &mut dyn CAIReadWrite,
    ) -> Result<SoftBinding>;
}
