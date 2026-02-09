//! Centralized location for file signatures (magic bytes).

/// JPEG start of image marker
pub const JPEG: &[u8] = b"\xff\xd8\xff";

/// PNG file signature
pub const PNG: &[u8] = b"\x89PNG\r\n\x1a\n";

/// GIF signatures
pub const GIF87A: &[u8] = b"GIF87a";
pub const GIF89A: &[u8] = b"GIF89a";

/// TIFF signatures (Little Endian and Big Endian)
pub const TIFF_LE: &[u8] = b"II\x2a\x00";
pub const TIFF_BE: &[u8] = b"MM\x00\x2a";

/// BMFF (ISO Base Media File Format) "ftyp" marker
pub const BMFF_FTYP: &[u8] = b"ftyp";

/// RIFF container signature (used by WEBP, WAV, AVI)
pub const RIFF: &[u8] = b"RIFF";
pub const WEBP: &[u8] = b"WEBP";
pub const WAVE: &[u8] = b"WAVE";
pub const AVI:  &[u8] = b"AVI ";

/// MP3 signatures
pub const MP3_ID3: &[u8] = b"ID3";

/// PDF signature
pub const PDF: &[u8] = b"%PDF-";

/// SVG text patterns
pub const SVG_TAG: &str = "<svg";
pub const SVG_XML_TAG: &str = "<?xml";

/// JUMBF/C2PA box type
pub const JUMBF_TYPE: &[u8] = b"jumb";