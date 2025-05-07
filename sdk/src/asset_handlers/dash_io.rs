use std::path::Path;
use crate::error::Result;
use quick_xml::de::from_str;
use serde::Deserialize;

use crate::asset_io::{AssetIO, CAIRead, CAIReadWrite, CAIReader, CAIWriter, RemoteRefEmbed, RemoteRefEmbedType, AssetPatch, HashObjectPositions};
use super::bmff_io::BmffIO;

#[derive(Debug, Deserialize)]
pub struct DashManifest {
    #[serde(rename = "@mediaPresentationDuration")]
    pub duration: String,
    #[serde(rename = "@minBufferTime")]
    pub min_buffer_time: String,
    #[serde(rename = "Period")]
    pub periods: Vec<Period>,
}

#[derive(Debug, Deserialize)]
pub struct Period {
    #[serde(rename = "AdaptationSet")]
    pub adaptation_sets: Vec<AdaptationSet>,
}

#[derive(Debug, Deserialize)]
pub struct AdaptationSet {
    #[serde(rename = "@id")]
    pub id: String,
    #[serde(rename = "@mimeType")]
    pub mime_type: String,
    #[serde(rename = "Representation")]
    pub representations: Vec<Representation>,
}

#[derive(Debug, Deserialize)]
pub struct Representation {
    #[serde(rename = "@id")]
    pub id: String,
    #[serde(rename = "@bandwidth")]
    pub bandwidth: u32,
    #[serde(rename = "@codecs")]
    pub codecs: String,
    #[serde(rename = "SegmentTemplate")]
    pub segment_template: Option<SegmentTemplate>,
}

#[derive(Debug, Deserialize)]
pub struct SegmentTemplate {
    #[serde(rename = "@initialization")]
    pub initialization: String,
    #[serde(rename = "@media")]
    pub media: String,
    #[serde(rename = "@timescale")]
    pub timescale: u32,
    #[serde(rename = "@duration")]
    pub duration: u32,
}

pub struct DashIO {
    bmff_io: BmffIO,
}

impl DashIO {
    pub fn parse_manifest(manifest_path: &Path) -> Result<DashManifest> {
        let manifest_content = std::fs::read_to_string(manifest_path)?;
        let manifest: DashManifest = from_str(&manifest_content)
            .map_err(|e| crate::error::Error::OtherError(format!("Failed to parse DASH manifest: {}", e).into()))?;
        Ok(manifest)
    }

    pub fn get_init_segments(&self, manifest: &DashManifest, base_path: &Path) -> Vec<String> {
        let mut init_segments = Vec::new();
        
        for period in &manifest.periods {
            for adaptation_set in &period.adaptation_sets {
                for representation in &adaptation_set.representations {
                    if let Some(template) = &representation.segment_template {
                        let init_path = template.initialization
                            .replace("$RepresentationID$", &representation.id);
                        let full_path = base_path.join(&init_path);
                        if let Some(path_str) = full_path.to_str() {
                            init_segments.push(path_str.to_string());
                        }
                    }
                }
            }
        }
        
        init_segments
    }

    pub fn get_fragment_pattern(&self, _manifest: &DashManifest, base_path: &Path) -> String {
        // For now, we'll use a simple pattern that matches all .m4s files
        // In a real implementation, we would parse the segment template pattern
        base_path.join("chunk-stream*-*.m4s").to_str().unwrap_or("").to_string()
    }
}

impl AssetIO for DashIO {
    fn new(asset_type: &str) -> Self {
        Self {
            bmff_io: BmffIO::new(asset_type),
        }
    }

    fn get_handler(&self, asset_type: &str) -> Box<dyn AssetIO> {
        Box::new(Self::new(asset_type))
    }

    fn get_reader(&self) -> &dyn CAIReader {
        self
    }

    fn supported_types(&self) -> &[&str] {
        &["dash"]
    }

    fn asset_patch_ref(&self) -> Option<&dyn AssetPatch> {
        self.bmff_io.asset_patch_ref()
    }

    fn read_cai_store(&self, asset_path: &Path) -> Result<Vec<u8>> {
        self.bmff_io.read_cai_store(asset_path)
    }

    fn save_cai_store(&self, asset_path: &Path, store_bytes: &[u8]) -> Result<()> {
        self.bmff_io.save_cai_store(asset_path, store_bytes)
    }

    fn get_object_locations(&self, asset_path: &Path) -> Result<Vec<HashObjectPositions>> {
        self.bmff_io.get_object_locations(asset_path)
    }

    fn remove_cai_store(&self, asset_path: &Path) -> Result<()> {
        self.bmff_io.remove_cai_store(asset_path)
    }
}

impl CAIReader for DashIO {
    fn read_cai(&self, reader: &mut dyn CAIRead) -> Result<Vec<u8>> {
        self.bmff_io.read_cai(reader)
    }

    fn read_xmp(&self, reader: &mut dyn CAIRead) -> Option<String> {
        self.bmff_io.read_xmp(reader)
    }
}

impl CAIWriter for DashIO {
    fn write_cai(
        &self,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
        store_bytes: &[u8],
    ) -> Result<()> {
        self.bmff_io.write_cai(input_stream, output_stream, store_bytes)
    }

    fn get_object_locations_from_stream(
        &self,
        input_stream: &mut dyn CAIRead,
    ) -> Result<Vec<HashObjectPositions>> {
        self.bmff_io.get_object_locations_from_stream(input_stream)
    }

    fn remove_cai_store_from_stream(
        &self,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
    ) -> Result<()> {
        self.bmff_io.remove_cai_store_from_stream(input_stream, output_stream)
    }
}

impl RemoteRefEmbed for DashIO {
    fn embed_reference(
        &self,
        asset_path: &Path,
        embed_ref: RemoteRefEmbedType,
    ) -> Result<()> {
        self.bmff_io.embed_reference(asset_path, embed_ref)
    }

    fn embed_reference_to_stream(
        &self,
        input_stream: &mut dyn CAIRead,
        output_stream: &mut dyn CAIReadWrite,
        embed_ref: RemoteRefEmbedType,
    ) -> Result<()> {
        self.bmff_io.embed_reference_to_stream(input_stream, output_stream, embed_ref)
    }
} 