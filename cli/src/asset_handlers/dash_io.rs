use std::path::Path;
use anyhow::Result;
use serde::Deserialize;
use quick_xml::de::from_str;

#[derive(Debug, Deserialize)]
#[serde(rename = "MPD")]
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
    #[serde(rename = "@contentType")]
    pub content_type: String,
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
    #[serde(rename = "SegmentTimeline")]
    pub segment_timeline: SegmentTimeline,
}

#[derive(Debug, Deserialize)]
pub struct SegmentTimeline {
    #[serde(rename = "S")]
    pub segments: Vec<TimelineSegment>,
}

#[derive(Debug, Deserialize)]
pub struct TimelineSegment {
    #[serde(rename = "@t")]
    pub time: Option<u32>,
    #[serde(rename = "@d")]
    pub duration: u32,
}

pub struct DashIO;

impl DashIO {
    pub fn new() -> Self {
        Self
    }

    pub fn parse_manifest(manifest_path: &Path) -> Result<DashManifest> {
        let manifest_content = std::fs::read_to_string(manifest_path)?;
        let manifest: DashManifest = from_str(&manifest_content)
            .map_err(|e| anyhow::anyhow!("Failed to parse DASH manifest: {}", e))?;
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