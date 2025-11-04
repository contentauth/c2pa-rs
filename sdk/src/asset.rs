use std::io::{BufReader, Read, Seek, Write};

use crate::{
    asset_io::CAIRead,
    jumbf_io::{get_cailoader_handler, get_caiwriter_handler},
    Error, Result,
};

pub struct Asset<'a> {
    stream: Box<dyn CAIRead + 'a>,
    xmp: Option<String>,
    manifest: Option<Vec<u8>>,
}

impl<'a> Asset<'a> {
    pub fn from_stream(stream: impl Read + Seek + Send + 'a, format: &str) -> Result<Self> {
        let cailoader_handler = get_cailoader_handler(format).ok_or(Error::UnsupportedType)?;
        let mut stream = BufReader::new(stream);
        let xmp = cailoader_handler.read_xmp(&mut stream);
        stream.rewind()?;
        let manifest = cailoader_handler.read_cai(&mut stream)?;
        Ok(Asset {
            stream: Box::new(stream),
            xmp,
            manifest: Some(manifest),
        })
    }

    pub fn to_stream(
        &mut self,
        mut output: impl Read + Write + Seek + Send,
        format: &str,
    ) -> Result<()> {
        let caiwriter_handler = get_caiwriter_handler(format).ok_or(Error::UnsupportedType)?;
        if let Some(manifest) = &self.manifest {
            caiwriter_handler.write_cai(&mut self.stream, &mut output, manifest)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use std::{
        fs::File,
        io::{BufReader, Cursor},
    };

    use super::*;
    use crate::{content_credential::ContentCredential, settings::Settings};
    #[test]
    fn test_asset_from_stream() {
        let settings = Settings::default();
        let file = File::open("tests/fixtures/C.jpg").unwrap();
        let mut reader = BufReader::new(file);
        let mut asset = Asset::from_stream(&mut reader, "image/jpeg").unwrap();
        if let Some(xmp) = &asset.xmp {
            println!("xmp: {xmp}");
        }
        assert!(asset.manifest.is_some());
        if let Some(manifest) = &asset.manifest {
            let cc = ContentCredential::from_stream(
                &settings,
                "application/c2pa",
                std::io::Cursor::new(manifest),
            )
            .unwrap();
            println!("manifest: {:?}", cc);
        }
        let mut output = Cursor::new(Vec::new());
        Asset::to_stream(&mut asset, &mut output, "image/jpeg").unwrap();

        let cc = ContentCredential::from_stream(&settings, "image/jpeg", &mut output).unwrap();
        println!("manifest: {:?}", cc);
    }
}
