V2 API 

/// Existing ManifestStore functions
pub fn from_store_with_resources(
    store: &Store,
    validation_log: &impl StatusTracker,
    resource_path: &Path
) -> ManifestStore

pub fn from_manifest(manifest: &Manifest) -> Result<Self>

pub fn from_bytes(
    format: &str,
    image_bytes: &[u8],
    verify: bool
) -> Result<ManifestStore>


pub fn from_stream(
    format: &str,
    stream: &mut dyn CAIRead,
    verify: bool
) -> Result<ManifestStore>


pub fn from_file<P: AsRef<Path>>(path: P) -> Result<ManifestStore>

pub fn from_file_with_resources<P: AsRef<Path>>(
    path: P,
    resource_path: P
) -> Result<ManifestStore>


pub async fn from_bytes_async(
    format: &str,
    image_bytes: &[u8],
    verify: bool
) -> Result<ManifestStore>


pub async fn from_fragment_bytes_async(
    format: &str,
    init_bytes: &[u8],
    fragment_bytes: &[u8],
    verify: bool
) -> Result<ManifestStore>

pub async fn from_manifest_and_asset_bytes_async(
    manifest_bytes: &[u8],
    format: &str,
    asset_bytes: &[u8]
) -> Result<ManifestStore>

pub fn from_manifest_and_asset_bytes(
    manifest_bytes: &[u8],
    format: &str,
    asset_bytes: &[u8]
) -> Result<ManifestStore>


struct Settings {
    /// Set verify to true to verify the integrity of the manifest.(default: true)
    verify: bool,
    /// preset the manifest bytes if you want to just verify against the asset
    manifest_bytes: Option<Vec<u8>>,
    /// Set init_bytes when reading fragments from from a video stream
    init_bytes: Option<Vec<u8>>,
}

pub fn c2pa::new(settings: &Settings) -> Result<Reader>

pub fn c2pa.read(
    &self,
    format: &str,
    stream: &mut dyn CAIRead,
) -> Result<Reader>

pub async fn c2pa.read_async(
    &self,
    format: &str,
    stream: &mut dyn CAIRead,
) -> Result<Reader>

pub fn Reader.json() -> Result<String>

pub fn Reader.resource(uri: &str, stream: &mut dyn CAIReadWrite) -> Result<usize>


/// Examples

// from_file:
fn c2pa.read_file<P: AsRef<Path>>(path: P) -> Result<Reader> {
    let file = File::open(path)?;
    let format = path.extension()?.to_str()?;
    c2pa.read(format, &mut file)
}

// from_bytes_async
async fn c2pa.read_bytes_async(format: &str, bytes: &[u8]) -> Result<Reader> {
    c2pa.read_async(format, &mut Cursor::new(bytes)).await
}

// from_manifest_and_asset_bytes_async:
let c2pa = c2pa.new(&Settings {
    manifest_bytes: Some(manifest_bytes.to_vec()),
});
let reader = c2pa.read_async(format, &mut Cursor::new(asset_bytes)).await?;

// from_file_with_resources:
// There are two ways to handle this
// The new way is to only read the resources you want
let reader = c2pa.from_file(file_path)?;
let json = reader.json()?;



let file = File::open(path)?;
let format = path.extension()?.to_str()?;
let c2pa = c2pa.new(&Settings {});
let mut reader = c2pa.read(format, &mut file)?;
std::fs::write(base_path.join("manifest.json"), reader.json()?)?;
for each reference in reader.resources() {
    let path = base_path.join(reference.to_path());
    let mut resource_file = File::open(path)?;
    reader.resource(reference.uri, &mut resource_file)?;
}   


let builder = c2pa.build().with_json(&json);
builder.add_resource("file:///path/to/resource", &mut resource_file);
builder.sign()?;