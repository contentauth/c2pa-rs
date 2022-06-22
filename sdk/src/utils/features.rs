/// Function that is used by serde to determine whether or not we should serialize
/// thumbnail data based on the "serialize_thumbnails" flag (serialization is disabled by default)
pub fn skip_serializing_thumbnails(_value: &Option<(String, Vec<u8>)>) -> bool {
    !cfg!(feature = "serialize_thumbnails")
}
