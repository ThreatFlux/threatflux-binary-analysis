use crate::{error::BinaryError, Result};
use flate2::read::{GzDecoder, ZlibDecoder};
use std::io::Read;

/// Decompress gzip or zlib data.
#[cfg(feature = "compression")]
pub fn decompress(data: &[u8]) -> Result<Vec<u8>> {
    if data.starts_with(b"\x1f\x8b") {
        let mut decoder = GzDecoder::new(data);
        let mut out = Vec::new();
        decoder.read_to_end(&mut out)?;
        Ok(out)
    } else if data.starts_with(b"\x78\x9c")
        || data.starts_with(b"\x78\x01")
        || data.starts_with(b"\x78\xda")
    {
        let mut decoder = ZlibDecoder::new(data);
        let mut out = Vec::new();
        decoder.read_to_end(&mut out)?;
        Ok(out)
    } else {
        Err(BinaryError::invalid_data("unsupported compression format"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::write::{GzEncoder, ZlibEncoder};
    use flate2::Compression;

    #[cfg(feature = "compression")]
    #[test]
    fn test_decompress_gzip() {
        let data = b"hello world";
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        use std::io::Write;
        encoder.write_all(data).unwrap();
        let compressed = encoder.finish().unwrap();

        let decompressed = decompress(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[cfg(feature = "compression")]
    #[test]
    fn test_decompress_zlib() {
        let data = b"another test";
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        use std::io::Write;
        encoder.write_all(data).unwrap();
        let compressed = encoder.finish().unwrap();

        let decompressed = decompress(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }
}
