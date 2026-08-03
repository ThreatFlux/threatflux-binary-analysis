use crate::{Result, error::BinaryError};
use flate2::read::{MultiGzDecoder, ZlibDecoder};
use std::io::Read;

/// Maximum decompressed size accepted by [`decompress`]: 64 MiB.
pub const DEFAULT_MAX_DECOMPRESSED_SIZE: usize = 64 * 1024 * 1024;

/// Decompress gzip or zlib data with a 64 MiB output limit.
///
/// Use [`decompress_with_limit`] when a different application budget is needed.
#[cfg(feature = "compression")]
pub fn decompress(data: &[u8]) -> Result<Vec<u8>> {
    decompress_with_limit(data, DEFAULT_MAX_DECOMPRESSED_SIZE)
}

/// Decompress gzip or zlib data without allowing the output to exceed `max_size`.
///
/// The limit is enforced while streaming, before bytes are appended to the output
/// allocation, which protects callers from high-expansion compressed inputs.
#[cfg(feature = "compression")]
pub fn decompress_with_limit(data: &[u8], max_size: usize) -> Result<Vec<u8>> {
    if data.starts_with(b"\x1f\x8b") {
        read_bounded(MultiGzDecoder::new(data), max_size)
    } else if is_zlib_header(data) {
        read_bounded(ZlibDecoder::new(data), max_size)
    } else {
        Err(BinaryError::invalid_data("unsupported compression format"))
    }
}

fn is_zlib_header(data: &[u8]) -> bool {
    let Some((&cmf, rest)) = data.split_first() else {
        return false;
    };
    let Some(&flg) = rest.first() else {
        return false;
    };

    // RFC 1950: DEFLATE (CM=8), a window no larger than 32 KiB (CINFO<=7),
    // and a header divisible by 31. This accepts every valid compression-level
    // encoding instead of recognizing only three common byte pairs.
    cmf & 0x0f == 8 && cmf >> 4 <= 7 && (u16::from(cmf) << 8 | u16::from(flg)) % 31 == 0
}

fn read_bounded(mut reader: impl Read, max_size: usize) -> Result<Vec<u8>> {
    const BUFFER_SIZE: usize = 8 * 1024;

    let mut output = Vec::with_capacity(max_size.min(BUFFER_SIZE));
    let mut buffer = [0_u8; BUFFER_SIZE];

    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            return Ok(output);
        }

        let new_len = output
            .len()
            .checked_add(count)
            .ok_or_else(|| BinaryError::invalid_data("decompressed size overflows usize"))?;
        if new_len > max_size {
            return Err(BinaryError::invalid_data(format!(
                "decompressed data exceeds the {max_size}-byte limit"
            )));
        }

        output
            .try_reserve(count)
            .map_err(|_| BinaryError::invalid_data("unable to allocate decompression output"))?;
        output.extend_from_slice(&buffer[..count]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::Compression;
    use flate2::write::{GzEncoder, ZlibEncoder};

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

    #[cfg(feature = "compression")]
    #[test]
    fn rejects_output_larger_than_limit() {
        let data = vec![b'A'; 64 * 1024];
        let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
        use std::io::Write;
        encoder.write_all(&data).unwrap();
        let compressed = encoder.finish().unwrap();

        let error = decompress_with_limit(&compressed, 1024).unwrap_err();
        assert!(error.to_string().contains("1024-byte limit"));
    }

    #[cfg(feature = "compression")]
    #[test]
    fn accepts_exact_output_limit() {
        let data = b"exact limit";
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::none());
        use std::io::Write;
        encoder.write_all(data).unwrap();
        let compressed = encoder.finish().unwrap();

        assert_eq!(
            decompress_with_limit(&compressed, data.len()).unwrap(),
            data
        );
    }

    #[test]
    fn recognizes_all_valid_rfc_1950_headers() {
        assert!(is_zlib_header(&[0x78, 0x01]));
        assert!(is_zlib_header(&[0x78, 0x5e]));
        assert!(is_zlib_header(&[0x78, 0x9c]));
        assert!(is_zlib_header(&[0x78, 0xda]));
        assert!(!is_zlib_header(&[0x78, 0x00]));
        assert!(!is_zlib_header(&[0x88, 0x1c]));
    }
}
