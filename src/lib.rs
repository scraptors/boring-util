use boring::ssl::{CertificateCompressionAlgorithm, CertificateCompressor};
use std::io::{self, Read, Result, Write};

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct BrotliCertificateCompressor;

impl CertificateCompressor for BrotliCertificateCompressor {
    const ALGORITHM: CertificateCompressionAlgorithm = CertificateCompressionAlgorithm::BROTLI;
    const CAN_COMPRESS: bool = true;
    const CAN_DECOMPRESS: bool = true;

    fn compress<W>(&self, input: &[u8], output: &mut W) -> Result<()>
    where
        W: Write,
    {
        let mut writer = brotli::CompressorWriter::new(output, input.len(), 11, 22);
        writer.write_all(input)?;
        writer.flush()?;
        Ok(())
    }

    fn decompress<W>(&self, input: &[u8], output: &mut W) -> Result<()>
    where
        W: Write,
    {
        let mut reader = brotli::Decompressor::new(input, 4096);
        let mut buf = [0u8; 4096];
        loop {
            match reader.read(&mut buf[..]) {
                Err(e) => {
                    if let io::ErrorKind::Interrupted = e.kind() {
                        continue;
                    }
                    return Err(e);
                }
                Ok(size) => {
                    if size == 0 {
                        break;
                    }
                    output.write_all(&buf[..size])?;
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct ZlibCertificateCompressor;

impl CertificateCompressor for ZlibCertificateCompressor {
    const ALGORITHM: CertificateCompressionAlgorithm = CertificateCompressionAlgorithm::ZLIB;
    const CAN_COMPRESS: bool = true;
    const CAN_DECOMPRESS: bool = true;

    fn compress<W>(&self, input: &[u8], output: &mut W) -> Result<()>
    where
        W: Write,
    {
        let mut encoder = flate2::write::ZlibEncoder::new(output, flate2::Compression::default());
        encoder.write_all(input)?;
        encoder.finish()?;
        Ok(())
    }

    fn decompress<W>(&self, input: &[u8], output: &mut W) -> Result<()>
    where
        W: Write,
    {
        let mut decoder = flate2::read::ZlibDecoder::new(input);
        io::copy(&mut decoder, output)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct ZstdCertificateCompressor;

impl CertificateCompressor for ZstdCertificateCompressor {
    const ALGORITHM: CertificateCompressionAlgorithm = CertificateCompressionAlgorithm::ZSTD;
    const CAN_COMPRESS: bool = true;
    const CAN_DECOMPRESS: bool = true;

    fn compress<W>(&self, input: &[u8], output: &mut W) -> Result<()>
    where
        W: Write,
    {
        let mut writer = zstd::stream::Encoder::new(output, 0)?;
        writer.write_all(input)?;
        writer.flush()?;
        Ok(())
    }

    fn decompress<W>(&self, input: &[u8], output: &mut W) -> Result<()>
    where
        W: Write,
    {
        let mut reader = zstd::stream::Decoder::new(input)?;
        let mut buf = [0u8; 4096];
        loop {
            match reader.read(&mut buf[..]) {
                Err(e) => {
                    if let io::ErrorKind::Interrupted = e.kind() {
                        continue;
                    }
                    return Err(e);
                }
                Ok(size) => {
                    if size == 0 {
                        break;
                    }
                    output.write_all(&buf[..size])?;
                }
            }
        }
        Ok(())
    }
}
