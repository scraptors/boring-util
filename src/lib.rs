use boring::{
    error::ErrorStack,
    ssl::{
        CertificateCompressionAlgorithm, CertificateCompressor, SslConnectorBuilder, SslVerifyMode,
    },
    x509::{X509, store::X509StoreBuilder},
};
use bytes::{BufMut, Bytes, BytesMut};
use std::io::{self, Read, Write};

#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct BrotliCertificateCompressor;

impl CertificateCompressor for BrotliCertificateCompressor {
    const ALGORITHM: CertificateCompressionAlgorithm = CertificateCompressionAlgorithm::BROTLI;
    const CAN_COMPRESS: bool = true;
    const CAN_DECOMPRESS: bool = true;

    fn compress<W>(&self, input: &[u8], output: &mut W) -> std::io::Result<()>
    where
        W: Write,
    {
        let mut writer = brotli::CompressorWriter::new(output, input.len(), 11, 22);
        writer.write_all(input)?;
        writer.flush()?;
        Ok(())
    }

    fn decompress<W>(&self, input: &[u8], output: &mut W) -> std::io::Result<()>
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

    fn compress<W>(&self, input: &[u8], output: &mut W) -> std::io::Result<()>
    where
        W: Write,
    {
        let mut encoder = flate2::write::ZlibEncoder::new(output, flate2::Compression::default());
        encoder.write_all(input)?;
        encoder.finish()?;
        Ok(())
    }

    fn decompress<W>(&self, input: &[u8], output: &mut W) -> std::io::Result<()>
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

    fn compress<W>(&self, input: &[u8], output: &mut W) -> std::io::Result<()>
    where
        W: Write,
    {
        let mut writer = zstd::stream::Encoder::new(output, 0)?;
        writer.write_all(input)?;
        writer.flush()?;
        Ok(())
    }

    fn decompress<W>(&self, input: &[u8], output: &mut W) -> std::io::Result<()>
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

/// SslConnectorBuilderExt trait for `SslConnectorBuilder`.
pub trait SslConnectorBuilderExt {
    /// Configure the CertStore for the given `SslConnectorBuilder`.
    fn set_cert_store_from_iter<I: IntoIterator<Item = T>, T: AsRef<[u8]>>(
        self,
        store: I,
    ) -> Result<SslConnectorBuilder, ErrorStack>;

    /// Configure the certificate verification for the given `SslConnectorBuilder`.
    fn set_cert_verification(self, enable: bool) -> Result<SslConnectorBuilder, ErrorStack>;

    /// Configure the certificate compression algorithm for the given `SslConnectorBuilder`.
    fn add_certificate_compression_algorithms(
        self,
        algs: Option<&[CertificateCompressionAlgorithm]>,
    ) -> Result<SslConnectorBuilder, ErrorStack>;
}

impl SslConnectorBuilderExt for SslConnectorBuilder {
    #[inline]
    fn set_cert_store_from_iter<I: IntoIterator<Item = T>, T: AsRef<[u8]>>(
        mut self,
        store: I,
    ) -> Result<SslConnectorBuilder, ErrorStack> {
        let mut cert_store = X509StoreBuilder::new()?;
        store
            .into_iter()
            .flat_map(|c| X509::from_der(AsRef::<[u8]>::as_ref(&c)))
            .for_each(|x509| cert_store.add_cert(x509).unwrap());
        self.set_cert_store_builder(cert_store);
        Ok(self)
    }

    #[inline]
    fn set_cert_verification(mut self, enable: bool) -> Result<SslConnectorBuilder, ErrorStack> {
        if enable {
            self.set_verify(SslVerifyMode::PEER);
        } else {
            self.set_verify(SslVerifyMode::NONE);
        }

        Ok(self)
    }

    #[inline]
    fn add_certificate_compression_algorithms(
        mut self,
        algs: Option<&[CertificateCompressionAlgorithm]>,
    ) -> Result<SslConnectorBuilder, ErrorStack> {
        if let Some(algs) = algs {
            for algorithm in algs.iter() {
                if algorithm == &CertificateCompressionAlgorithm::ZLIB {
                    self.add_certificate_compression_algorithm(
                        ZlibCertificateCompressor::default(),
                    )?;
                }

                if algorithm == &CertificateCompressionAlgorithm::BROTLI {
                    self.add_certificate_compression_algorithm(
                        BrotliCertificateCompressor::default(),
                    )?;
                }

                if algorithm == &CertificateCompressionAlgorithm::ZSTD {
                    self.add_certificate_compression_algorithm(
                        ZstdCertificateCompressor::default(),
                    )?;
                }
            }
        }

        Ok(self)
    }
}

// From https://github.com/0x676e67/wreq/blob/86ee4e3343466f0284837d4bec6429f28620fc1a/src/tls/mod.rs#L59

/// A TLS ALPN protocol.
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct AlpnProtocol(&'static [u8]);

impl AlpnProtocol {
    /// Prefer HTTP/1.1
    pub const HTTP1: AlpnProtocol = AlpnProtocol(b"http/1.1");

    /// Prefer HTTP/2
    pub const HTTP2: AlpnProtocol = AlpnProtocol(b"h2");

    /// Create a new [`AlpnProtocol`] from a static byte slice.
    #[inline]
    pub const fn new(value: &'static [u8]) -> Self {
        AlpnProtocol(value)
    }

    #[inline]
    pub fn encode(self) -> Bytes {
        Self::encode_sequence(std::iter::once(&self))
    }

    pub fn encode_sequence<'a, I>(items: I) -> Bytes
    where
        I: IntoIterator<Item = &'a AlpnProtocol>,
    {
        let mut buf = BytesMut::new();
        for item in items {
            buf.put_u8(item.0.len() as u8);
            buf.extend_from_slice(item.0);
        }
        buf.freeze()
    }
}

/// Application-layer protocol settings for HTTP/1.1 and HTTP/2.
#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct AlpsProtocol(&'static [u8]);

impl AlpsProtocol {
    /// Prefer HTTP/1.1
    pub const HTTP1: AlpsProtocol = AlpsProtocol(b"http/1.1");

    /// Prefer HTTP/2
    pub const HTTP2: AlpsProtocol = AlpsProtocol(b"h2");
}
