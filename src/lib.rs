use boring::{
    error::ErrorStack,
    ssl::{
        CertificateCompressionAlgorithm, CertificateCompressor, SslConnectorBuilder, SslCurve,
        SslVerifyMode, SslVersion,
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

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct Cipher(&'static str);

impl Cipher {
    // TLS 1.3 cipher suites
    pub const TLS_AES_128_GCM_SHA256: Cipher = Cipher("TLS_AES_128_GCM_SHA256");
    pub const TLS_AES_256_CCM_8_SHA256: Cipher = Cipher("TLS_AES_256_CCM_8_SHA256");
    pub const TLS_AES_256_GCM_SHA384: Cipher = Cipher("TLS_AES_256_GCM_SHA384");
    pub const TLS_CHACHA20_POLY1305_SHA256: Cipher = Cipher("TLS_CHACHA20_POLY1305_SHA256");

    // ECDHE + ECDSA
    pub const TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA: Cipher =
        Cipher("TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA");
    pub const TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA: Cipher =
        Cipher("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA");
    pub const TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256: Cipher =
        Cipher("TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256");
    pub const TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: Cipher =
        Cipher("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256");
    pub const TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA: Cipher =
        Cipher("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA");
    pub const TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384: Cipher =
        Cipher("TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384");
    pub const TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: Cipher =
        Cipher("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384");
    pub const TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: Cipher =
        Cipher("TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256");

    // ECDHE + RSA
    pub const TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA: Cipher =
        Cipher("TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA");
    pub const TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA: Cipher =
        Cipher("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA");
    pub const TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256: Cipher =
        Cipher("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256");
    pub const TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256: Cipher =
        Cipher("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256");
    pub const TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA: Cipher =
        Cipher("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA");
    pub const TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384: Cipher =
        Cipher("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384");
    pub const TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384: Cipher =
        Cipher("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384");
    pub const TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256: Cipher =
        Cipher("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256");

    // RSA (no PFS)
    pub const TLS_RSA_WITH_3DES_EDE_CBC_SHA: Cipher = Cipher("TLS_RSA_WITH_3DES_EDE_CBC_SHA");
    pub const TLS_RSA_WITH_AES_128_CBC_SHA: Cipher = Cipher("TLS_RSA_WITH_AES_128_CBC_SHA");
    pub const TLS_RSA_WITH_AES_128_CBC_SHA256: Cipher = Cipher("TLS_RSA_WITH_AES_128_CBC_SHA256");
    pub const TLS_RSA_WITH_AES_128_GCM_SHA256: Cipher = Cipher("TLS_RSA_WITH_AES_128_GCM_SHA256");
    pub const TLS_RSA_WITH_AES_256_CBC_SHA: Cipher = Cipher("TLS_RSA_WITH_AES_256_CBC_SHA");
    pub const TLS_RSA_WITH_AES_256_CBC_SHA256: Cipher = Cipher("TLS_RSA_WITH_AES_256_CBC_SHA256");
    pub const TLS_RSA_WITH_AES_256_GCM_SHA384: Cipher = Cipher("TLS_RSA_WITH_AES_256_GCM_SHA384");

    #[inline]
    pub const fn as_str(&self) -> &'static str {
        self.0
    }
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct SignatureAlgorithm(&'static str);

impl SignatureAlgorithm {
    // RSA PKCS#1
    pub const RSA_PKCS1_SHA1: SignatureAlgorithm = SignatureAlgorithm("rsa_pkcs1_sha1");
    pub const RSA_PKCS1_SHA256: SignatureAlgorithm = SignatureAlgorithm("rsa_pkcs1_sha256");
    pub const RSA_PKCS1_SHA384: SignatureAlgorithm = SignatureAlgorithm("rsa_pkcs1_sha384");
    pub const RSA_PKCS1_SHA512: SignatureAlgorithm = SignatureAlgorithm("rsa_pkcs1_sha512");
    pub const RSA_PKCS1_MD5_SHA1: SignatureAlgorithm = SignatureAlgorithm("rsa_pkcs1_md5_sha1");

    // ECDSA generic & with explicit curves
    pub const ECDSA_SHA1: SignatureAlgorithm = SignatureAlgorithm("ecdsa_sha1");
    pub const ECDSA_SECP256R1_SHA256: SignatureAlgorithm =
        SignatureAlgorithm("ecdsa_secp256r1_sha256");
    pub const ECDSA_SECP384R1_SHA384: SignatureAlgorithm =
        SignatureAlgorithm("ecdsa_secp384r1_sha384");
    pub const ECDSA_SECP521R1_SHA512: SignatureAlgorithm =
        SignatureAlgorithm("ecdsa_secp521r1_sha512");

    // RSA-PSS
    pub const RSA_PSS_RSAE_SHA256: SignatureAlgorithm = SignatureAlgorithm("rsa_pss_rsae_sha256");
    pub const RSA_PSS_RSAE_SHA384: SignatureAlgorithm = SignatureAlgorithm("rsa_pss_rsae_sha384");
    pub const RSA_PSS_RSAE_SHA512: SignatureAlgorithm = SignatureAlgorithm("rsa_pss_rsae_sha512");

    // EdDSA
    pub const ED25519: SignatureAlgorithm = SignatureAlgorithm("ed25519");

    #[inline]
    pub const fn as_str(&self) -> &str {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Curve(SslCurve);

impl Curve {
    // NIST Prime Curves
    pub const SECP224R1: Curve = Curve(SslCurve::SECP224R1);
    pub const SECP256R1: Curve = Curve(SslCurve::SECP256R1);
    pub const SECP384R1: Curve = Curve(SslCurve::SECP384R1);
    pub const SECP521R1: Curve = Curve(SslCurve::SECP521R1);

    // Montgomery / Edwards / Post-Quantum Hybrid Curves
    pub const X25519: Curve = Curve(SslCurve::X25519);
    pub const X25519_KYBER768_DRAFT00: Curve = Curve(SslCurve::X25519_KYBER768_DRAFT00);
    pub const X25519_KYBER768_DRAFT00_OLD: Curve = Curve(SslCurve::X25519_KYBER768_DRAFT00_OLD);
    pub const X25519_KYBER512_DRAFT00: Curve = Curve(SslCurve::X25519_KYBER512_DRAFT00);
    pub const P256_KYBER768_DRAFT00: Curve = Curve(SslCurve::P256_KYBER768_DRAFT00);
    pub const X25519_MLKEM768: Curve = Curve(SslCurve::X25519_MLKEM768);

    // Finite Field DH groups
    pub const FFDHE2048: Curve = Curve(SslCurve::FFDHE2048);
    pub const FFDHE3072: Curve = Curve(SslCurve::FFDHE3072);

    /// Returns the underlying SslCurve reference.
    #[inline]
    pub const fn as_ssl_curve(&self) -> SslCurve {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CertCompressionAlgorithm(CertificateCompressionAlgorithm);

impl CertCompressionAlgorithm {
    pub const BROTLI: CertCompressionAlgorithm =
        CertCompressionAlgorithm(CertificateCompressionAlgorithm::BROTLI);

    pub const ZLIB: CertCompressionAlgorithm =
        CertCompressionAlgorithm(CertificateCompressionAlgorithm::ZLIB);

    pub const ZSTD: CertCompressionAlgorithm =
        CertCompressionAlgorithm(CertificateCompressionAlgorithm::ZSTD);

    #[inline]
    pub const fn as_certificate_compression_algorithm(&self) -> CertificateCompressionAlgorithm {
        self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TlsVersion(SslVersion);

impl TlsVersion {
    pub const SSL3: TlsVersion = TlsVersion(SslVersion::SSL3);

    pub const TLS1: TlsVersion = TlsVersion(SslVersion::TLS1);

    pub const TLS1_1: TlsVersion = TlsVersion(SslVersion::TLS1_1);

    pub const TLS1_2: TlsVersion = TlsVersion(SslVersion::TLS1_2);

    pub const TLS1_3: TlsVersion = TlsVersion(SslVersion::TLS1_3);

    #[inline]
    pub const fn as_ssl_version(&self) -> SslVersion {
        self.0
    }
}
