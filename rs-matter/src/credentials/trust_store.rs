/*
 *
 *    Copyright (c) 2020-2022 Project CHIP Authors
 *
 *    Licensed under the Apache License, Version 2.0 (the "License");
 *    you may not use this file except in compliance with the License.
 *    You may obtain a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS,
 *    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *    See the License for the specific language governing permissions and
 *    limitations under the License.
 */

//! PAA (Product Attestation Authority) trust store for device attestation.
//!
//! Provides the [`AttestationTrustStore`] trait for PAA certificate lookup by SKID,
//! and [`ArrayAttestationTrustStore`] — a unified implementation backed by a fixed-capacity
//! `heapless::Vec`. Certificates can be ingested from DER slices or from a directory of
//! `.der` files.

use crate::cert::x509::X509CertRef;
use crate::error::{Error, ErrorCode};

const SKID_LEN: usize = 20;

/// Maximum length of a DER-encoded PAA certificate.
/// Matches C++ SDK `kMaxDERCertLength` (CHIPCert.h).
pub const MAX_PAA_CERT_DER_LEN: usize = 600;

/// Trait for looking up PAA certificates by Subject Key Identifier (SKID).
///
/// Used during device commissioning to find the PAA that issued a device's PAI,
/// by matching the PAI's Authority Key Identifier (AKID) against PAA SKIDs.
pub trait AttestationTrustStore {
    /// Look up a PAA certificate by its Subject Key Identifier.
    ///
    /// Returns the DER-encoded PAA certificate, or `ErrorCode::NotFound`
    /// if no PAA with the given SKID is present in the store.
    fn get_paa(&self, skid: &[u8]) -> Result<&[u8], Error>;
}

/// A single PAA certificate entry: pre-extracted SKID + DER bytes.
struct PaaCertEntry {
    skid: [u8; SKID_LEN],
    der: [u8; MAX_PAA_CERT_DER_LEN],
    der_len: usize,
}

/// PAA trust store backed by a fixed-capacity array (`heapless::Vec`).
///
/// Certificates are ingested via [`from_certs`](Self::from_certs) (DER slices) or
/// [`from_directory`](Self::from_directory) (filesystem, `std` only). SKIDs are
/// extracted once at construction time.
///
/// The const generic `N` determines the maximum number of PAA certificates.
/// Each entry is ~628 bytes (20 SKID + 600 DER + 8 len).
/// Typical values: `N = 2` for testing, `N = 128..256` for production (~80–160 KB).
///
/// # Example (no_std)
///
/// ```ignore
/// use rs_matter::credentials::trust_store::ArrayAttestationTrustStore;
///
/// let store = ArrayAttestationTrustStore::<2>::from_certs(&[
///     &MY_PAA_CERT_1_DER,
///     &MY_PAA_CERT_2_DER,
/// ]).unwrap();
/// ```
///
/// # Example (std only)
///
/// ```ignore
/// use rs_matter::credentials::trust_store::ArrayAttestationTrustStore;
///
/// let store = ArrayAttestationTrustStore::<256>::from_directory(
///     std::path::Path::new("/etc/matter/paa-certs")
/// ).unwrap();
/// ```
pub struct ArrayAttestationTrustStore<const N: usize> {
    certs: heapless::Vec<PaaCertEntry, N>,
}

impl<const N: usize> ArrayAttestationTrustStore<N> {
    /// Create a trust store from DER-encoded PAA certificate slices.
    ///
    /// Extracts the SKID from each certificate and copies the DER bytes
    /// into internal fixed-size buffers.
    ///
    /// Returns `ErrorCode::InvalidData` if a certificate exceeds [`MAX_PAA_CERT_DER_LEN`],
    /// is malformed, or has no SKID.
    /// Returns `ErrorCode::NoSpace` if the number of certificates exceeds capacity `N`.
    pub fn from_certs(certs: &[&[u8]]) -> Result<Self, Error> {
        let mut store = Self {
            certs: heapless::Vec::new(),
        };

        for cert in certs {
            store.push_cert(cert)?;
        }

        Ok(store)
    }

    /// Load PAA certificates from `.der` files in the given directory.
    ///
    /// Skips files that:
    /// - Don't have a `.der` extension
    /// - Are larger than [`MAX_PAA_CERT_DER_LEN`] bytes
    /// - Fail to parse (invalid DER or missing SKID extension)
    ///
    /// Returns `ErrorCode::NoSpace` if the directory contains more valid
    /// certificates than capacity `N`.
    #[cfg(feature = "std")]
    pub fn from_directory(dir: &std::path::Path) -> Result<Self, Error> {
        use core::fmt::Write;
        use std::io::Read;

        let mut store = Self {
            certs: heapless::Vec::new(),
        };

        let entries = std::fs::read_dir(dir).map_err(|_| ErrorCode::StdIoError)?;

        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };

            let path = entry.path();

            // Only process .der files
            match path.extension().and_then(|e| e.to_str()) {
                Some("der") => {}
                _ => continue,
            }

            let file_name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("<unknown>");

            // Check file size
            let metadata = match std::fs::metadata(&path) {
                Ok(m) => m,
                Err(e) => {
                    let mut msg = heapless::String::<64>::new();
                    let _ = write!(&mut msg, "{}", e);
                    warn!(
                        "Skipping PAA cert {}: cannot read metadata: {}",
                        file_name,
                        msg.as_str()
                    );
                    continue;
                }
            };

            if metadata.len() > MAX_PAA_CERT_DER_LEN as u64 {
                warn!(
                    "Skipping PAA cert {}: file too large ({} bytes, max {})",
                    file_name,
                    metadata.len(),
                    MAX_PAA_CERT_DER_LEN,
                );
                continue;
            }

            // Read file contents into fixed-size buffer
            let size = metadata.len() as usize;
            let mut der = [0u8; MAX_PAA_CERT_DER_LEN];

            let mut file = match std::fs::File::open(&path) {
                Ok(f) => f,
                Err(e) => {
                    let mut msg = heapless::String::<64>::new();
                    let _ = write!(&mut msg, "{}", e);
                    warn!(
                        "Skipping PAA cert {}: cannot open: {}",
                        file_name,
                        msg.as_str()
                    );
                    continue;
                }
            };

            if let Err(e) = file.read_exact(&mut der[..size]) {
                let mut msg = heapless::String::<64>::new();
                let _ = write!(&mut msg, "{}", e);
                warn!(
                    "Skipping PAA cert {}: read error: {}",
                    file_name,
                    msg.as_str()
                );
                continue;
            }

            match store.push_cert(&der[..size]) {
                Ok(()) => {}
                Err(e) if e.code() == ErrorCode::NoSpace => return Err(e),
                Err(_) => {
                    warn!(
                        "Skipping PAA cert {}: invalid certificate or missing SKID",
                        file_name,
                    );
                }
            }
        }

        Ok(store)
    }

    /// Number of PAA certificates in the store.
    pub fn paa_count(&self) -> usize {
        self.certs.len()
    }

    fn push_cert(&mut self, cert: &[u8]) -> Result<(), Error> {
        if cert.len() > MAX_PAA_CERT_DER_LEN {
            return Err(ErrorCode::InvalidData.into());
        }

        let cert_ref = X509CertRef::new(cert)?;
        let skid_slice = cert_ref.subject_key_id()?;
        if skid_slice.len() != SKID_LEN {
            return Err(ErrorCode::InvalidData.into());
        }
        let mut skid = [0u8; SKID_LEN];
        skid.copy_from_slice(skid_slice);

        let mut der = [0u8; MAX_PAA_CERT_DER_LEN];
        der[..cert.len()].copy_from_slice(cert);

        self.certs
            .push(PaaCertEntry {
                skid,
                der,
                der_len: cert.len(),
            })
            .map_err(|_| ErrorCode::NoSpace)?;

        Ok(())
    }
}

impl<const N: usize> AttestationTrustStore for ArrayAttestationTrustStore<N> {
    fn get_paa(&self, skid: &[u8]) -> Result<&[u8], Error> {
        for entry in &self.certs {
            if entry.skid.as_slice() == skid {
                return Ok(&entry.der[..entry.der_len]);
            }
        }

        Err(ErrorCode::NotFound.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::test_paa::*;
    use crate::error::ErrorCode;

    // --- ArrayAttestationTrustStore tests ---

    #[test]
    fn store_finds_known_skid() {
        let store = ArrayAttestationTrustStore::<2>::from_certs(&[TEST_PAA_FFF1_CERT]).unwrap();
        assert_eq!(store.paa_count(), 1);
        let result = store.get_paa(&TEST_PAA_FFF1_SKID);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), TEST_PAA_FFF1_CERT);
    }

    #[test]
    fn store_not_found_unknown_skid() {
        let store = ArrayAttestationTrustStore::<2>::from_certs(&[TEST_PAA_FFF1_CERT]).unwrap();
        assert_eq!(store.paa_count(), 1);
        let unknown_skid = [0xFF; 20];
        let result = store.get_paa(&unknown_skid);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), ErrorCode::NotFound);
    }

    #[test]
    fn store_multiple_certs() {
        let store =
            ArrayAttestationTrustStore::<2>::from_certs(&[TEST_PAA_FFF1_CERT, TEST_PAA_NOVID_CERT])
                .unwrap();
        assert_eq!(store.paa_count(), 2);

        // Find FFF1
        let fff1 = store.get_paa(&TEST_PAA_FFF1_SKID).unwrap();
        assert_eq!(fff1, TEST_PAA_FFF1_CERT);

        // Find NoVID
        let novid = store.get_paa(&TEST_PAA_NOVID_SKID).unwrap();
        assert_eq!(novid, TEST_PAA_NOVID_CERT);
    }

    #[test]
    fn store_empty() {
        let store = ArrayAttestationTrustStore::<2>::from_certs(&[]).unwrap();
        assert_eq!(store.paa_count(), 0);
        let result = store.get_paa(&TEST_PAA_FFF1_SKID);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().code(), ErrorCode::NotFound);
    }

    #[test]
    fn store_capacity_exceeded() {
        let result =
            ArrayAttestationTrustStore::<1>::from_certs(&[TEST_PAA_FFF1_CERT, TEST_PAA_NOVID_CERT]);
        match result {
            Err(e) => assert_eq!(e.code(), ErrorCode::NoSpace),
            Ok(_) => panic!("expected NoSpace error"),
        }
    }

    #[test]
    fn store_cert_too_large() {
        let oversized = [0u8; MAX_PAA_CERT_DER_LEN + 1];
        let result = ArrayAttestationTrustStore::<2>::from_certs(&[&oversized]);
        match result {
            Err(e) => assert_eq!(e.code(), ErrorCode::InvalidData),
            Ok(_) => panic!("expected InvalidData error"),
        }
    }

    // --- test_paa_store convenience function tests ---

    #[test]
    fn test_paa_store_has_fff1() {
        let store = test_paa_store();
        let cert = store.get_paa(&TEST_PAA_FFF1_SKID).unwrap();
        assert_eq!(cert, TEST_PAA_FFF1_CERT);
    }

    #[test]
    fn test_paa_store_has_novid() {
        let store = test_paa_store();
        let cert = store.get_paa(&TEST_PAA_NOVID_SKID).unwrap();
        assert_eq!(cert, TEST_PAA_NOVID_CERT);
    }

    // --- from_directory tests ---

    #[cfg(feature = "std")]
    const TEST_DATA_DIR: &str = "src/credentials/test_data";

    /// RAII guard that removes its directory on drop, even if a test panics.
    #[cfg(feature = "std")]
    struct TempDir(std::path::PathBuf);

    #[cfg(feature = "std")]
    impl TempDir {
        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }

    #[cfg(feature = "std")]
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Create a temp directory pre-populated with the contents of `test_data/`.
    #[cfg(feature = "std")]
    fn create_test_dir(test_name: &str) -> TempDir {
        let path =
            std::env::temp_dir().join(format!("paa_test_{}_{}", std::process::id(), test_name));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();

        for entry in std::fs::read_dir(TEST_DATA_DIR).unwrap() {
            let entry = entry.unwrap();
            std::fs::copy(entry.path(), path.join(entry.file_name())).unwrap();
        }

        TempDir(path)
    }

    #[cfg(feature = "std")]
    fn write_file(dir: &std::path::Path, name: &str, data: &[u8]) {
        use std::io::Write;
        let path = dir.join(name);
        let mut f = std::fs::File::create(path).unwrap();
        f.write_all(data).unwrap();
    }

    #[cfg(feature = "std")]
    #[test]
    fn from_directory_loads() {
        let dir = create_test_dir("loads");
        write_file(dir.path(), "readme.txt", b"not a cert");

        let store = ArrayAttestationTrustStore::<8>::from_directory(dir.path()).unwrap();
        assert_eq!(store.paa_count(), 2);
    }

    #[cfg(feature = "std")]
    #[test]
    fn from_directory_skips_invalid() {
        let dir = create_test_dir("skips");
        write_file(dir.path(), "garbage.der", &[0xDE, 0xAD, 0xBE, 0xEF]);
        write_file(dir.path(), "toobig.der", &[0u8; 700]);

        let store = ArrayAttestationTrustStore::<8>::from_directory(dir.path()).unwrap();
        assert_eq!(store.paa_count(), 2);
    }

    #[cfg(feature = "std")]
    #[test]
    fn from_directory_lookup() {
        let dir = create_test_dir("lookup");

        let store = ArrayAttestationTrustStore::<8>::from_directory(dir.path()).unwrap();

        let fff1 = store.get_paa(&TEST_PAA_FFF1_SKID).unwrap();
        assert_eq!(fff1, TEST_PAA_FFF1_CERT);

        let novid = store.get_paa(&TEST_PAA_NOVID_SKID).unwrap();
        assert_eq!(novid, TEST_PAA_NOVID_CERT);

        let unknown = store.get_paa(&[0xFF; 20]);
        assert!(unknown.is_err());
    }

    #[cfg(feature = "std")]
    #[test]
    fn from_directory_empty() {
        let path = std::env::temp_dir().join(format!("paa_test_{}_empty", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).unwrap();
        let dir = TempDir(path);

        let store = ArrayAttestationTrustStore::<8>::from_directory(dir.path()).unwrap();
        assert_eq!(store.paa_count(), 0);
        assert!(store.get_paa(&TEST_PAA_FFF1_SKID).is_err());
    }

    #[cfg(feature = "std")]
    #[test]
    fn from_directory_nonexistent() {
        let dir = std::env::temp_dir().join(format!(
            "paa_test_nonexistent_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        if dir.exists() {
            warn!(
                "nonexistent test dir unexpectedly exists: {}",
                dir.display()
            );
            let _ = std::fs::remove_dir_all(&dir);
        }
        assert!(ArrayAttestationTrustStore::<8>::from_directory(&dir).is_err());
    }
}
