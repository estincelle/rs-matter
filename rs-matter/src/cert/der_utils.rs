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

//! DER encoding utilities for ECDSA signatures and certificate operations.
//!
//! This module provides utilities for working with DER-encoded ECDSA signatures
//! on the P-256 (secp256r1) curve, including conversion between DER format and
//! raw (r || s) format used by Matter for signature verification.

use crate::crypto::{PKC_CANON_SECRET_KEY_LEN, PKC_SIGNATURE_LEN};
use crate::error::{Error, ErrorCode};
use der::asn1::AnyRef;
use der::{Decode, Header, Reader, SliceReader, Tag, Tagged};

/// P-256 field element length in bytes (ECDSA signature r and s values).
const P256_FE_LEN: usize = PKC_CANON_SECRET_KEY_LEN;

/// Raw ECDSA signature length: r (32 bytes) || s (32 bytes).
const RAW_SIGNATURE_LEN: usize = PKC_SIGNATURE_LEN;

/// Convert a DER-encoded ECDSA signature to raw (r || s) format.
///
/// DER format: `SEQUENCE { INTEGER r, INTEGER s }`
/// Raw format: `r[32] || s[32]` (each padded/trimmed to exactly 32 bytes)
///
/// DER INTEGERs may have a leading 0x00 byte for positive representation,
/// which must be stripped. They may also be shorter than 32 bytes.
///
/// # Arguments
///
/// * `der` - DER-encoded ECDSA signature bytes
///
/// # Returns
///
/// A 64-byte array containing the raw signature (r || s), or an error if
/// the DER encoding is invalid or the signature is not P-256.
///
/// # Errors
///
/// Returns `ErrorCode::Invalid` if:
/// - The DER structure is malformed
/// - The signature components are not the expected size for P-256
/// - The encoding does not follow the expected SEQUENCE { INTEGER, INTEGER } format
pub fn ecdsa_der_to_raw(der: &[u8]) -> Result<[u8; RAW_SIGNATURE_LEN], Error> {
    let mut reader = SliceReader::new(der).map_err(|_| Error::from(ErrorCode::Invalid))?;

    // Read the SEQUENCE header
    let seq_header = Header::decode(&mut reader).map_err(|_| Error::from(ErrorCode::Invalid))?;

    if seq_header.tag != Tag::Sequence {
        return Err(ErrorCode::Invalid.into());
    }

    // Read INTEGER r
    let r_any = AnyRef::decode(&mut reader).map_err(|_| Error::from(ErrorCode::Invalid))?;
    if r_any.tag() != Tag::Integer {
        return Err(ErrorCode::Invalid.into());
    }

    // Read INTEGER s
    let s_any = AnyRef::decode(&mut reader).map_err(|_| Error::from(ErrorCode::Invalid))?;
    if s_any.tag() != Tag::Integer {
        return Err(ErrorCode::Invalid.into());
    }

    // Convert to fixed-length raw format
    let mut raw = [0u8; RAW_SIGNATURE_LEN];
    copy_integer_to_fixed(&mut raw[..P256_FE_LEN], r_any.value())?;
    copy_integer_to_fixed(&mut raw[P256_FE_LEN..], s_any.value())?;

    Ok(raw)
}

/// Copy a DER INTEGER value into a fixed-length buffer, right-aligned.
///
/// Strips leading zero bytes (DER positive sign padding) and pads with
/// zeros on the left to fill the target buffer.
///
/// # Arguments
///
/// * `target` - The destination buffer to write the integer value into
/// * `integer` - The DER INTEGER value bytes (without tag/length header)
///
/// # Returns
///
/// `Ok(())` if the integer was successfully copied, or an error if the
/// integer value is too large for the target buffer.
///
/// # Errors
///
/// Returns `ErrorCode::Invalid` if the integer value (after stripping leading
/// zeros) is larger than the target buffer.
pub fn copy_integer_to_fixed(target: &mut [u8], integer: &[u8]) -> Result<(), Error> {
    // Strip leading zeros
    let mut src = integer;
    while src.len() > 1 && src[0] == 0 {
        src = &src[1..];
    }

    if src.len() > target.len() {
        return Err(ErrorCode::Invalid.into());
    }

    // Right-align: pad with zeros on the left
    let offset = target.len() - src.len();
    target[..offset].fill(0);
    target[offset..].copy_from_slice(src);

    Ok(())
}

/// Open a DER-encoded X.509 certificate and return a reader positioned
/// after the outer SEQUENCE header.
fn open_cert_sequence(cert_der: &[u8]) -> Result<SliceReader<'_>, Error> {
    let mut reader = SliceReader::new(cert_der).map_err(|_| Error::from(ErrorCode::Invalid))?;
    let outer_header = Header::decode(&mut reader).map_err(|_| Error::from(ErrorCode::Invalid))?;
    if outer_header.tag != Tag::Sequence {
        return Err(ErrorCode::Invalid.into());
    }
    Ok(reader)
}

/// Extract the raw TBS (To-Be-Signed) certificate bytes from a DER-encoded X.509 certificate.
///
/// Certificate ::= SEQUENCE { tbsCertificate SEQUENCE {...}, signatureAlgorithm, signatureValue }
///
/// Returns the complete TBS SEQUENCE including its tag and length header.
/// This is the data that the issuer's signature covers.
pub fn tbs_certificate_raw(cert_der: &[u8]) -> Result<&[u8], Error> {
    let mut reader = open_cert_sequence(cert_der)?;

    let before_tbs: usize = reader
        .position()
        .try_into()
        .map_err(|_| Error::from(ErrorCode::Invalid))?;

    // Skip TBS SEQUENCE (reads its header + content)
    AnyRef::decode(&mut reader).map_err(|_| Error::from(ErrorCode::Invalid))?;

    let after_tbs: usize = reader
        .position()
        .try_into()
        .map_err(|_| Error::from(ErrorCode::Invalid))?;

    Ok(&cert_der[before_tbs..after_tbs])
}

/// Extract the signature from a DER-encoded X.509 certificate as raw r||s (64 bytes).
///
/// Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue BIT STRING }
///
/// The BIT STRING contains a DER-encoded ECDSA signature which is converted to raw format.
pub fn cert_signature_raw(cert_der: &[u8]) -> Result<[u8; RAW_SIGNATURE_LEN], Error> {
    let mut reader = open_cert_sequence(cert_der)?;

    // Skip tbsCertificate + signatureAlgorithm
    AnyRef::decode(&mut reader).map_err(|_| Error::from(ErrorCode::Invalid))?;
    AnyRef::decode(&mut reader).map_err(|_| Error::from(ErrorCode::Invalid))?;

    // Read signatureValue BIT STRING
    let sig_any = AnyRef::decode(&mut reader).map_err(|_| Error::from(ErrorCode::Invalid))?;
    if sig_any.tag() != Tag::BitString {
        return Err(ErrorCode::Invalid.into());
    }

    let bs_value = sig_any.value();
    // BIT STRING has unused-bits prefix byte (must be 0 for byte-aligned signatures)
    if bs_value.is_empty() || bs_value[0] != 0x00 {
        return Err(ErrorCode::Invalid.into());
    }

    // The remaining bytes are the DER-encoded ECDSA signature
    ecdsa_der_to_raw(&bs_value[1..])
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_ecdsa_der_to_raw_basic() {
        // Simple case: both r and s are exactly 32 bytes (no leading zero)
        let mut der = [0u8; 70];
        let r = [0x01u8; 32];
        let s = [0x02u8; 32];

        // Build DER: SEQUENCE { INTEGER r, INTEGER s }
        // Each INTEGER: 0x02, len, data
        // SEQUENCE length = 2 + 32 + 2 + 32 = 68
        der[0] = 0x30; // SEQUENCE
        der[1] = 68;
        der[2] = 0x02; // INTEGER r
        der[3] = 32;
        der[4..36].copy_from_slice(&r);
        der[36] = 0x02; // INTEGER s
        der[37] = 32;
        der[38..70].copy_from_slice(&s);

        let raw = unwrap!(ecdsa_der_to_raw(&der[..70]));
        assert_eq!(&raw[..32], &r);
        assert_eq!(&raw[32..], &s);
    }

    #[test]
    fn test_ecdsa_der_to_raw_with_leading_zeros() {
        // Case: r has a leading 0x00 (33 bytes DER -> 32 bytes raw)
        let mut der = [0u8; 72];
        let r = [0x80u8; 32]; // High bit set, so DER prepends 0x00
        let s = [0x01u8; 32];

        der[0] = 0x30; // SEQUENCE
        der[1] = 69; // 2+32+1 + 2+32 = 69 = 70
        der[2] = 0x02; // INTEGER r
        der[3] = 33;
        der[4] = 0x00; // leading zero
        der[5..37].copy_from_slice(&r);
        der[37] = 0x02; // INTEGER s
        der[38] = 32;
        der[39..71].copy_from_slice(&s);

        let raw = unwrap!(ecdsa_der_to_raw(&der[..71]));
        assert_eq!(&raw[..32], &r);
        assert_eq!(&raw[32..], &s);
    }

    #[test]
    fn test_ecdsa_der_to_raw_short_integer() {
        // Case: s is short (e.g., 31 bytes, needs left-padding with zero)
        let mut der = [0u8; 70];
        let r = [0x42u8; 32];
        let s_short = [0x05u8; 31]; // 31 bytes

        der[0] = 0x30;
        der[1] = 67; // 2+32 + 2+31
        der[2] = 0x02;
        der[3] = 32;
        der[4..36].copy_from_slice(&r);
        der[36] = 0x02;
        der[37] = 31;
        der[38..69].copy_from_slice(&s_short);

        let raw = unwrap!(ecdsa_der_to_raw(&der[..69]));
        assert_eq!(&raw[..32], &r);
        assert_eq!(raw[32], 0x00); // left-padded zero
        assert_eq!(&raw[33..], &s_short);
    }

    #[test]
    fn test_copy_integer_to_fixed_strips_leading_zeros() {
        let mut target = [0u8; 4];
        let integer = [0x00, 0x00, 0x12, 0x34];

        unwrap!(copy_integer_to_fixed(&mut target, &integer));
        assert_eq!(target, [0x00, 0x00, 0x12, 0x34]);
    }

    #[test]
    fn test_copy_integer_to_fixed_pads_short_values() {
        let mut target = [0u8; 4];
        let integer = [0x12, 0x34];

        unwrap!(copy_integer_to_fixed(&mut target, &integer));
        assert_eq!(target, [0x00, 0x00, 0x12, 0x34]);
    }

    #[test]
    fn test_copy_integer_to_fixed_error_on_overflow() {
        let mut target = [0u8; 4];
        let integer = [0x01, 0x02, 0x03, 0x04, 0x05]; // Too long

        let result = copy_integer_to_fixed(&mut target, &integer);
        assert!(result.is_err());
    }

    // Test DAC cert for tbs/signature extraction tests
    const TEST_DAC_CERT: &[u8] = include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/credentials/test-attestation/Chip-Test-DAC-FFF1-8000-0000-Cert.der"
    ));

    #[test]
    fn test_tbs_certificate_raw() {
        let tbs = tbs_certificate_raw(TEST_DAC_CERT).unwrap();
        // TBS must start with SEQUENCE tag
        assert_eq!(tbs[0], 0x30);
        // TBS is a strict subset of the full cert (excludes signatureAlgorithm + signatureValue)
        assert!(tbs.len() < TEST_DAC_CERT.len());
        // TBS bytes must appear contiguously within the cert
        let offset = TEST_DAC_CERT.windows(tbs.len()).position(|w| w == tbs);
        assert!(offset.is_some());
    }

    #[test]
    fn test_cert_signature_raw() {
        // Expected raw r||s extracted from test DAC cert via openssl
        const EXPECTED_SIG: [u8; RAW_SIGNATURE_LEN] = [
            0x05, 0x6e, 0xe3, 0x30, 0x5c, 0x1b, 0x2e, 0x80, 0xe2, 0x26, 0x0b, 0x84, 0xd4, 0x52,
            0x8e, 0x52, 0xda, 0xef, 0x0b, 0x80, 0x1b, 0xd4, 0x92, 0xe8, 0x3e, 0xf7, 0x86, 0x4f,
            0xc5, 0x12, 0x8c, 0x4c, 0xe9, 0x87, 0xf4, 0x1b, 0xf8, 0xfa, 0xbe, 0x48, 0x10, 0x55,
            0xdb, 0x9d, 0xda, 0xf8, 0xa7, 0x75, 0x55, 0x24, 0x2c, 0x38, 0xb5, 0xcd, 0x8e, 0xbe,
            0xd6, 0x73, 0x06, 0x8d, 0x75, 0x52, 0xb2, 0xfd,
        ];
        let sig = cert_signature_raw(TEST_DAC_CERT).unwrap();
        assert_eq!(sig, EXPECTED_SIG);
    }
}
