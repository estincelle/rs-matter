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

//! Device Attestation Verification for Matter commissioning.
//!
//! Implements the attestation verification flow per Matter Spec Section 6.2.3.1
//! "Attestation Information Validation". Verifies the DAC → PAI → PAA certificate
//! chain, the attestation signature, and the Certification Declaration (CD).
//!
//! Reference: connectedhomeip `src/credentials/attestation_verifier/DefaultDeviceAttestationVerifier.cpp`

use crate::cert::x509::{CertType, DacCert, PaaCert, PaiCert, X509Cert};
use crate::credentials::cd::{CertificationElements, DeviceInfoForAttestation};
use crate::credentials::cd_keys::KEY_IDENTIFIER_LEN;
use crate::credentials::trust_store::{AttestationTrustStore, KeyId};
use crate::crypto::{
    CanonPkcPublicKeyRef, CanonPkcSignatureRef, Crypto, PublicKey, PKC_SIGNATURE_LEN,
};
use crate::error::{Error, ErrorCode};
use crate::tlv::TLVElement;
use crate::utils::epoch::Epoch;

/// Maximum size of attestation elements TLV payload.
/// Matter Spec, Section 11.18.4.1 "RESP_MAX Constant Type": 900 bytes.
const ATTESTATION_ELEMENTS_MAX_LEN: usize = 900;

/// Attestation challenge length.
/// Matter Spec, Section 11.18.4.7 "Attestation Information" step 2:
/// CRYPTO_SYMMETRIC_KEY_LENGTH_BYTES = 16.
const ATTESTATION_CHALLENGE_LEN: usize = 16;

/// Attestation nonce length.
/// Matter Spec, Section 11.18.6.1 "AttestationRequest Command": octstr constraint 32.
const ATTESTATION_NONCE_LEN: usize = 32;

/// TLV context tags for attestation elements (Matter Spec, Section 11.18.4.6 "Attestation Elements").
const TAG_CERTIFICATION_DECLARATION: u8 = 1;
const TAG_ATTESTATION_NONCE: u8 = 2;
const TAG_TIMESTAMP: u8 = 3;
const TAG_FIRMWARE_INFO: u8 = 4;

/// Parsed attestation elements from the device's AttestationResponse.
///
/// Matter Spec, Section 11.18.4.6 "Attestation Elements" — TLV structure:
/// - Context tag 1: certification_declaration (octet string)
/// - Context tag 2: attestation_nonce (octet string, 32 bytes)
/// - Context tag 3: timestamp (unsigned integer)
/// - Context tag 4: firmware_info (octet string, optional)
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct AttestationElements<'a> {
    pub certification_declaration: &'a [u8],
    pub attestation_nonce: &'a [u8],
    pub timestamp: u32,
    pub firmware_info: Option<&'a [u8]>,
}

impl<'a> AttestationElements<'a> {
    /// Decode attestation elements from a TLV-encoded byte slice.
    pub fn decode(data: &'a [u8]) -> Result<Self, Error> {
        let elem = TLVElement::new(data);
        let seq = elem
            .structure()
            .map_err(|_| ErrorCode::AttElementsMalformed)?;

        let certification_declaration = seq
            .ctx(TAG_CERTIFICATION_DECLARATION)
            .and_then(|e| e.octets())
            .map_err(|_| ErrorCode::AttElementsMalformed)?;

        let attestation_nonce = seq
            .ctx(TAG_ATTESTATION_NONCE)
            .and_then(|e| e.octets())
            .map_err(|_| ErrorCode::AttElementsMalformed)?;

        if attestation_nonce.len() != ATTESTATION_NONCE_LEN {
            return Err(ErrorCode::AttElementsMalformed.into());
        }

        let timestamp = seq
            .ctx(TAG_TIMESTAMP)
            .and_then(|e| e.u32())
            .map_err(|_| ErrorCode::AttElementsMalformed)?;

        let firmware_info = match seq.ctx(TAG_FIRMWARE_INFO) {
            Ok(e) => Some(e.octets().map_err(|_| ErrorCode::AttElementsMalformed)?),
            Err(e) if e.code() == ErrorCode::NotFound => None,
            Err(_) => return Err(ErrorCode::AttElementsMalformed.into()),
        };

        Ok(Self {
            certification_declaration,
            attestation_nonce,
            timestamp,
            firmware_info,
        })
    }
}

/// Input data for device attestation verification.
#[derive(Debug)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct AttestationInfo<'a> {
    /// Raw TLV attestation elements from the device's AttestationResponse.
    pub attestation_elements: &'a [u8],
    /// Attestation challenge from the PASE/CASE secure session (16 bytes).
    pub attestation_challenge: &'a [u8],
    /// Attestation signature from the device (raw r||s, 64 bytes).
    pub attestation_signature: &'a [u8],
    /// DER-encoded DAC certificate.
    pub dac_der: &'a [u8],
    /// DER-encoded PAI certificate.
    pub pai_der: &'a [u8],
    /// Vendor ID from BasicInformation cluster.
    pub vendor_id: u16,
    /// Product ID from BasicInformation cluster.
    pub product_id: u16,
}

/// Device Attestation Verifier.
///
/// Orchestrates the full attestation verification flow per Matter Spec, Section 6.2.3.1:
/// certificate chain validation, attestation signature verification, and
/// Certification Declaration verification/validation.
pub struct AttestationVerifier<'a, C: Crypto, T: AttestationTrustStore> {
    crypto: &'a C,
    trust_store: &'a T,
    epoch: Epoch,
    allow_test_cd_signing_key: bool,
}

impl<'a, C: Crypto, T: AttestationTrustStore> AttestationVerifier<'a, C, T> {
    pub fn new(
        crypto: &'a C,
        trust_store: &'a T,
        epoch: Epoch,
        allow_test_cd_signing_key: bool,
    ) -> Self {
        Self {
            crypto,
            trust_store,
            epoch,
            allow_test_cd_signing_key,
        }
    }

    /// Verify device attestation information.
    ///
    /// Follows the C++ SDK `DefaultDACVerifier::VerifyAttestationInformation` order:
    ///
    /// 1. Input validation
    /// 2. Parse DAC and PAI, extract VID/PID
    /// 3. DAC↔PAI VID/PID cross-validation
    /// 4. Verify attestation signature (DAC pubkey over elements || challenge)
    /// 5. Find PAA via PAI's AKID, validate PAA VID constraints
    /// 6. DAC validity period check
    /// 7. Certificate chain signature verification (PAA→PAI→DAC)
    /// 8. Decode attestation elements TLV
    /// 9. Verify attestation nonce
    /// 10. Verify and validate Certification Declaration
    pub fn verify_device_attestation(
        &self,
        info: &AttestationInfo,
        expected_nonce: &[u8; ATTESTATION_NONCE_LEN],
    ) -> Result<(), Error> {
        // 1. Input validation
        if info.attestation_elements.is_empty()
            || info.attestation_elements.len() > ATTESTATION_ELEMENTS_MAX_LEN
        {
            return Err(ErrorCode::InvalidArgument.into());
        }
        if info.attestation_challenge.len() != ATTESTATION_CHALLENGE_LEN {
            return Err(ErrorCode::InvalidArgument.into());
        }
        if info.dac_der.is_empty() {
            return Err(ErrorCode::InvalidArgument.into());
        }
        if info.pai_der.is_empty() {
            return Err(ErrorCode::AttPaiMissing.into());
        }

        // 2. Parse DAC and PAI
        let dac = DacCert::new(info.dac_der).map_err(|_| ErrorCode::AttDacFormatInvalid)?;
        let pai = PaiCert::new(info.pai_der).map_err(|_| ErrorCode::AttPaiFormatInvalid)?;

        // Extract VID/PID
        let dac_vid = dac
            .vendor_id()
            .map_err(|_| ErrorCode::AttDacFormatInvalid)?;
        let dac_pid = dac
            .product_id()
            .map_err(|_| ErrorCode::AttDacProductIdMismatch)?;
        let pai_vid = pai
            .vendor_id()
            .map_err(|_| ErrorCode::AttPaiFormatInvalid)?;
        // 0 = not present; see DeviceInfoForAttestation::pai_product_id doc
        let pai_pid = pai.product_id().unwrap_or(0);

        // 3. DAC↔PAI VID/PID cross-validation
        if pai_vid != dac_vid {
            return Err(ErrorCode::AttDacVendorIdMismatch.into());
        }
        if pai_pid != 0 && pai_pid != dac_pid {
            return Err(ErrorCode::AttDacProductIdMismatch.into());
        }

        // 4. Verify attestation signature
        // Signature is raw r||s (64 bytes) per Matter Spec, Section 3.5.3
        let sig_raw: &[u8; PKC_SIGNATURE_LEN] = info
            .attestation_signature
            .try_into()
            .map_err(|_| ErrorCode::AttSignatureInvalidFormat)?;

        let dac_pubkey_bytes = dac
            .public_key()
            .map_err(|_| ErrorCode::AttDacFormatInvalid)?;
        let dac_pubkey = self.load_pubkey(dac_pubkey_bytes)?;

        // Signed data = attestation_elements || attestation_challenge
        // Build concatenated buffer on stack
        let total_len = info.attestation_elements.len() + info.attestation_challenge.len();
        let mut signed_data = [0u8; ATTESTATION_ELEMENTS_MAX_LEN + ATTESTATION_CHALLENGE_LEN];
        signed_data[..info.attestation_elements.len()].copy_from_slice(info.attestation_elements);
        signed_data[info.attestation_elements.len()..total_len]
            .copy_from_slice(info.attestation_challenge);

        let sig_ref = CanonPkcSignatureRef::new(sig_raw);
        let valid = dac_pubkey
            .verify(&signed_data[..total_len], sig_ref)
            .map_err(|_| ErrorCode::AttSignatureInvalid)?;
        if !valid {
            return Err(ErrorCode::AttSignatureInvalid.into());
        }

        // 5. Find PAA via PAI's AKID
        let pai_akid = pai
            .authority_key_id()
            .map_err(|_| ErrorCode::AttPaiFormatInvalid)?;
        let pai_akid: &KeyId = pai_akid
            .try_into()
            .map_err(|_| ErrorCode::AttPaiFormatInvalid)?;
        let paa_der = self
            .trust_store
            .paa(pai_akid)
            .map_err(|_| ErrorCode::AttPaaNotFound)?;

        let paa = PaaCert::new(paa_der).map_err(|_| ErrorCode::AttPaaFormatInvalid)?;

        // PAA VID constraint: if PAA has VID, it must match PAI VID
        if let Ok(paa_vid) = paa.vendor_id() {
            if paa_vid != pai_vid {
                return Err(ErrorCode::AttPaiVendorIdMismatch.into());
            }
        }
        // PAA must NOT have PID (Matter Spec, Section 6.2.2.5 constraint #8)
        if paa.product_id().is_ok() {
            return Err(ErrorCode::AttPaaFormatInvalid.into());
        }

        // PAA SKID for CD validation
        let paa_skid_bytes = paa
            .subject_key_id()
            .map_err(|_| ErrorCode::AttPaaFormatInvalid)?;
        let paa_skid: [u8; KEY_IDENTIFIER_LEN] = paa_skid_bytes
            .try_into()
            .map_err(|_| ErrorCode::AttPaaFormatInvalid)?;

        // 6. DAC validity period check
        // Matter Spec, Section 3.5.6 "Time and date considerations for certificate path validation"
        let now_secs = (self.epoch)().as_secs();
        if now_secs > 0 {
            // Skip check if epoch returns 0 (no clock available, e.g. embedded without RTC)
            let valid_at = dac
                .is_valid_at(now_secs)
                .map_err(|_| ErrorCode::AttDacFormatInvalid)?;
            if !valid_at {
                return Err(ErrorCode::AttDacExpired.into());
            }
        }

        // 7. Certificate chain signature verification (PAA→PAI→DAC)
        self.verify_cert_chain(&paa, &pai, &dac)?;

        // 8. Decode attestation elements TLV
        let elements = AttestationElements::decode(info.attestation_elements)?;

        // 9. Verify attestation nonce
        if elements.attestation_nonce != expected_nonce {
            return Err(ErrorCode::AttNonceMismatch.into());
        }

        // 10. Verify CD signature and validate CD content
        // CD errors (CdInvalidFormat, CdInvalidVendorId, etc.) propagate directly
        // as they are already ErrorCode variants.
        let cd = CertificationElements::verify(
            self.crypto,
            elements.certification_declaration,
            self.allow_test_cd_signing_key,
        )?;

        let device_info = DeviceInfoForAttestation {
            vendor_id: info.vendor_id,
            product_id: info.product_id,
            dac_vendor_id: dac_vid,
            dac_product_id: dac_pid,
            pai_vendor_id: pai_vid,
            pai_product_id: pai_pid,
            paa_skid,
        };

        cd.validate(&device_info)?;

        Ok(())
    }

    /// Verify the full certificate chain: PAA signed PAI, PAI signed DAC.
    ///
    /// For each link, checks AKID/SKID match and verifies the parent's signature
    /// over the child's TBS certificate data.
    ///
    /// Mirrors C++ SDK's `ValidateCertificateChain(paa, pai, dac)`.
    fn verify_cert_chain(&self, paa: &PaaCert, pai: &PaiCert, dac: &DacCert) -> Result<(), Error> {
        // AKID/SKID authority checks
        let paa_skid = paa
            .subject_key_id()
            .map_err(|_| ErrorCode::AttChainInvalid)?;
        let pai_akid = pai
            .authority_key_id()
            .map_err(|_| ErrorCode::AttChainInvalid)?;
        if pai_akid != paa_skid {
            return Err(ErrorCode::AttChainInvalid.into());
        }

        let pai_skid = pai
            .subject_key_id()
            .map_err(|_| ErrorCode::AttChainInvalid)?;
        let dac_akid = dac
            .authority_key_id()
            .map_err(|_| ErrorCode::AttChainInvalid)?;
        if dac_akid != pai_skid {
            return Err(ErrorCode::AttChainInvalid.into());
        }

        // Signature verification
        self.verify_sig(pai, paa)
            .map_err(|_| ErrorCode::AttChainInvalid)?;
        self.verify_sig(dac, pai)
            .map_err(|_| ErrorCode::AttChainInvalid)?;

        Ok(())
    }

    /// Load a public key from raw bytes via the crypto backend.
    fn load_pubkey(&self, pubkey_bytes: &[u8]) -> Result<C::PublicKey<'a>, Error> {
        let pubkey_ref = CanonPkcPublicKeyRef::try_new(pubkey_bytes)?;
        self.crypto.pub_key(pubkey_ref)
    }

    /// Verify that parent's public key produced the signature over child's
    /// TBS (To Be Signed) certificate data.
    fn verify_sig<'b, E1, E2>(
        &self,
        child: &X509Cert<'b, E1>,
        parent: &X509Cert<'b, E2>,
    ) -> Result<(), Error>
    where
        E1: CertType<'b>,
        E2: CertType<'b>,
    {
        let parent_pubkey_bytes = parent.public_key()?;
        let parent_pubkey = self.load_pubkey(parent_pubkey_bytes)?;

        let sig_ref = CanonPkcSignatureRef::new(child.signature_raw());

        let valid = parent_pubkey.verify(child.tbs_raw(), sig_ref)?;
        if !valid {
            return Err(ErrorCode::InvalidSignature.into());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::credentials::test_paa::*;
    use crate::crypto::test_only_crypto;
    use crate::dm::clusters::dev_att::DeviceAttestation;
    use crate::dm::devices::test::TEST_DEV_ATT;
    use crate::utils::epoch::dummy_epoch;

    // Test device credentials: VID=0xFFF1, PID=0x8001 (from dm::devices::test)
    fn test_dac_der() -> &'static [u8] {
        TEST_DEV_ATT.dac()
    }
    fn test_pai_der() -> &'static [u8] {
        TEST_DEV_ATT.pai()
    }
    fn test_cd() -> &'static [u8] {
        TEST_DEV_ATT.cert_declaration()
    }

    #[test]
    fn cert_chain_full() {
        let crypto = test_only_crypto();
        let store = TEST_PAA_STORE;
        let verifier = AttestationVerifier::new(&crypto, &store, dummy_epoch, true);
        let paa = PaaCert::new(TEST_PAA_FFF1_CERT).unwrap();
        let pai = PaiCert::new(test_pai_der()).unwrap();
        let dac = DacCert::new(test_dac_der()).unwrap();
        verifier.verify_cert_chain(&paa, &pai, &dac).unwrap();
    }

    #[test]
    fn cert_chain_wrong_parent_fails() {
        let crypto = test_only_crypto();
        let store = TEST_PAA_STORE;
        let verifier = AttestationVerifier::new(&crypto, &store, dummy_epoch, true);
        // Use a different PAA (no-VID PAA) that didn't sign this PAI
        // — PAI's AKID won't match this PAA's SKID
        let wrong_paa = PaaCert::new(TEST_PAA_NOVID_CERT).unwrap();
        let pai = PaiCert::new(test_pai_der()).unwrap();
        let dac = DacCert::new(test_dac_der()).unwrap();
        let result = verifier.verify_cert_chain(&wrong_paa, &pai, &dac);
        assert_eq!(result.unwrap_err().code(), ErrorCode::AttChainInvalid);
    }

    /// Build a TLV-encoded attestation elements structure for testing.
    fn build_test_attestation_elements(cd: &[u8], nonce: &[u8], timestamp: u32) -> Vec<u8> {
        use crate::tlv::{TLVTag, TLVWrite};
        use crate::utils::storage::WriteBuf;

        let mut buf = [0u8; 2048];
        let len = {
            let mut wb = WriteBuf::new(&mut buf);
            wb.start_struct(&TLVTag::Anonymous).unwrap();
            wb.str(&TLVTag::Context(TAG_CERTIFICATION_DECLARATION), cd)
                .unwrap();
            wb.str(&TLVTag::Context(TAG_ATTESTATION_NONCE), nonce)
                .unwrap();
            wb.u32(&TLVTag::Context(TAG_TIMESTAMP), timestamp).unwrap();
            wb.end_container().unwrap();
            wb.get_tail()
        };
        buf[..len].to_vec()
    }

    #[test]
    fn attestation_elements_decode() {
        let nonce = [0x42u8; ATTESTATION_NONCE_LEN];
        let att_elements = build_test_attestation_elements(test_cd(), &nonce, 1000);
        let elements = AttestationElements::decode(&att_elements).unwrap();
        assert_eq!(elements.certification_declaration, test_cd());
        assert_eq!(elements.attestation_nonce, &nonce);
        assert_eq!(elements.timestamp, 1000);
        assert!(elements.firmware_info.is_none());
    }

    #[test]
    fn attestation_elements_bad_nonce_len() {
        // Wrong nonce length (16 instead of 32)
        let bad_nonce = [0x42u8; 16];
        let att_elements = build_test_attestation_elements(test_cd(), &bad_nonce, 1000);
        assert_eq!(
            AttestationElements::decode(&att_elements)
                .unwrap_err()
                .code(),
            ErrorCode::AttElementsMalformed,
        );
    }

    #[test]
    fn attestation_elements_firmware_info_wrong_type() {
        // firmware_info tag present but as u32 instead of octet string → must reject
        use crate::tlv::{TLVTag, TLVWrite};
        use crate::utils::storage::WriteBuf;

        let nonce = [0x42u8; ATTESTATION_NONCE_LEN];
        let mut buf = [0u8; 2048];
        let len = {
            let mut wb = WriteBuf::new(&mut buf);
            wb.start_struct(&TLVTag::Anonymous).unwrap();
            wb.str(&TLVTag::Context(TAG_CERTIFICATION_DECLARATION), test_cd())
                .unwrap();
            wb.str(&TLVTag::Context(TAG_ATTESTATION_NONCE), &nonce)
                .unwrap();
            wb.u32(&TLVTag::Context(TAG_TIMESTAMP), 1000).unwrap();
            // Wrong type: u32 instead of octet string
            wb.u32(&TLVTag::Context(TAG_FIRMWARE_INFO), 0xDEAD).unwrap();
            wb.end_container().unwrap();
            wb.get_tail()
        };
        assert_eq!(
            AttestationElements::decode(&buf[..len]).unwrap_err().code(),
            ErrorCode::AttElementsMalformed,
        );
    }

    /// Sign `attestation_elements || attestation_challenge` with the test DAC private key.
    fn sign_attestation(
        crypto: &impl Crypto,
        att_elements: &[u8],
        att_challenge: &[u8],
    ) -> Vec<u8> {
        use crate::crypto::{CanonPkcSignature, SigningSecretKey};

        let secret_key = crypto.secret_key(TEST_DEV_ATT.dac_priv_key()).unwrap();

        let mut msg = Vec::new();
        msg.extend_from_slice(att_elements);
        msg.extend_from_slice(att_challenge);

        let mut signature = CanonPkcSignature::new();
        secret_key.sign(&msg, &mut signature).unwrap();
        signature.access().to_vec()
    }

    #[test]
    fn full_verification_happy_path() {
        let crypto = test_only_crypto();
        let store = TEST_PAA_STORE;

        let nonce = [0xABu8; 32];
        let att_elements = build_test_attestation_elements(test_cd(), &nonce, 1000);
        let att_challenge = [0x42u8; ATTESTATION_CHALLENGE_LEN];
        let att_signature = sign_attestation(&crypto, &att_elements, &att_challenge);

        let verifier = AttestationVerifier::new(&crypto, &store, dummy_epoch, true);
        let info = AttestationInfo {
            attestation_elements: &att_elements,
            attestation_challenge: &att_challenge,
            attestation_signature: &att_signature,
            dac_der: test_dac_der(),
            pai_der: test_pai_der(),
            vendor_id: 0xFFF1,
            product_id: 0x8001,
        };

        verifier.verify_device_attestation(&info, &nonce).unwrap();
    }

    #[test]
    fn verification_bad_signature() {
        let crypto = test_only_crypto();
        let store = TEST_PAA_STORE;

        let nonce = [0xABu8; 32];
        let att_elements = build_test_attestation_elements(test_cd(), &nonce, 1000);
        let att_challenge = [0x42u8; ATTESTATION_CHALLENGE_LEN];
        let mut att_signature = sign_attestation(&crypto, &att_elements, &att_challenge);
        att_signature[10] ^= 0xFF; // corrupt

        let verifier = AttestationVerifier::new(&crypto, &store, dummy_epoch, true);
        let info = AttestationInfo {
            attestation_elements: &att_elements,
            attestation_challenge: &att_challenge,
            attestation_signature: &att_signature,
            dac_der: test_dac_der(),
            pai_der: test_pai_der(),
            vendor_id: 0xFFF1,
            product_id: 0x8001,
        };

        assert_eq!(
            verifier
                .verify_device_attestation(&info, &nonce)
                .unwrap_err()
                .code(),
            ErrorCode::AttSignatureInvalid,
        );
    }

    #[test]
    fn verification_vid_mismatch() {
        let crypto = test_only_crypto();
        let store = TEST_PAA_STORE;

        let nonce = [0xABu8; 32];
        let att_elements = build_test_attestation_elements(test_cd(), &nonce, 1000);
        let att_challenge = [0x42u8; ATTESTATION_CHALLENGE_LEN];
        let att_signature = sign_attestation(&crypto, &att_elements, &att_challenge);

        let verifier = AttestationVerifier::new(&crypto, &store, dummy_epoch, true);
        let info = AttestationInfo {
            attestation_elements: &att_elements,
            attestation_challenge: &att_challenge,
            attestation_signature: &att_signature,
            dac_der: test_dac_der(),
            pai_der: test_pai_der(),
            vendor_id: 0xFFF2, // wrong VID
            product_id: 0x8001,
        };

        assert_eq!(
            verifier
                .verify_device_attestation(&info, &nonce)
                .unwrap_err()
                .code(),
            ErrorCode::CdInvalidVendorId,
        );
    }

    #[test]
    fn verification_pid_mismatch() {
        let crypto = test_only_crypto();
        let store = TEST_PAA_STORE;

        let nonce = [0xABu8; 32];
        let att_elements = build_test_attestation_elements(test_cd(), &nonce, 1000);
        let att_challenge = [0x42u8; ATTESTATION_CHALLENGE_LEN];
        let att_signature = sign_attestation(&crypto, &att_elements, &att_challenge);

        let verifier = AttestationVerifier::new(&crypto, &store, dummy_epoch, true);
        let info = AttestationInfo {
            attestation_elements: &att_elements,
            attestation_challenge: &att_challenge,
            attestation_signature: &att_signature,
            dac_der: test_dac_der(),
            pai_der: test_pai_der(),
            vendor_id: 0xFFF1,
            product_id: 0x9999, // wrong PID
        };

        assert_eq!(
            verifier
                .verify_device_attestation(&info, &nonce)
                .unwrap_err()
                .code(),
            ErrorCode::CdInvalidProductId,
        );
    }

    #[test]
    fn verification_empty_dac() {
        let crypto = test_only_crypto();
        let store = TEST_PAA_STORE;

        let verifier = AttestationVerifier::new(&crypto, &store, dummy_epoch, true);
        let info = AttestationInfo {
            attestation_elements: &[0x15, 0x18], // minimal non-empty
            attestation_challenge: &[0u8; ATTESTATION_CHALLENGE_LEN],
            attestation_signature: &[],
            dac_der: &[], // empty
            pai_der: test_pai_der(),
            vendor_id: 0xFFF1,
            product_id: 0x8001,
        };

        assert_eq!(
            verifier
                .verify_device_attestation(&info, &[0u8; ATTESTATION_NONCE_LEN])
                .unwrap_err()
                .code(),
            ErrorCode::InvalidArgument,
        );
    }

    #[test]
    fn verification_nonce_mismatch() {
        let crypto = test_only_crypto();
        let store = TEST_PAA_STORE;

        let nonce = [0xABu8; 32];
        let att_elements = build_test_attestation_elements(test_cd(), &nonce, 1000);
        let att_challenge = [0x42u8; ATTESTATION_CHALLENGE_LEN];
        let att_signature = sign_attestation(&crypto, &att_elements, &att_challenge);

        let verifier = AttestationVerifier::new(&crypto, &store, dummy_epoch, true);
        let info = AttestationInfo {
            attestation_elements: &att_elements,
            attestation_challenge: &att_challenge,
            attestation_signature: &att_signature,
            dac_der: test_dac_der(),
            pai_der: test_pai_der(),
            vendor_id: 0xFFF1,
            product_id: 0x8001,
        };

        let wrong_nonce = [0xCDu8; 32];
        assert_eq!(
            verifier
                .verify_device_attestation(&info, &wrong_nonce)
                .unwrap_err()
                .code(),
            ErrorCode::AttNonceMismatch,
        );
    }

    #[test]
    fn verification_dac_expired() {
        use core::time::Duration;

        let crypto = test_only_crypto();
        let store = TEST_PAA_STORE;

        let nonce = [0xABu8; 32];
        let att_elements = build_test_attestation_elements(test_cd(), &nonce, 1000);
        let att_challenge = [0x42u8; ATTESTATION_CHALLENGE_LEN];
        let att_signature = sign_attestation(&crypto, &att_elements, &att_challenge);

        // Test DAC not_before is 1644019200 (2022-02-05), use a time before that
        fn past_epoch() -> Duration {
            Duration::from_secs(1600000000) // 2020-09-13, before DAC's not_before
        }

        let verifier = AttestationVerifier::new(&crypto, &store, past_epoch, true);
        let info = AttestationInfo {
            attestation_elements: &att_elements,
            attestation_challenge: &att_challenge,
            attestation_signature: &att_signature,
            dac_der: test_dac_der(),
            pai_der: test_pai_der(),
            vendor_id: 0xFFF1,
            product_id: 0x8001,
        };

        assert_eq!(
            verifier
                .verify_device_attestation(&info, &nonce)
                .unwrap_err()
                .code(),
            ErrorCode::AttDacExpired,
        );
    }
}
