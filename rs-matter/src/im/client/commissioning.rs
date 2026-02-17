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

//! Client-side types and methods for commissioning commands.
//!
//! This module provides type-safe wrappers for invoking commissioning cluster
//! commands from a Matter controller/commissioner.
//!
//! # Supported Clusters
//!
//! ## General Commissioning (0x0030)
//! - [`arm_fail_safe`](ImClient::arm_fail_safe) - Arm/extend the fail-safe timer
//! - [`set_regulatory_config`](ImClient::set_regulatory_config) - Set regulatory configuration
//! - [`commissioning_complete`](ImClient::commissioning_complete) - Complete commissioning
//!
//! ## Operational Credentials (0x003E)
//! - [`attestation_request`](ImClient::attestation_request) - Request device attestation
//! - [`certificate_chain_request`](ImClient::certificate_chain_request) - Request certificate chain
//! - [`csr_request`](ImClient::csr_request) - Request CSR for NOC
//! - [`add_trusted_root_certificate`](ImClient::add_trusted_root_certificate) - Add trusted root CA
//! - [`add_noc`](ImClient::add_noc) - Add Node Operational Certificate

use crate::error::{Error, ErrorCode};
use crate::tlv::{Octets, TLVBuilderParent, TLVElement, TLVTag, TLVWriteParent};
use crate::transport::exchange::Exchange;
use crate::utils::storage::WriteBuf;

use super::{CmdResp, ImClient};

// General Commissioning types
pub use crate::dm::clusters::decl::general_commissioning::{
    // Request builders
    ArmFailSafeRequestBuilder,
    // Response types (TLVElement wrappers)
    ArmFailSafeResponse,
    CommissioningCompleteResponse,
    // Enums
    CommissioningErrorEnum,
    RegulatoryLocationTypeEnum,
    SetRegulatoryConfigRequestBuilder,
    SetRegulatoryConfigResponse,
};

// Operational Credentials types
pub use crate::dm::clusters::decl::operational_credentials::{
    // Request builders
    AddNOCRequestBuilder,
    AddTrustedRootCertificateRequestBuilder,
    AttestationRequestRequestBuilder,
    // Response types (TLVElement wrappers)
    AttestationResponse,
    CSRRequestRequestBuilder,
    CSRResponse,
    CertificateChainRequestRequestBuilder,
    CertificateChainResponse,
    // Enums
    CertificateChainTypeEnum,
    NOCResponse,
    NodeOperationalCertStatusEnum,
};

/// General Commissioning cluster ID
pub const GENERAL_COMMISSIONING_CLUSTER: u32 = 0x0030;

/// Operational Credentials cluster ID
pub const OPERATIONAL_CREDENTIALS_CLUSTER: u32 = 0x003E;

// General Commissioning command IDs
const CMD_ARM_FAIL_SAFE: u32 = 0x00;
const CMD_SET_REGULATORY_CONFIG: u32 = 0x02;
const CMD_COMMISSIONING_COMPLETE: u32 = 0x04;

// Operational Credentials command IDs
const CMD_ATTESTATION_REQUEST: u32 = 0x00;
const CMD_CERTIFICATE_CHAIN_REQUEST: u32 = 0x02;
const CMD_CSR_REQUEST: u32 = 0x04;
const CMD_ADD_NOC: u32 = 0x06;
const CMD_ADD_TRUSTED_ROOT_CERTIFICATE: u32 = 0x0B;

/// Extract the command response data from a CmdResp, returning an error if it's a status-only response.
fn extract_cmd_data<'a>(resp: &CmdResp<'a>) -> Result<TLVElement<'a>, Error> {
    match resp {
        CmdResp::Cmd(cmd_data) => Ok(cmd_data.data.clone()),
        CmdResp::Status(status) => {
            error!("Command failed with IM status: {:?}", status.status.status);
            Err(ErrorCode::InvalidCommand.into())
        }
    }
}

impl ImClient {
    /// Arm or extend the fail-safe timer on the device.
    ///
    /// The fail-safe timer provides a window during which commissioning operations
    /// can be performed. If commissioning is not completed within this window,
    /// the device will revert to its pre-commissioning state.
    ///
    /// # Arguments
    /// - `exchange` - An established exchange (typically PASE session during commissioning)
    /// - `expiry_length_seconds` - Duration in seconds for the fail-safe timer
    /// - `breadcrumb` - A value to track commissioning progress
    ///
    /// # Returns
    /// The response containing the error code and optional debug text.
    /// Use `.error_code()` and `.debug_text()` to access fields.
    pub async fn arm_fail_safe<'a>(
        exchange: &'a mut Exchange<'_>,
        expiry_length_seconds: u16,
        breadcrumb: u64,
    ) -> Result<ArmFailSafeResponse<'a>, Error> {
        let mut buf = [0u8; 64];
        let tail = {
            let wb = WriteBuf::new(&mut buf);
            let parent = TLVWriteParent::new((), wb);

            let mut parent = ArmFailSafeRequestBuilder::new(parent, &TLVTag::Anonymous)?
                .expiry_length_seconds(expiry_length_seconds)?
                .breadcrumb(breadcrumb)?
                .end()?;

            parent.writer().get_tail()
        };
        let cmd_data = TLVElement::new(&buf[..tail]);

        let resp = Self::invoke_single(
            exchange,
            0, // endpoint 0
            GENERAL_COMMISSIONING_CLUSTER,
            CMD_ARM_FAIL_SAFE,
            cmd_data,
            None,
        )
        .await?;

        let data = extract_cmd_data(&resp)?;
        Ok(ArmFailSafeResponse::new(data))
    }

    /// Set the regulatory configuration on the device.
    ///
    /// Configures whether the device is installed indoors, outdoors, or both,
    /// and sets the country code for regulatory compliance.
    ///
    /// # Arguments
    /// - `exchange` - An established exchange (typically PASE session during commissioning)
    /// - `config` - The regulatory location type (Indoor, Outdoor, or IndoorOutdoor)
    /// - `country_code` - Two-character ISO 3166-1 alpha-2 country code
    /// - `breadcrumb` - A value to track commissioning progress
    ///
    /// # Returns
    /// The response containing the error code and optional debug text.
    /// Use `.error_code()` and `.debug_text()` to access fields.
    pub async fn set_regulatory_config<'a>(
        exchange: &'a mut Exchange<'_>,
        config: RegulatoryLocationTypeEnum,
        country_code: &str,
        breadcrumb: u64,
    ) -> Result<SetRegulatoryConfigResponse<'a>, Error> {
        let mut buf = [0u8; 64];
        let tail = {
            let wb = WriteBuf::new(&mut buf);
            let parent = TLVWriteParent::new((), wb);

            let mut parent = SetRegulatoryConfigRequestBuilder::new(parent, &TLVTag::Anonymous)?
                .new_regulatory_config(config)?
                .country_code(country_code)?
                .breadcrumb(breadcrumb)?
                .end()?;

            parent.writer().get_tail()
        };
        let cmd_data = TLVElement::new(&buf[..tail]);

        let resp = Self::invoke_single(
            exchange,
            0, // endpoint 0
            GENERAL_COMMISSIONING_CLUSTER,
            CMD_SET_REGULATORY_CONFIG,
            cmd_data,
            None,
        )
        .await?;

        let data = extract_cmd_data(&resp)?;
        Ok(SetRegulatoryConfigResponse::new(data))
    }

    /// Signal that commissioning is complete.
    ///
    /// This should be called after all commissioning steps are complete.
    /// Upon success, the device will disarm the fail-safe timer and close
    /// the commissioning window.
    ///
    /// # Arguments
    /// - `exchange` - An established exchange (typically CASE session after NOC provisioning)
    ///
    /// # Returns
    /// The response containing the error code and optional debug text.
    /// Use `.error_code()` and `.debug_text()` to access fields.
    pub async fn commissioning_complete<'a>(
        exchange: &'a mut Exchange<'_>,
    ) -> Result<CommissioningCompleteResponse<'a>, Error> {
        // CommissioningComplete has no request fields - send empty struct
        let cmd_data = TLVElement::new(&[0x15, 0x18]); // Empty struct: start_struct + end_container

        let resp = Self::invoke_single(
            exchange,
            0, // endpoint 0
            GENERAL_COMMISSIONING_CLUSTER,
            CMD_COMMISSIONING_COMPLETE,
            cmd_data,
            None,
        )
        .await?;

        let data = extract_cmd_data(&resp)?;
        Ok(CommissioningCompleteResponse::new(data))
    }

    /// Request device attestation information.
    ///
    /// The device will return its Certification Declaration and a signature
    /// over the attestation elements, allowing the commissioner to verify
    /// the device's authenticity.
    ///
    /// # Arguments
    /// - `exchange` - An established exchange (typically PASE session)
    /// - `nonce` - A 32-byte nonce for freshness
    ///
    /// # Returns
    /// The attestation response containing attestation elements and signature.
    /// Use `.attestation_elements()` and `.attestation_signature()` to access fields.
    pub async fn attestation_request<'a>(
        exchange: &'a mut Exchange<'_>,
        nonce: &[u8],
    ) -> Result<AttestationResponse<'a>, Error> {
        let mut buf = [0u8; 64];
        let tail = {
            let wb = WriteBuf::new(&mut buf);
            let parent = TLVWriteParent::new((), wb);

            let mut parent = AttestationRequestRequestBuilder::new(parent, &TLVTag::Anonymous)?
                .attestation_nonce(Octets(nonce))?
                .end()?;

            parent.writer().get_tail()
        };
        let cmd_data = TLVElement::new(&buf[..tail]);

        let resp = Self::invoke_single(
            exchange,
            0, // endpoint 0
            OPERATIONAL_CREDENTIALS_CLUSTER,
            CMD_ATTESTATION_REQUEST,
            cmd_data,
            None,
        )
        .await?;

        let data = extract_cmd_data(&resp)?;
        Ok(AttestationResponse::new(data))
    }

    /// Request a certificate from the device's certificate chain.
    ///
    /// # Arguments
    /// - `exchange` - An established exchange (typically PASE session)
    /// - `cert_type` - The type of certificate to request (DAC or PAI)
    ///
    /// # Returns
    /// The certificate chain response containing the requested certificate.
    /// Use `.certificate()` to access the certificate bytes.
    pub async fn certificate_chain_request<'a>(
        exchange: &'a mut Exchange<'_>,
        cert_type: CertificateChainTypeEnum,
    ) -> Result<CertificateChainResponse<'a>, Error> {
        let mut buf = [0u8; 16];
        let tail = {
            let wb = WriteBuf::new(&mut buf);
            let parent = TLVWriteParent::new((), wb);

            let mut parent =
                CertificateChainRequestRequestBuilder::new(parent, &TLVTag::Anonymous)?
                    .certificate_type(cert_type)?
                    .end()?;

            parent.writer().get_tail()
        };
        let cmd_data = TLVElement::new(&buf[..tail]);

        let resp = Self::invoke_single(
            exchange,
            0, // endpoint 0
            OPERATIONAL_CREDENTIALS_CLUSTER,
            CMD_CERTIFICATE_CHAIN_REQUEST,
            cmd_data,
            None,
        )
        .await?;

        let data = extract_cmd_data(&resp)?;
        Ok(CertificateChainResponse::new(data))
    }

    /// Request a Certificate Signing Request from the device.
    ///
    /// The device will generate a new operational key pair and return a CSR
    /// that the commissioner can use to issue a Node Operational Certificate.
    ///
    /// # Arguments
    /// - `exchange` - An established exchange (typically PASE session)
    /// - `nonce` - A 32-byte nonce for freshness
    /// - `is_for_update` - If true, the CSR is for updating an existing NOC
    ///
    /// # Returns
    /// The CSR response containing NOCSR elements and signature.
    /// Use `.nocsr_elements()` and `.attestation_signature()` to access fields.
    pub async fn csr_request<'a>(
        exchange: &'a mut Exchange<'_>,
        nonce: &[u8],
        is_for_update: bool,
    ) -> Result<CSRResponse<'a>, Error> {
        let mut buf = [0u8; 64];
        let tail = {
            let wb = WriteBuf::new(&mut buf);
            let parent = TLVWriteParent::new((), wb);

            let mut parent = CSRRequestRequestBuilder::new(parent, &TLVTag::Anonymous)?
                .csr_nonce(Octets(nonce))?
                .is_for_update_noc(if is_for_update { Some(true) } else { None })?
                .end()?;

            parent.writer().get_tail()
        };
        let cmd_data = TLVElement::new(&buf[..tail]);

        let resp = Self::invoke_single(
            exchange,
            0, // endpoint 0
            OPERATIONAL_CREDENTIALS_CLUSTER,
            CMD_CSR_REQUEST,
            cmd_data,
            None,
        )
        .await?;

        let data = extract_cmd_data(&resp)?;
        Ok(CSRResponse::new(data))
    }

    /// Add a trusted root CA certificate.
    ///
    /// This must be called before AddNOC to establish the trust anchor for
    /// the fabric being commissioned.
    ///
    /// # Arguments
    /// - `exchange` - An established exchange (typically PASE session)
    /// - `root_ca` - The root CA certificate in Matter TLV format
    ///
    /// # Returns
    /// `Ok(())` on success, or an error if the command failed.
    pub async fn add_trusted_root_certificate(
        exchange: &mut Exchange<'_>,
        root_ca: &[u8],
    ) -> Result<(), Error> {
        let mut buf = [0u8; 512]; // Root CA can be large
        let tail = {
            let wb = WriteBuf::new(&mut buf);
            let parent = TLVWriteParent::new((), wb);

            let mut parent =
                AddTrustedRootCertificateRequestBuilder::new(parent, &TLVTag::Anonymous)?
                    .root_ca_certificate(Octets(root_ca))?
                    .end()?;

            parent.writer().get_tail()
        };
        let cmd_data = TLVElement::new(&buf[..tail]);

        let resp = Self::invoke_single(
            exchange,
            0, // endpoint 0
            OPERATIONAL_CREDENTIALS_CLUSTER,
            CMD_ADD_TRUSTED_ROOT_CERTIFICATE,
            cmd_data,
            None,
        )
        .await?;

        // AddTrustedRootCertificate returns no response data on success,
        // just check that we got a successful command response
        match &resp {
            CmdResp::Cmd(_) => Ok(()),
            CmdResp::Status(status) => {
                if status.status.status == crate::im::IMStatusCode::Success {
                    Ok(())
                } else {
                    error!(
                        "AddTrustedRootCertificate failed with status: {:?}",
                        status.status.status
                    );
                    Err(ErrorCode::InvalidCommand.into())
                }
            }
        }
    }

    /// Add a Node Operational Certificate to commission the device.
    ///
    /// This is the final step in fabric commissioning. After this succeeds,
    /// the device will be part of the commissioner's fabric and can be
    /// accessed via CASE sessions.
    ///
    /// # Arguments
    /// - `exchange` - An established exchange (typically PASE session)
    /// - `noc` - The NOC in Matter TLV format
    /// - `icac` - Optional ICAC in Matter TLV format
    /// - `ipk` - The 16-byte Identity Protection Key
    /// - `case_admin_subject` - Node ID of the administrator
    /// - `admin_vendor_id` - Vendor ID of the administrator
    ///
    /// # Returns
    /// The NOC response containing status and fabric index.
    /// Use `.status_code()`, `.fabric_index()`, and `.debug_text()` to access fields.
    pub async fn add_noc<'a>(
        exchange: &'a mut Exchange<'_>,
        noc: &[u8],
        icac: Option<&[u8]>,
        ipk: &[u8],
        case_admin_subject: u64,
        admin_vendor_id: u16,
    ) -> Result<NOCResponse<'a>, Error> {
        let mut buf = [0u8; 1024]; // NOC + ICAC can be large
        let tail = {
            let wb = WriteBuf::new(&mut buf);
            let parent = TLVWriteParent::new((), wb);

            let mut parent = AddNOCRequestBuilder::new(parent, &TLVTag::Anonymous)?
                .noc_value(Octets(noc))?
                .icac_value(icac.map(Octets))?
                .ipk_value(Octets(ipk))?
                .case_admin_subject(case_admin_subject)?
                .admin_vendor_id(admin_vendor_id)?
                .end()?;

            parent.writer().get_tail()
        };
        let cmd_data = TLVElement::new(&buf[..tail]);

        let resp = Self::invoke_single(
            exchange,
            0, // endpoint 0
            OPERATIONAL_CREDENTIALS_CLUSTER,
            CMD_ADD_NOC,
            cmd_data,
            None,
        )
        .await?;

        let data = extract_cmd_data(&resp)?;
        Ok(NOCResponse::new(data))
    }
}
