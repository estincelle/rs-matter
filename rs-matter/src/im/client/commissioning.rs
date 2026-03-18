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
//! - [`set_tc_acknowledgements`](ImClient::set_tc_acknowledgements) - Set Terms & Conditions acknowledgements
//!
//! ## Operational Credentials (0x003E)
//! - [`attestation_request`](ImClient::attestation_request) - Request device attestation
//! - [`certificate_chain_request`](ImClient::certificate_chain_request) - Request certificate chain
//! - [`csr_request`](ImClient::csr_request) - Request CSR for NOC
//! - [`add_trusted_root_certificate`](ImClient::add_trusted_root_certificate) - Add trusted root CA
//! - [`add_noc`](ImClient::add_noc) - Add Node Operational Certificate
//! - [`update_noc`](ImClient::update_noc) - Update existing NOC (certificate rotation)
//! - [`update_fabric_label`](ImClient::update_fabric_label) - Update fabric label
//! - [`remove_fabric`](ImClient::remove_fabric) - Remove a fabric from the device
//! - [`set_vid_verification_statement`](ImClient::set_vid_verification_statement) - Set VID verification statement
//! - [`sign_vid_verification_request`](ImClient::sign_vid_verification_request) - Request VID verification signature
//!
//! ## Administrator Commissioning (0x003C)
//! - [`open_commissioning_window`](ImClient::open_commissioning_window) - Open enhanced commissioning window (timed)
//! - [`open_basic_commissioning_window`](ImClient::open_basic_commissioning_window) - Open basic commissioning window (timed)
//! - [`revoke_commissioning`](ImClient::revoke_commissioning) - Revoke active commissioning window (timed)
//!
//! ## Attribute Reads (General Commissioning)
//! - [`read_basic_commissioning_info`](ImClient::read_basic_commissioning_info) - Read fail-safe timing parameters
//! - [`read_regulatory_config`](ImClient::read_regulatory_config) - Read current regulatory configuration
//! - [`read_location_capability`](ImClient::read_location_capability) - Read device location capability
//! - [`read_supports_concurrent_connection`](ImClient::read_supports_concurrent_connection) - Read concurrent connection support

use crate::error::{Error, ErrorCode};
use crate::tlv::{FromTLV, Octets, TLVBuilderParent, TLVElement, TLVTag, TLVWrite, TLVWriteParent};
use crate::transport::exchange::Exchange;
use crate::utils::storage::WriteBuf;

use super::ImClient;

// General Commissioning types
pub use crate::dm::clusters::decl::general_commissioning::{
    // Request builders
    ArmFailSafeRequestBuilder,
    // Response types (TLVElement wrappers)
    ArmFailSafeResponse,
    BasicCommissioningInfo,
    CommissioningCompleteResponse,
    // Enums
    CommissioningErrorEnum,
    RegulatoryLocationTypeEnum,
    SetRegulatoryConfigRequestBuilder,
    SetRegulatoryConfigResponse,
    SetTCAcknowledgementsRequestBuilder,
    SetTCAcknowledgementsResponse,
};

// Administrator Commissioning types
pub use crate::dm::clusters::decl::administrator_commissioning::{
    // Request builders
    OpenBasicCommissioningWindowRequestBuilder,
    OpenCommissioningWindowRequestBuilder,
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
    RemoveFabricRequestBuilder,
    SetVIDVerificationStatementRequestBuilder,
    SignVIDVerificationRequestRequestBuilder,
    SignVIDVerificationResponse,
    UpdateFabricLabelRequestBuilder,
    UpdateNOCRequestBuilder,
};

/// All commissioning clusters live on endpoint 0 per the Matter spec.
const ENDPOINT: super::EndptId = 0;

/// General Commissioning cluster ID
pub const GENERAL_COMMISSIONING_CLUSTER: u32 = 0x0030;

/// Operational Credentials cluster ID
pub const OPERATIONAL_CREDENTIALS_CLUSTER: u32 = 0x003E;

/// Administrator Commissioning cluster ID
pub const ADMINISTRATOR_COMMISSIONING_CLUSTER: u32 = 0x003C;

// General Commissioning command IDs
const CMD_ARM_FAIL_SAFE: u32 = 0x00;
const CMD_SET_REGULATORY_CONFIG: u32 = 0x02;
const CMD_COMMISSIONING_COMPLETE: u32 = 0x04;
const CMD_SET_TC_ACKNOWLEDGEMENTS: u32 = 0x06;

// Operational Credentials command IDs
const CMD_ATTESTATION_REQUEST: u32 = 0x00;
const CMD_CERTIFICATE_CHAIN_REQUEST: u32 = 0x02;
const CMD_CSR_REQUEST: u32 = 0x04;
const CMD_ADD_NOC: u32 = 0x06;
const CMD_UPDATE_NOC: u32 = 0x07;
const CMD_UPDATE_FABRIC_LABEL: u32 = 0x09;
const CMD_REMOVE_FABRIC: u32 = 0x0A;
const CMD_ADD_TRUSTED_ROOT_CERTIFICATE: u32 = 0x0B;
const CMD_SET_VID_VERIFICATION_STATEMENT: u32 = 0x0C;
const CMD_SIGN_VID_VERIFICATION_REQUEST: u32 = 0x0D;

// Administrator Commissioning command IDs
const CMD_OPEN_COMMISSIONING_WINDOW: u32 = 0x00;
const CMD_OPEN_BASIC_COMMISSIONING_WINDOW: u32 = 0x01;
const CMD_REVOKE_COMMISSIONING: u32 = 0x02;

/// Default timed invoke timeout for Administrator Commissioning commands (10 seconds).
/// Matches the C++ SDK `kTimedInvokeTimeoutMs` value.
const ADMIN_COMM_TIMED_INVOKE_TIMEOUT_MS: u16 = 10000;

// General Commissioning attribute IDs
const ATTR_BASIC_COMMISSIONING_INFO: u32 = 0x01;
const ATTR_REGULATORY_CONFIG: u32 = 0x02;
const ATTR_LOCATION_CAPABILITY: u32 = 0x03;
const ATTR_SUPPORTS_CONCURRENT_CONNECTION: u32 = 0x04;

use super::{extract_attr_data, extract_cmd_data, extract_status_success};

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

        let resp = Self::invoke_single_cmd(
            exchange,
            ENDPOINT,
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

        let resp = Self::invoke_single_cmd(
            exchange,
            ENDPOINT,
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
        let mut buf = [0u8; 8];
        let tail = {
            let mut wb = WriteBuf::new(&mut buf);
            wb.start_struct(&TLVTag::Anonymous)?;
            wb.end_container()?;
            wb.get_tail()
        };
        let cmd_data = TLVElement::new(&buf[..tail]);

        let resp = Self::invoke_single_cmd(
            exchange,
            ENDPOINT,
            GENERAL_COMMISSIONING_CLUSTER,
            CMD_COMMISSIONING_COMPLETE,
            cmd_data,
            None,
        )
        .await?;

        let data = extract_cmd_data(&resp)?;
        Ok(CommissioningCompleteResponse::new(data))
    }

    /// Set the Terms & Conditions acknowledgements on the device.
    ///
    /// Required for Matter 1.4+ devices that support the Terms & Conditions
    /// feature. The commissioner sends the TC version and user response flags
    /// to indicate which terms have been accepted.
    ///
    /// # Arguments
    /// - `exchange` - An established exchange (typically PASE session during commissioning)
    /// - `tc_version` - The Terms & Conditions version being acknowledged
    /// - `tc_user_response` - Bitmap of user responses (accepted terms)
    ///
    /// # Returns
    /// The response containing the error code.
    /// Use `.error_code()` to access the field.
    pub async fn set_tc_acknowledgements<'a>(
        exchange: &'a mut Exchange<'_>,
        tc_version: u16,
        tc_user_response: u16,
    ) -> Result<SetTCAcknowledgementsResponse<'a>, Error> {
        let mut buf = [0u8; 32];
        let tail = {
            let wb = WriteBuf::new(&mut buf);
            let parent = TLVWriteParent::new((), wb);

            let mut parent = SetTCAcknowledgementsRequestBuilder::new(parent, &TLVTag::Anonymous)?
                .tc_version(tc_version)?
                .tc_user_response(tc_user_response)?
                .end()?;

            parent.writer().get_tail()
        };
        let cmd_data = TLVElement::new(&buf[..tail]);

        let resp = Self::invoke_single_cmd(
            exchange,
            ENDPOINT,
            GENERAL_COMMISSIONING_CLUSTER,
            CMD_SET_TC_ACKNOWLEDGEMENTS,
            cmd_data,
            None,
        )
        .await?;

        let data = extract_cmd_data(&resp)?;
        Ok(SetTCAcknowledgementsResponse::new(data))
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
        if nonce.len() != 32 {
            return Err(ErrorCode::ConstraintError.into());
        }

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

        let resp = Self::invoke_single_cmd(
            exchange,
            ENDPOINT,
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

        let resp = Self::invoke_single_cmd(
            exchange,
            ENDPOINT,
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
        if nonce.len() != 32 {
            return Err(ErrorCode::ConstraintError.into());
        }

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

        let resp = Self::invoke_single_cmd(
            exchange,
            ENDPOINT,
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
    /// # Stack Usage
    /// Allocates a 512-byte buffer on the stack for TLV encoding.
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

        let resp = Self::invoke_single_cmd(
            exchange,
            ENDPOINT,
            OPERATIONAL_CREDENTIALS_CLUSTER,
            CMD_ADD_TRUSTED_ROOT_CERTIFICATE,
            cmd_data,
            None,
        )
        .await?;

        extract_status_success(&resp)
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
    /// # Stack Usage
    /// Allocates a 1024-byte buffer on the stack for TLV encoding.
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
        if ipk.len() != 16 {
            return Err(ErrorCode::ConstraintError.into());
        }

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

        let resp = Self::invoke_single_cmd(
            exchange,
            ENDPOINT,
            OPERATIONAL_CREDENTIALS_CLUSTER,
            CMD_ADD_NOC,
            cmd_data,
            None,
        )
        .await?;

        let data = extract_cmd_data(&resp)?;
        Ok(NOCResponse::new(data))
    }

    /// Update an existing Node Operational Certificate.
    ///
    /// This command is used to update the NOC on an existing fabric,
    /// typically for certificate rotation. The device must already be
    /// commissioned on the fabric.
    ///
    /// # Arguments
    /// - `exchange` - An established CASE session on the fabric to update
    /// - `noc` - The new NOC in Matter TLV format
    /// - `icac` - Optional new ICAC in Matter TLV format
    ///
    /// # Stack Usage
    /// Allocates a 1024-byte buffer on the stack for TLV encoding.
    ///
    /// # Returns
    /// The NOC response containing status and fabric index.
    /// Use `.status_code()`, `.fabric_index()`, and `.debug_text()` to access fields.
    pub async fn update_noc<'a>(
        exchange: &'a mut Exchange<'_>,
        noc: &[u8],
        icac: Option<&[u8]>,
    ) -> Result<NOCResponse<'a>, Error> {
        let mut buf = [0u8; 1024]; // NOC + ICAC can be large
        let tail = {
            let wb = WriteBuf::new(&mut buf);
            let parent = TLVWriteParent::new((), wb);

            let mut parent = UpdateNOCRequestBuilder::new(parent, &TLVTag::Anonymous)?
                .noc_value(Octets(noc))?
                .icac_value(icac.map(Octets))?
                .end()?;

            parent.writer().get_tail()
        };
        let cmd_data = TLVElement::new(&buf[..tail]);

        let resp = Self::invoke_single_cmd(
            exchange,
            ENDPOINT,
            OPERATIONAL_CREDENTIALS_CLUSTER,
            CMD_UPDATE_NOC,
            cmd_data,
            None,
        )
        .await?;

        let data = extract_cmd_data(&resp)?;
        Ok(NOCResponse::new(data))
    }

    /// Update the label of an existing fabric.
    ///
    /// This command allows changing the user-visible label associated with
    /// a fabric. The label must be unique among all fabrics on the device.
    ///
    /// # Arguments
    /// - `exchange` - An established CASE session on the fabric to update
    /// - `label` - The new label string (max 32 characters)
    ///
    /// # Returns
    /// The NOC response containing status and fabric index.
    /// Use `.status_code()`, `.fabric_index()`, and `.debug_text()` to access fields.
    pub async fn update_fabric_label<'a>(
        exchange: &'a mut Exchange<'_>,
        label: &str,
    ) -> Result<NOCResponse<'a>, Error> {
        let mut buf = [0u8; 64];
        let tail = {
            let wb = WriteBuf::new(&mut buf);
            let parent = TLVWriteParent::new((), wb);

            let mut parent = UpdateFabricLabelRequestBuilder::new(parent, &TLVTag::Anonymous)?
                .label(label)?
                .end()?;

            parent.writer().get_tail()
        };
        let cmd_data = TLVElement::new(&buf[..tail]);

        let resp = Self::invoke_single_cmd(
            exchange,
            ENDPOINT,
            OPERATIONAL_CREDENTIALS_CLUSTER,
            CMD_UPDATE_FABRIC_LABEL,
            cmd_data,
            None,
        )
        .await?;

        let data = extract_cmd_data(&resp)?;
        Ok(NOCResponse::new(data))
    }

    /// Remove a fabric from the device.
    ///
    /// This command removes all state associated with a fabric, including
    /// the NOC, ICAC, root CA, ACL entries, and bindings. If the fabric
    /// being removed is the one on which the command is sent, the session
    /// will be terminated after the response.
    ///
    /// # Arguments
    /// - `exchange` - An established CASE session with administrator privileges
    /// - `fabric_index` - The index of the fabric to remove
    ///
    /// # Returns
    /// The NOC response containing status and fabric index.
    /// Use `.status_code()`, `.fabric_index()`, and `.debug_text()` to access fields.
    pub async fn remove_fabric<'a>(
        exchange: &'a mut Exchange<'_>,
        fabric_index: u8,
    ) -> Result<NOCResponse<'a>, Error> {
        let mut buf = [0u8; 16];
        let tail = {
            let wb = WriteBuf::new(&mut buf);
            let parent = TLVWriteParent::new((), wb);

            let mut parent = RemoveFabricRequestBuilder::new(parent, &TLVTag::Anonymous)?
                .fabric_index(fabric_index)?
                .end()?;

            parent.writer().get_tail()
        };
        let cmd_data = TLVElement::new(&buf[..tail]);

        let resp = Self::invoke_single_cmd(
            exchange,
            ENDPOINT,
            OPERATIONAL_CREDENTIALS_CLUSTER,
            CMD_REMOVE_FABRIC,
            cmd_data,
            None,
        )
        .await?;

        let data = extract_cmd_data(&resp)?;
        Ok(NOCResponse::new(data))
    }

    /// Open an enhanced commissioning window on the device.
    ///
    /// This command instructs the device to begin advertising and accepting
    /// PASE connections using the provided PAKE passcode verifier. This is
    /// used for multi-admin scenarios where a new administrator needs to
    /// commission an already-commissioned device.
    ///
    /// This is a timed command (10-second timeout per the Matter spec).
    ///
    /// # Arguments
    /// - `exchange` - An established CASE session with administrator privileges
    /// - `commissioning_timeout` - Duration in seconds the window should remain open
    /// - `pake_passcode_verifier` - The PAKE passcode verifier (SPAKE2+ verifier)
    /// - `discriminator` - The discriminator to use for discovery
    /// - `iterations` - PBKDF2 iteration count
    /// - `salt` - PBKDF2 salt (max 32 bytes)
    ///
    /// # Stack Usage
    /// Allocates a 256-byte buffer on the stack for TLV encoding.
    ///
    /// # Returns
    /// `Ok(())` on success, or an error if the command failed.
    pub async fn open_commissioning_window(
        exchange: &mut Exchange<'_>,
        commissioning_timeout: u16,
        pake_passcode_verifier: &[u8],
        discriminator: u16,
        iterations: u32,
        salt: &[u8],
    ) -> Result<(), Error> {
        let mut buf = [0u8; 256]; // Verifier + salt can be large
        let tail = {
            let wb = WriteBuf::new(&mut buf);
            let parent = TLVWriteParent::new((), wb);

            let mut parent =
                OpenCommissioningWindowRequestBuilder::new(parent, &TLVTag::Anonymous)?
                    .commissioning_timeout(commissioning_timeout)?
                    .pake_passcode_verifier(Octets(pake_passcode_verifier))?
                    .discriminator(discriminator)?
                    .iterations(iterations)?
                    .salt(Octets(salt))?
                    .end()?;

            parent.writer().get_tail()
        };
        let cmd_data = TLVElement::new(&buf[..tail]);

        let resp = Self::invoke_single_cmd(
            exchange,
            ENDPOINT,
            ADMINISTRATOR_COMMISSIONING_CLUSTER,
            CMD_OPEN_COMMISSIONING_WINDOW,
            cmd_data,
            Some(ADMIN_COMM_TIMED_INVOKE_TIMEOUT_MS),
        )
        .await?;

        extract_status_success(&resp)
    }

    /// Open a basic commissioning window on the device.
    ///
    /// This command instructs the device to begin advertising and accepting
    /// PASE connections using the device's default passcode. This is a simpler
    /// alternative to [`open_commissioning_window`](Self::open_commissioning_window)
    /// that does not require generating a PAKE verifier.
    ///
    /// This is a timed command (10-second timeout per the Matter spec).
    ///
    /// # Arguments
    /// - `exchange` - An established CASE session with administrator privileges
    /// - `commissioning_timeout` - Duration in seconds the window should remain open
    ///
    /// # Returns
    /// `Ok(())` on success, or an error if the command failed.
    pub async fn open_basic_commissioning_window(
        exchange: &mut Exchange<'_>,
        commissioning_timeout: u16,
    ) -> Result<(), Error> {
        let mut buf = [0u8; 16];
        let tail = {
            let wb = WriteBuf::new(&mut buf);
            let parent = TLVWriteParent::new((), wb);

            let mut parent =
                OpenBasicCommissioningWindowRequestBuilder::new(parent, &TLVTag::Anonymous)?
                    .commissioning_timeout(commissioning_timeout)?
                    .end()?;

            parent.writer().get_tail()
        };
        let cmd_data = TLVElement::new(&buf[..tail]);

        let resp = Self::invoke_single_cmd(
            exchange,
            ENDPOINT,
            ADMINISTRATOR_COMMISSIONING_CLUSTER,
            CMD_OPEN_BASIC_COMMISSIONING_WINDOW,
            cmd_data,
            Some(ADMIN_COMM_TIMED_INVOKE_TIMEOUT_MS),
        )
        .await?;

        extract_status_success(&resp)
    }

    /// Revoke any active commissioning window on the device.
    ///
    /// This command closes any open commissioning window (either enhanced or
    /// basic). If no commissioning window is open, the device may return an
    /// error.
    ///
    /// This is a timed command (10-second timeout per the Matter spec).
    ///
    /// # Arguments
    /// - `exchange` - An established CASE session with administrator privileges
    ///
    /// # Returns
    /// `Ok(())` on success, or an error if the command failed.
    pub async fn revoke_commissioning(exchange: &mut Exchange<'_>) -> Result<(), Error> {
        // RevokeCommissioning has no request fields - send empty struct
        let mut buf = [0u8; 8];
        let tail = {
            let mut wb = WriteBuf::new(&mut buf);
            wb.start_struct(&TLVTag::Anonymous)?;
            wb.end_container()?;
            wb.get_tail()
        };
        let cmd_data = TLVElement::new(&buf[..tail]);

        let resp = Self::invoke_single_cmd(
            exchange,
            ENDPOINT,
            ADMINISTRATOR_COMMISSIONING_CLUSTER,
            CMD_REVOKE_COMMISSIONING,
            cmd_data,
            Some(ADMIN_COMM_TIMED_INVOKE_TIMEOUT_MS),
        )
        .await?;

        extract_status_success(&resp)
    }

    /// Read the basic commissioning info from the device.
    ///
    /// Returns the fail-safe timing parameters: the default fail-safe expiry
    /// length and the maximum cumulative fail-safe duration. These values are
    /// used to determine how long to arm the fail-safe timer during commissioning.
    ///
    /// # Arguments
    /// - `exchange` - An established exchange (typically PASE session)
    ///
    /// # Returns
    /// The `BasicCommissioningInfo` struct.
    /// Use `.fail_safe_expiry_length_seconds()` and `.max_cumulative_failsafe_seconds()` to access fields.
    pub async fn read_basic_commissioning_info<'a>(
        exchange: &'a mut Exchange<'_>,
    ) -> Result<BasicCommissioningInfo<'a>, Error> {
        let resp = Self::read_single_attr(
            exchange,
            ENDPOINT,
            GENERAL_COMMISSIONING_CLUSTER,
            ATTR_BASIC_COMMISSIONING_INFO,
            false,
        )
        .await?;

        let data = extract_attr_data(&resp)?;
        Ok(BasicCommissioningInfo::new(data))
    }

    /// Read the current regulatory configuration from the device.
    ///
    /// Returns the regulatory location type that the device is currently
    /// configured for (Indoor, Outdoor, or IndoorOutdoor).
    ///
    /// # Arguments
    /// - `exchange` - An established exchange (typically PASE session)
    ///
    /// # Returns
    /// The current `RegulatoryLocationTypeEnum` value.
    pub async fn read_regulatory_config(
        exchange: &mut Exchange<'_>,
    ) -> Result<RegulatoryLocationTypeEnum, Error> {
        let resp = Self::read_single_attr(
            exchange,
            ENDPOINT,
            GENERAL_COMMISSIONING_CLUSTER,
            ATTR_REGULATORY_CONFIG,
            false,
        )
        .await?;

        let data = extract_attr_data(&resp)?;
        RegulatoryLocationTypeEnum::from_tlv(&data)
    }

    /// Read the location capability of the device.
    ///
    /// Returns the regulatory location types that the device supports
    /// (Indoor, Outdoor, or IndoorOutdoor). This determines what values
    /// are valid for [`set_regulatory_config`](Self::set_regulatory_config).
    ///
    /// # Arguments
    /// - `exchange` - An established exchange (typically PASE session)
    ///
    /// # Returns
    /// The device's `RegulatoryLocationTypeEnum` capability.
    pub async fn read_location_capability(
        exchange: &mut Exchange<'_>,
    ) -> Result<RegulatoryLocationTypeEnum, Error> {
        let resp = Self::read_single_attr(
            exchange,
            ENDPOINT,
            GENERAL_COMMISSIONING_CLUSTER,
            ATTR_LOCATION_CAPABILITY,
            false,
        )
        .await?;

        let data = extract_attr_data(&resp)?;
        RegulatoryLocationTypeEnum::from_tlv(&data)
    }

    /// Read whether the device supports concurrent connections.
    ///
    /// When `true`, the device supports simultaneous CASE and PASE sessions,
    /// allowing the commissioner to establish a CASE session before closing
    /// the PASE session. When `false`, the commissioner must close the PASE
    /// session before establishing CASE.
    ///
    /// # Arguments
    /// - `exchange` - An established exchange (typically PASE session)
    ///
    /// # Returns
    /// `true` if the device supports concurrent connections.
    pub async fn read_supports_concurrent_connection(
        exchange: &mut Exchange<'_>,
    ) -> Result<bool, Error> {
        let resp = Self::read_single_attr(
            exchange,
            ENDPOINT,
            GENERAL_COMMISSIONING_CLUSTER,
            ATTR_SUPPORTS_CONCURRENT_CONNECTION,
            false,
        )
        .await?;

        let data = extract_attr_data(&resp)?;
        data.bool()
    }

    /// Set the VID Verification Statement for the accessing fabric.
    ///
    /// This command updates the VendorID, VID Verification Statement, and/or
    /// Vendor Verification Signing Certificate (VVSC) associated with the
    /// fabric on which the command is sent. All fields are optional.
    ///
    /// # Arguments
    /// - `exchange` - An established CASE session with administrator privileges
    /// - `vendor_id` - Optional vendor ID to set
    /// - `vid_verification_statement` - Optional VID verification statement (max 85 bytes)
    /// - `vvsc` - Optional Vendor Verification Signing Certificate (max 400 bytes)
    ///
    /// # Stack Usage
    /// Allocates a 512-byte buffer on the stack for TLV encoding.
    ///
    /// # Returns
    /// `Ok(())` on success, or an error if the command failed.
    pub async fn set_vid_verification_statement(
        exchange: &mut Exchange<'_>,
        vendor_id: Option<u16>,
        vid_verification_statement: Option<&[u8]>,
        vvsc: Option<&[u8]>,
    ) -> Result<(), Error> {
        let mut buf = [0u8; 512]; // VVSC can be up to 400 bytes
        let tail = {
            let wb = WriteBuf::new(&mut buf);
            let parent = TLVWriteParent::new((), wb);

            let mut parent =
                SetVIDVerificationStatementRequestBuilder::new(parent, &TLVTag::Anonymous)?
                    .vendor_id(vendor_id)?
                    .vid_verification_statement(vid_verification_statement.map(Octets))?
                    .vvsc(vvsc.map(Octets))?
                    .end()?;

            parent.writer().get_tail()
        };
        let cmd_data = TLVElement::new(&buf[..tail]);

        let resp = Self::invoke_single_cmd(
            exchange,
            ENDPOINT,
            OPERATIONAL_CREDENTIALS_CLUSTER,
            CMD_SET_VID_VERIFICATION_STATEMENT,
            cmd_data,
            None,
        )
        .await?;

        extract_status_success(&resp)
    }

    /// Request a VID verification signature from the device.
    ///
    /// This command asks the device to authenticate the fabric associated with
    /// the given fabric index by producing a signature over the client challenge.
    ///
    /// # Arguments
    /// - `exchange` - An established CASE session with administrator privileges
    /// - `fabric_index` - The index of the fabric to verify
    /// - `client_challenge` - A 32-byte challenge nonce
    ///
    /// # Returns
    /// The response containing the fabric index, fabric binding version, and signature.
    /// Use `.fabric_index()`, `.fabric_binding_version()`, and `.signature()` to access fields.
    pub async fn sign_vid_verification_request<'a>(
        exchange: &'a mut Exchange<'_>,
        fabric_index: u8,
        client_challenge: &[u8],
    ) -> Result<SignVIDVerificationResponse<'a>, Error> {
        if client_challenge.len() != 32 {
            return Err(ErrorCode::ConstraintError.into());
        }

        let mut buf = [0u8; 64];
        let tail = {
            let wb = WriteBuf::new(&mut buf);
            let parent = TLVWriteParent::new((), wb);

            let mut parent =
                SignVIDVerificationRequestRequestBuilder::new(parent, &TLVTag::Anonymous)?
                    .fabric_index(fabric_index)?
                    .client_challenge(Octets(client_challenge))?
                    .end()?;

            parent.writer().get_tail()
        };
        let cmd_data = TLVElement::new(&buf[..tail]);

        let resp = Self::invoke_single_cmd(
            exchange,
            ENDPOINT,
            OPERATIONAL_CREDENTIALS_CLUSTER,
            CMD_SIGN_VID_VERIFICATION_REQUEST,
            cmd_data,
            None,
        )
        .await?;

        let data = extract_cmd_data(&resp)?;
        Ok(SignVIDVerificationResponse::new(data))
    }
}
