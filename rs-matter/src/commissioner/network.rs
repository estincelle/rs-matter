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

//! Network Commissioning client for Matter commissioners.
//!
//! This module provides type-safe wrappers for invoking Network Commissioning
//! cluster (0x0031) commands from a Matter controller/commissioner.
//!
//! The Network Commissioning cluster is used to configure network credentials
//! on a device during commissioning. It supports:
//! - **WiFi**: Configure SSID and password credentials
//! - **Thread**: Configure Thread operational dataset
//! - **Ethernet**: No configuration needed (wired connection)
//!
//! # Supported Commands
//!
//! - [`scan_networks`](ImClient::scan_networks) - Scan for available networks
//! - [`add_or_update_wifi_network`](ImClient::add_or_update_wifi_network) - Add/update WiFi credentials
//! - [`add_or_update_thread_network`](ImClient::add_or_update_thread_network) - Add/update Thread credentials
//! - [`connect_network`](ImClient::connect_network) - Connect to a configured network
//! - [`remove_network`](ImClient::remove_network) - Remove a network configuration
//! - [`reorder_network`](ImClient::reorder_network) - Change network priority order
//!
//! # Attribute Reads
//!
//! - [`detect_network_type`](ImClient::detect_network_type) - Detect WiFi/Thread/Ethernet support
//! - [`read_max_networks`](ImClient::read_max_networks) - Maximum storable networks
//! - [`read_scan_max_time_seconds`](ImClient::read_scan_max_time_seconds) - Scan timeout
//! - [`read_connect_max_time_seconds`](ImClient::read_connect_max_time_seconds) - Connect timeout
//! - [`read_interface_enabled`](ImClient::read_interface_enabled) - Interface status
//! - [`read_last_networking_status`](ImClient::read_last_networking_status) - Last operation status
//! - [`read_last_network_id`](ImClient::read_last_network_id) - Last network ID
//! - [`read_last_connect_error_value`](ImClient::read_last_connect_error_value) - Last error code
//!
//! # Example
//!
//! ```ignore
//! use rs_matter::commissioner::network::{NetworkType};
//! use rs_matter::im::client::ImClient;
//!
//! // Detect network type
//! let net_type = ImClient::detect_network_type(&mut exchange, 0).await?;
//!
//! match net_type {
//!     NetworkType::WiFi => {
//!         // Scan for networks
//!         let scan_resp = ImClient::scan_networks(&mut exchange, 0, None, None).await?;
//!         
//!         // Add WiFi credentials
//!         let resp = ImClient::add_or_update_wifi_network(
//!             &mut exchange,
//!             0,
//!             b"MyNetwork",
//!             b"MyPassword123",
//!             None,
//!         ).await?;
//!         
//!         // Connect to the network
//!         let connect_resp = ImClient::connect_network(
//!             &mut exchange,
//!             0,
//!             b"MyNetwork",
//!             None,
//!         ).await?;
//!     }
//!     NetworkType::Thread => {
//!         // Add Thread operational dataset
//!         let resp = ImClient::add_or_update_thread_network(
//!             &mut exchange,
//!             0,
//!             &thread_dataset_tlv,
//!             None,
//!         ).await?;
//!     }
//!     _ => {}
//! }
//! ```

use crate::dm::GlobalElements;
use crate::error::{Error, ErrorCode};
use crate::im::client::{extract_attr_data, extract_cmd_data, ImClient};
use crate::tlv::{FromTLV, Nullable, Octets, TLVBuilderParent, TLVElement, TLVTag, TLVWriteParent};
use crate::transport::exchange::Exchange;
use crate::utils::storage::WriteBuf;

// Re-export Network Commissioning types for convenience
pub use crate::dm::clusters::decl::network_commissioning::{
    // Request builders
    AddOrUpdateThreadNetworkRequestBuilder,
    AddOrUpdateWiFiNetworkRequestBuilder,
    ConnectNetworkRequestBuilder,
    RemoveNetworkRequestBuilder,
    ReorderNetworkRequestBuilder,
    ScanNetworksRequestBuilder,
    // Response wrappers
    ConnectNetworkResponse,
    NetworkConfigResponse,
    ScanNetworksResponse,
    // Scan result struct wrappers
    ThreadInterfaceScanResultStruct,
    WiFiInterfaceScanResultStruct,
    // Enums, IDs, and flags
    AttributeId,
    CommandId,
    Feature,
    NetworkCommissioningStatusEnum,
    NetworkInfoStruct,
    ThreadCapabilitiesBitmap,
    WiFiBandEnum,
    WiFiSecurityBitmap,
};

use crate::dm::clusters::decl::network_commissioning::{
    self, AttributeId as AttrId, CommandId as CmdId
};

/// Network Commissioning cluster ID.
pub const NETWORK_COMMISSIONING_CLUSTER: u32 = network_commissioning::FULL_CLUSTER.id;

/// Matter size restraints
const MAX_SSID_LEN: usize = 32; // Matter spec 11.9.7.3
const MAX_CRED_LEN: usize = 64;
const MAX_OPERATIONAL_DATASET_LEN: usize = 256; // Matter spec 11.9.7.4
const MAX_NETWORK_ID_LEN: usize = 32; // Matter spec 11.9.7.6

/// Network interface type supported by the device.
///
/// Determined by reading the FeatureMap attribute from the
/// Network Commissioning cluster.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum NetworkType {
    /// WiFi network interface - requires SSID and password
    WiFi,
    /// Thread network interface - requires operational dataset
    Thread,
    /// Ethernet network interface - no credentials needed
    Ethernet,
    /// Unknown or unsupported network type
    Unknown,
}

impl NetworkType {
    /// Create a NetworkType from a [`Feature`] bitmap.
    ///
    /// The feature map is read from the FeatureMap attribute (0xFFFC)
    /// of the Network Commissioning cluster.
    ///
    /// # Example
    /// ```ignore
    /// let features = Feature::from_bits_truncate(feature_map);
    /// let net_type = NetworkType::from_features(features);
    /// ```
    pub const fn from_features(features: Feature) -> Self {
        if features.contains(Feature::WI_FI_NETWORK_INTERFACE) {
            NetworkType::WiFi
        } else if features.contains(Feature::THREAD_NETWORK_INTERFACE) {
            NetworkType::Thread
        } else if features.contains(Feature::ETHERNET_NETWORK_INTERFACE) {
            NetworkType::Ethernet
        } else {
            NetworkType::Unknown
        }
    }

    /// Create a NetworkType from raw feature map bits.
    ///
    /// This is a convenience method that converts raw u32 bits to a [`Feature`]
    /// bitmap before determining the network type.
    pub const fn from_feature_map(feature_map: u32) -> Self {
        Self::from_features(Feature::from_bits_truncate(feature_map))
    }

    /// Check if this network type requires wireless credentials.
    pub const fn requires_credentials(&self) -> bool {
        matches!(self, NetworkType::WiFi | NetworkType::Thread)
    }
}

impl ImClient {
    // =========================================================================
    // Network Commissioning Commands
    // =========================================================================

    /// Scan for available networks.
    ///
    /// This command triggers a network scan on the device. For WiFi devices,
    /// an optional SSID can be provided to filter results. The scan may take
    /// up to `ScanMaxTimeSeconds` to complete.
    ///
    /// # Arguments
    /// - `exchange` - An established exchange (PASE or CASE session)
    /// - `endpoint` - Endpoint with Network Commissioning cluster (usually 0)
    /// - `ssid` - Optional SSID to filter results (WiFi only, max 32 bytes)
    /// - `breadcrumb` - Optional breadcrumb for commissioning progress tracking
    ///
    /// # Returns
    /// The scan response containing:
    /// - `networking_status()` - Status of the scan operation
    /// - `debug_text()` - Optional debug information
    /// - `wifi_scan_results()` - WiFi networks found (if WiFi device)
    /// - `thread_scan_results()` - Thread networks found (if Thread device)
    ///
    /// # Stack Usage
    /// Allocates a 64-byte buffer on the stack for TLV encoding.
    pub async fn scan_networks<'a>(
        exchange: &'a mut Exchange<'_>,
        endpoint: u16,
        ssid: Option<&[u8]>,
        breadcrumb: Option<u64>,
    ) -> Result<ScanNetworksResponse<'a>, Error> {
        let mut buf = [0u8; 64];
        let tail = {
            let wb = WriteBuf::new(&mut buf);
            let parent = TLVWriteParent::new((), wb);

            let mut parent = ScanNetworksRequestBuilder::new(parent, &TLVTag::Anonymous)?
                .ssid(ssid.map(|s| Nullable::new(Some(Octets(s)))))?
                .breadcrumb(breadcrumb)?
                .end()?;

            parent.writer().get_tail()
        };
        let cmd_data = TLVElement::new(&buf[..tail]);

        let resp = Self::invoke_single_cmd(
            exchange,
            endpoint,
            NETWORK_COMMISSIONING_CLUSTER,
            CmdId::ScanNetworks as u32,
            cmd_data,
            None,
        )
        .await?;

        let data = extract_cmd_data(&resp)?;
        Ok(ScanNetworksResponse::new(data))
    }

    /// Add or update a WiFi network configuration.
    ///
    /// This command stores WiFi credentials on the device. If a network with
    /// the same SSID already exists, it will be updated. If the network is not
    /// automatically connected, use [`connect_network`](Self::connect_network)
    /// after adding credentials.
    ///
    /// # Arguments
    /// - `exchange` - An established exchange (PASE or CASE session)
    /// - `endpoint` - Endpoint with Network Commissioning cluster (usually 0)
    /// - `ssid` - Network SSID (max 32 bytes)
    /// - `credentials` - Network password (max 64 bytes)
    /// - `breadcrumb` - Optional breadcrumb for commissioning progress tracking
    ///
    /// # Returns
    /// The response containing:
    /// - `networking_status()` - Status of the operation
    /// - `debug_text()` - Optional debug information
    /// - `network_index()` - Index of the added/updated network
    pub async fn add_or_update_wifi_network<'a>(
        exchange: &'a mut Exchange<'_>,
        endpoint: u16,
        ssid: &[u8],
        credentials: &[u8],
        breadcrumb: Option<u64>,
    ) -> Result<NetworkConfigResponse<'a>, Error> {
        // Validate input lengths
        if ssid.len() > MAX_SSID_LEN {
            return Err(ErrorCode::ConstraintError.into());
        }
        if credentials.len() > MAX_CRED_LEN {
            return Err(ErrorCode::ConstraintError.into());
        }

        let mut buf = [0u8; 128]; // SSID(32) + credentials(64) + some TLV overhead
        let tail = {
            let wb = WriteBuf::new(&mut buf);
            let parent = TLVWriteParent::new((), wb);

            let mut parent =
                AddOrUpdateWiFiNetworkRequestBuilder::new(parent, &TLVTag::Anonymous)?
                    .ssid(Octets(ssid))?
                    .credentials(Octets(credentials))?
                    .breadcrumb(breadcrumb)?
                    .network_identity(None)?
                    .client_identifier(None)?
                    .possession_nonce(None)?
                    .end()?;

            parent.writer().get_tail()
        };
        let cmd_data = TLVElement::new(&buf[..tail]);

        let resp = Self::invoke_single_cmd(
            exchange,
            endpoint,
            NETWORK_COMMISSIONING_CLUSTER,
            CmdId::AddOrUpdateWiFiNetwork as u32,
            cmd_data,
            None,
        )
        .await?;

        let data = extract_cmd_data(&resp)?;
        Ok(NetworkConfigResponse::new(data))
    }

    /// Add or update a Thread network configuration.
    ///
    /// This command stores Thread operational dataset on the device. If a
    /// network with the same Extended PAN ID already exists, it will be
    /// updated. If the network is not automatically connected, use
    /// [`connect_network`](Self::connect_network) after adding the dataset.
    ///
    /// # Arguments
    /// - `exchange` - An established exchange (PASE or CASE session)
    /// - `endpoint` - Endpoint with Network Commissioning cluster (usually 0)
    /// - `operational_dataset` - Thread operational dataset TLV (max 254 bytes)
    /// - `breadcrumb` - Optional breadcrumb for commissioning progress tracking
    ///
    /// # Returns
    /// The response containing:
    /// - `networking_status()` - Status of the operation
    /// - `debug_text()` - Optional debug information
    /// - `network_index()` - Index of the added/updated network
    pub async fn add_or_update_thread_network<'a>(
        exchange: &'a mut Exchange<'_>,
        endpoint: u16,
        operational_dataset: &[u8],
        breadcrumb: Option<u64>,
    ) -> Result<NetworkConfigResponse<'a>, Error> {
        // Validate input length per Matter spec
        if operational_dataset.len() > MAX_OPERATIONAL_DATASET_LEN {
            return Err(ErrorCode::ConstraintError.into());
        }

        let mut buf = [0u8; 280]; // Dataset(254) + TLV overhead
        let tail = {
            let wb = WriteBuf::new(&mut buf);
            let parent = TLVWriteParent::new((), wb);

            let mut parent =
                AddOrUpdateThreadNetworkRequestBuilder::new(parent, &TLVTag::Anonymous)?
                    .operational_dataset(Octets(operational_dataset))?
                    .breadcrumb(breadcrumb)?
                    .end()?;

            parent.writer().get_tail()
        };
        let cmd_data = TLVElement::new(&buf[..tail]);

        let resp = Self::invoke_single_cmd(
            exchange,
            endpoint,
            NETWORK_COMMISSIONING_CLUSTER,
            CmdId::AddOrUpdateThreadNetwork as u32,
            cmd_data,
            None,
        )
        .await?;

        let data = extract_cmd_data(&resp)?;
        Ok(NetworkConfigResponse::new(data))
    }

    /// Remove a network configuration from the device.
    ///
    /// This command removes the network with the specified ID. The device
    /// will disconnect from this network if currently connected.
    ///
    /// # Arguments
    /// - `exchange` - An established exchange (PASE or CASE session)
    /// - `endpoint` - Endpoint with Network Commissioning cluster (usually 0)
    /// - `network_id` - Network identifier (SSID for WiFi, Extended PAN ID for Thread)
    /// - `breadcrumb` - Optional breadcrumb for commissioning progress tracking
    ///
    /// # Returns
    /// The response containing:
    /// - `networking_status()` - Status of the operation
    /// - `debug_text()` - Optional debug information
    /// - `network_index()` - Index of the removed network (before removal)
    ///
    /// # Stack Usage
    /// Allocates a 64-byte buffer on the stack for TLV encoding.
    pub async fn remove_network<'a>(
        exchange: &'a mut Exchange<'_>,
        endpoint: u16,
        network_id: &[u8],
        breadcrumb: Option<u64>,
    ) -> Result<NetworkConfigResponse<'a>, Error> {
        // Validate input length per Matter spec
        if network_id.len() > MAX_NETWORK_ID_LEN {
            return Err(ErrorCode::ConstraintError.into());
        }

        let mut buf = [0u8; 64];
        let tail = {
            let wb = WriteBuf::new(&mut buf);
            let parent = TLVWriteParent::new((), wb);

            let mut parent = RemoveNetworkRequestBuilder::new(parent, &TLVTag::Anonymous)?
                .network_id(Octets(network_id))?
                .breadcrumb(breadcrumb)?
                .end()?;

            parent.writer().get_tail()
        };
        let cmd_data = TLVElement::new(&buf[..tail]);

        let resp = Self::invoke_single_cmd(
            exchange,
            endpoint,
            NETWORK_COMMISSIONING_CLUSTER,
            CmdId::RemoveNetwork as u32,
            cmd_data,
            None,
        )
        .await?;

        let data = extract_cmd_data(&resp)?;
        Ok(NetworkConfigResponse::new(data))
    }

    /// Connect to a configured network.
    ///
    /// This command initiates a connection to a previously configured network.
    /// The connection may take up to `ConnectMaxTimeSeconds` to complete.
    ///
    /// # Arguments
    /// - `exchange` - An established exchange (PASE or CASE session)
    /// - `endpoint` - Endpoint with Network Commissioning cluster (usually 0)
    /// - `network_id` - Network identifier (SSID for WiFi, Extended PAN ID for Thread)
    /// - `breadcrumb` - Optional breadcrumb for commissioning progress tracking
    ///
    /// # Returns
    /// The response containing:
    /// - `networking_status()` - Status of the connection attempt
    /// - `debug_text()` - Optional debug information
    /// - `error_value()` - Platform-specific error code on failure
    ///
    /// # Stack Usage
    /// Allocates a 64-byte buffer on the stack for TLV encoding.
    pub async fn connect_network<'a>(
        exchange: &'a mut Exchange<'_>,
        endpoint: u16,
        network_id: &[u8],
        breadcrumb: Option<u64>,
    ) -> Result<ConnectNetworkResponse<'a>, Error> {
        // Validate input length per Matter spec
        if network_id.len() > MAX_NETWORK_ID_LEN {
            return Err(ErrorCode::ConstraintError.into());
        }

        let mut buf = [0u8; 64];
        let tail = {
            let wb = WriteBuf::new(&mut buf);
            let parent = TLVWriteParent::new((), wb);

            let mut parent = ConnectNetworkRequestBuilder::new(parent, &TLVTag::Anonymous)?
                .network_id(Octets(network_id))?
                .breadcrumb(breadcrumb)?
                .end()?;

            parent.writer().get_tail()
        };
        let cmd_data = TLVElement::new(&buf[..tail]);

        let resp = Self::invoke_single_cmd(
            exchange,
            endpoint,
            NETWORK_COMMISSIONING_CLUSTER,
            CmdId::ConnectNetwork as u32,
            cmd_data,
            None,
        )
        .await?;

        let data = extract_cmd_data(&resp)?;
        Ok(ConnectNetworkResponse::new(data))
    }

    /// Reorder a network in the priority list.
    ///
    /// This command changes the priority of a network by moving it to a
    /// new index in the network list. Networks at higher indices have
    /// lower priority.
    ///
    /// # Arguments
    /// - `exchange` - An established exchange (PASE or CASE session)
    /// - `endpoint` - Endpoint with Network Commissioning cluster (usually 0)
    /// - `network_id` - Network identifier (SSID for WiFi, Extended PAN ID for Thread)
    /// - `network_index` - New index for the network (0 = highest priority)
    /// - `breadcrumb` - Optional breadcrumb for commissioning progress tracking
    ///
    /// # Returns
    /// The response containing:
    /// - `networking_status()` - Status of the operation
    /// - `debug_text()` - Optional debug information
    /// - `network_index()` - New index of the network
    ///
    /// # Stack Usage
    /// Allocates a 64-byte buffer on the stack for TLV encoding.
    pub async fn reorder_network<'a>(
        exchange: &'a mut Exchange<'_>,
        endpoint: u16,
        network_id: &[u8],
        network_index: u8,
        breadcrumb: Option<u64>,
    ) -> Result<NetworkConfigResponse<'a>, Error> {
        // Validate input length per Matter spec
        if network_id.len() > 32 {
            return Err(ErrorCode::ConstraintError.into());
        }

        let mut buf = [0u8; 64];
        let tail = {
            let wb = WriteBuf::new(&mut buf);
            let parent = TLVWriteParent::new((), wb);

            let mut parent = ReorderNetworkRequestBuilder::new(parent, &TLVTag::Anonymous)?
                .network_id(Octets(network_id))?
                .network_index(network_index)?
                .breadcrumb(breadcrumb)?
                .end()?;

            parent.writer().get_tail()
        };
        let cmd_data = TLVElement::new(&buf[..tail]);

        let resp = Self::invoke_single_cmd(
            exchange,
            endpoint,
            NETWORK_COMMISSIONING_CLUSTER,
            CmdId::ReorderNetwork as u32,
            cmd_data,
            None,
        )
        .await?;

        let data = extract_cmd_data(&resp)?;
        Ok(NetworkConfigResponse::new(data))
    }

    /// Detect the network type supported by the device.
    ///
    /// Reads the FeatureMap attribute to determine whether the device
    /// supports WiFi, Thread, or Ethernet networking.
    ///
    /// # Arguments
    /// - `exchange` - An established exchange (PASE or CASE session)
    /// - `endpoint` - Endpoint with Network Commissioning cluster (usually 0)
    ///
    /// # Returns
    /// The detected [`NetworkType`].
    pub async fn detect_network_type(
        exchange: &mut Exchange<'_>,
        endpoint: u16,
    ) -> Result<NetworkType, Error> {
        let resp = Self::read_single_attr(
            exchange,
            endpoint,
            NETWORK_COMMISSIONING_CLUSTER,
            GlobalElements::FeatureMap as u32,
            false,
        )
        .await?;

        let data = extract_attr_data(&resp)?;
        let feature_map: u32 = data.u32()?;
        Ok(NetworkType::from_feature_map(feature_map))
    }

    /// Read the maximum number of networks the device can store.
    ///
    /// # Arguments
    /// - `exchange` - An established exchange (PASE or CASE session)
    /// - `endpoint` - Endpoint with Network Commissioning cluster (usually 0)
    ///
    /// # Returns
    /// The maximum number of network configurations.
    pub async fn read_max_networks(
        exchange: &mut Exchange<'_>,
        endpoint: u16,
    ) -> Result<u8, Error> {
        let resp = Self::read_single_attr(
            exchange,
            endpoint,
            NETWORK_COMMISSIONING_CLUSTER,
            AttrId::MaxNetworks as u32,
            false,
        )
        .await?;

        let data = extract_attr_data(&resp)?;
        data.u8()
    }

    /// Read the list of configured networks.
    ///
    /// Returns a wrapper around the Networks attribute that provides
    /// an iterator over `NetworkInfoStruct` entries.
    ///
    /// # Arguments
    /// - `exchange` - An established exchange (PASE or CASE session)
    /// - `endpoint` - Endpoint with Network Commissioning cluster (usually 0)
    ///
    /// # Returns
    /// A TLV element containing the array of network info structs.
    /// Use `TLVElement::array()` to iterate over the results.
    pub async fn read_networks<'a>(
        exchange: &'a mut Exchange<'_>,
        endpoint: u16,
    ) -> Result<TLVElement<'a>, Error> {
        let resp = Self::read_single_attr(
            exchange,
            endpoint,
            NETWORK_COMMISSIONING_CLUSTER,
            AttrId::Networks as u32,
            false,
        )
        .await?;

        extract_attr_data(&resp)
    }

    /// Read the maximum time in seconds for a network scan.
    ///
    /// # Arguments
    /// - `exchange` - An established exchange (PASE or CASE session)
    /// - `endpoint` - Endpoint with Network Commissioning cluster (usually 0)
    ///
    /// # Returns
    /// The scan timeout in seconds (typically 10).
    pub async fn read_scan_max_time_seconds(
        exchange: &mut Exchange<'_>,
        endpoint: u16,
    ) -> Result<u8, Error> {
        let resp = Self::read_single_attr(
            exchange,
            endpoint,
            NETWORK_COMMISSIONING_CLUSTER,
            AttrId::ScanMaxTimeSeconds as u32,
            false,
        )
        .await?;

        let data = extract_attr_data(&resp)?;
        data.u8()
    }

    /// Read the maximum time in seconds for a network connection attempt.
    ///
    /// # Arguments
    /// - `exchange` - An established exchange (PASE or CASE session)
    /// - `endpoint` - Endpoint with Network Commissioning cluster (usually 0)
    ///
    /// # Returns
    /// The connect timeout in seconds (typically 30).
    pub async fn read_connect_max_time_seconds(
        exchange: &mut Exchange<'_>,
        endpoint: u16,
    ) -> Result<u8, Error> {
        let resp = Self::read_single_attr(
            exchange,
            endpoint,
            NETWORK_COMMISSIONING_CLUSTER,
            AttrId::ConnectMaxTimeSeconds as u32,
            false,
        )
        .await?;

        let data = extract_attr_data(&resp)?;
        data.u8()
    }

    /// Read whether the network interface is enabled.
    ///
    /// # Arguments
    /// - `exchange` - An established exchange (PASE or CASE session)
    /// - `endpoint` - Endpoint with Network Commissioning cluster (usually 0)
    ///
    /// # Returns
    /// `true` if the interface is enabled.
    pub async fn read_interface_enabled(
        exchange: &mut Exchange<'_>,
        endpoint: u16,
    ) -> Result<bool, Error> {
        let resp = Self::read_single_attr(
            exchange,
            endpoint,
            NETWORK_COMMISSIONING_CLUSTER,
            AttrId::InterfaceEnabled as u32,
            false,
        )
        .await?;

        let data = extract_attr_data(&resp)?;
        data.bool()
    }

    /// Read the status of the last networking operation.
    ///
    /// # Arguments
    /// - `exchange` - An established exchange (PASE or CASE session)
    /// - `endpoint` - Endpoint with Network Commissioning cluster (usually 0)
    ///
    /// # Returns
    /// The last networking status, or `None` if no operation has been performed.
    pub async fn read_last_networking_status(
        exchange: &mut Exchange<'_>,
        endpoint: u16,
    ) -> Result<Option<NetworkCommissioningStatusEnum>, Error> {
        let resp = Self::read_single_attr(
            exchange,
            endpoint,
            NETWORK_COMMISSIONING_CLUSTER,
            AttrId::LastNetworkingStatus as u32,
            false,
        )
        .await?;

        let data = extract_attr_data(&resp)?;
        let nullable: Nullable<NetworkCommissioningStatusEnum> = Nullable::from_tlv(&data)?;
        Ok(nullable.into_option())
    }

    /// Read the network ID of the last networking operation.
    ///
    /// Returns the raw TLV element which may be null. Use `TLVElement::is_null()`
    /// to check, then `TLVElement::octet_string()` to get the value.
    ///
    /// # Arguments
    /// - `exchange` - An established exchange (PASE or CASE session)
    /// - `endpoint` - Endpoint with Network Commissioning cluster (usually 0)
    ///
    /// # Returns
    /// A TLV element containing the nullable network ID.
    pub async fn read_last_network_id<'a>(
        exchange: &'a mut Exchange<'_>,
        endpoint: u16,
    ) -> Result<TLVElement<'a>, Error> {
        let resp = Self::read_single_attr(
            exchange,
            endpoint,
            NETWORK_COMMISSIONING_CLUSTER,
            AttrId::LastNetworkID as u32,
            false,
        )
        .await?;

        extract_attr_data(&resp)
    }

    /// Read the error value from the last connection attempt.
    ///
    /// # Arguments
    /// - `exchange` - An established exchange (PASE or CASE session)
    /// - `endpoint` - Endpoint with Network Commissioning cluster (usually 0)
    ///
    /// # Returns
    /// The platform-specific error code, or `None` if no error occurred.
    pub async fn read_last_connect_error_value(
        exchange: &mut Exchange<'_>,
        endpoint: u16,
    ) -> Result<Option<i32>, Error> {
        let resp = Self::read_single_attr(
            exchange,
            endpoint,
            NETWORK_COMMISSIONING_CLUSTER,
            AttrId::LastConnectErrorValue as u32,
            false,
        )
        .await?;

        let data = extract_attr_data(&resp)?;
        let nullable: Nullable<i32> = Nullable::from_tlv(&data)?;
        Ok(nullable.into_option())
    }
}

