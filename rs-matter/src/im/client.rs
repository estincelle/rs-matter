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

//! Interaction Model Client implementation.
//!
//! This module provides client-side functionality for sending IM requests
//! (Read, Write, Invoke) to Matter devices and processing their responses.

use crate::error::{Error, ErrorCode};
use crate::tlv::{FromTLV, TLVElement, TagType, ToTLV};
use crate::transport::exchange::Exchange;

use super::{
    AttrData, AttrPath, AttrResp, CmdData, CmdPath, CmdResp, DataVersionFilter, EventFilter,
    EventPath, IMStatusCode, InvokeResp, OpCode, ReportDataResp, StatusResp, TimedReq, WriteResp,
};

/// Builder for constructing ReadRequest messages.
///
/// Corresponds to the `ReadRequestMessage` TLV structure in the Interaction Model.
#[derive(Debug, Clone, ToTLV)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[tlvargs(lifetime = "'a")]
pub struct ReadRequestBuilder<'a> {
    /// Attribute paths to read
    pub attr_requests: Option<&'a [AttrPath]>,
    /// Event paths to read
    pub event_requests: Option<&'a [EventPath]>,
    /// Event filters
    pub event_filters: Option<&'a [EventFilter]>,
    /// Whether to filter by fabric
    pub fabric_filtered: bool,
    /// Data version filters for conditional reads
    pub dataver_filters: Option<&'a [DataVersionFilter]>,
}

impl<'a> ReadRequestBuilder<'a> {
    /// Create a new ReadRequestBuilder for reading attributes
    pub const fn attributes(attr_requests: &'a [AttrPath], fabric_filtered: bool) -> Self {
        Self {
            attr_requests: Some(attr_requests),
            event_requests: None,
            event_filters: None,
            fabric_filtered,
            dataver_filters: None,
        }
    }
}

/// Builder for constructing WriteRequest messages.
///
/// Corresponds to the `WriteRequestMessage` TLV structure in the Interaction Model.
#[derive(Debug, Clone, ToTLV)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[tlvargs(lifetime = "'a")]
pub struct WriteRequestBuilder<'a> {
    /// Whether to suppress the response
    pub suppress_response: Option<bool>,
    /// Whether this is a timed request
    pub timed_request: Option<bool>,
    /// Attribute data to write
    pub write_requests: &'a [AttrData<'a>],
    /// Whether there are more chunks coming
    pub more_chunks: Option<bool>,
}

impl<'a> WriteRequestBuilder<'a> {
    /// Create a new WriteRequestBuilder
    pub const fn new(write_requests: &'a [AttrData<'a>], timed: bool) -> Self {
        Self {
            suppress_response: None,
            timed_request: if timed { Some(true) } else { None },
            write_requests,
            more_chunks: None,
        }
    }
}

/// Builder for constructing InvokeRequest messages.
///
/// Corresponds to the `InvokeRequestMessage` TLV structure in the Interaction Model.
#[derive(Debug, Clone, ToTLV)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
#[tlvargs(lifetime = "'a")]
pub struct InvokeRequestBuilder<'a> {
    /// Whether to suppress the response
    pub suppress_response: Option<bool>,
    /// Whether this is a timed request
    pub timed_request: Option<bool>,
    /// Command invocations
    pub invoke_requests: &'a [CmdData<'a>],
}

impl<'a> InvokeRequestBuilder<'a> {
    /// Create a new InvokeRequestBuilder
    pub const fn new(invoke_requests: &'a [CmdData<'a>], timed: bool) -> Self {
        Self {
            suppress_response: None,
            timed_request: if timed { Some(true) } else { None },
            invoke_requests,
        }
    }
}

/// IM Client for sending requests to Matter devices.
///
/// This struct provides methods for sending Read, Write, and Invoke requests
/// over an established exchange (either PASE or CASE session).
///
/// # Example
///
/// ```ignore
/// // Read an attribute
/// let attr_path = AttrPath {
///     endpoint: Some(1),
///     cluster: Some(0x0006), // OnOff cluster
///     attr: Some(0x0000),    // OnOff attribute
///     ..Default::default()
/// };
/// let report = ImClient::read(exchange, &[attr_path], true).await?;
/// ```
pub struct ImClient;

impl ImClient {
    /// Read attributes from a device.
    ///
    /// Sends a ReadRequest and returns the ReportData response containing
    /// the requested attribute values.
    ///
    /// # Arguments
    /// - `exchange` - An established exchange (PASE or CASE session)
    /// - `attr_paths` - Attribute paths to read
    /// - `fabric_filtered` - Whether to filter results by fabric
    ///
    /// # Returns
    /// The parsed ReportData response, or an error if the request failed.
    pub async fn read<'a>(
        exchange: &'a mut Exchange<'_>,
        attr_paths: &[AttrPath],
        fabric_filtered: bool,
    ) -> Result<ReportDataResp<'a>, Error> {
        let req = ReadRequestBuilder::attributes(attr_paths, fabric_filtered);

        // Send ReadRequest
        exchange
            .send_with(|_, wb| {
                req.to_tlv(&TagType::Anonymous, wb)?;
                Ok(Some(OpCode::ReadRequest.into()))
            })
            .await?;

        // Receive ReportData
        exchange.recv_fetch().await?;

        // Check opcode and extract suppress_response flag before borrowing payload
        let suppress_response = {
            let rx = exchange.rx()?;
            Self::check_opcode(rx.meta().proto_opcode, OpCode::ReportData)?;

            // Quick check for suppress_response flag (parse TLV to extract it)
            let element = TLVElement::new(rx.payload());
            let resp = ReportDataResp::from_tlv(&element)?;
            resp.suppress_response.unwrap_or(false)
        };

        // Send StatusResponse if not suppressed
        if !suppress_response {
            exchange
                .send_with(|_, wb| {
                    StatusResp::write(wb, IMStatusCode::Success)?;
                    Ok(Some(OpCode::StatusResponse.into()))
                })
                .await?;
        }

        // Re-parse the response for return (the rx buffer is still valid)
        let rx = exchange.rx()?;
        let resp = ReportDataResp::from_tlv(&TLVElement::new(rx.payload()))?;

        Ok(resp)
    }

    /// Invoke a command on a device.
    ///
    /// Sends an InvokeRequest and returns the InvokeResponse containing
    /// the command results.
    ///
    /// # Arguments
    /// - `exchange` - An established exchange (PASE or CASE session)
    /// - `cmd_data` - Command data to invoke
    /// - `timed_timeout_ms` - Optional timeout for timed invoke (required for some commands)
    ///
    /// # Returns
    /// The parsed InvokeResponse, or an error if the request failed.
    pub async fn invoke<'a>(
        exchange: &'a mut Exchange<'_>,
        cmd_data: &[CmdData<'_>],
        timed_timeout_ms: Option<u16>,
    ) -> Result<InvokeResp<'a>, Error> {
        // If timed, send TimedRequest first
        if let Some(timeout_ms) = timed_timeout_ms {
            Self::send_timed_request(exchange, timeout_ms).await?;
        }

        let req = InvokeRequestBuilder::new(cmd_data, timed_timeout_ms.is_some());

        // Send InvokeRequest
        exchange
            .send_with(|_, wb| {
                req.to_tlv(&TagType::Anonymous, wb)?;
                Ok(Some(OpCode::InvokeRequest.into()))
            })
            .await?;

        // Receive InvokeResponse
        exchange.recv_fetch().await?;

        let rx = exchange.rx()?;
        Self::check_opcode(rx.meta().proto_opcode, OpCode::InvokeResponse)?;

        // Parse response
        let resp = InvokeResp::from_tlv(&TLVElement::new(rx.payload()))?;

        Ok(resp)
    }

    /// Write attributes to a device.
    ///
    /// Sends a WriteRequest and returns the WriteResponse containing
    /// the status of each write operation.
    ///
    /// # Arguments
    /// - `exchange` - An established exchange (PASE or CASE session)
    /// - `attr_data` - Attribute data to write
    /// - `timed_timeout_ms` - Optional timeout for timed write (required for some attributes)
    ///
    /// # Returns
    /// The parsed WriteResponse, or an error if the request failed.
    pub async fn write<'a>(
        exchange: &'a mut Exchange<'_>,
        attr_data: &[AttrData<'_>],
        timed_timeout_ms: Option<u16>,
    ) -> Result<WriteResp<'a>, Error> {
        // If timed, send TimedRequest first
        if let Some(timeout_ms) = timed_timeout_ms {
            Self::send_timed_request(exchange, timeout_ms).await?;
        }

        let req = WriteRequestBuilder::new(attr_data, timed_timeout_ms.is_some());

        // Send WriteRequest
        exchange
            .send_with(|_, wb| {
                req.to_tlv(&TagType::Anonymous, wb)?;
                Ok(Some(OpCode::WriteRequest.into()))
            })
            .await?;

        // Receive WriteResponse
        exchange.recv_fetch().await?;

        let rx = exchange.rx()?;
        Self::check_opcode(rx.meta().proto_opcode, OpCode::WriteResponse)?;

        // Parse response
        let resp = WriteResp::from_tlv(&TLVElement::new(rx.payload()))?;

        Ok(resp)
    }

    /// Send a timed request and wait for the status response.
    ///
    /// This is used before timed write or invoke operations.
    async fn send_timed_request(exchange: &mut Exchange<'_>, timeout_ms: u16) -> Result<(), Error> {
        let req = TimedReq {
            timeout: timeout_ms,
        };

        // Send TimedRequest
        exchange
            .send_with(|_, wb| {
                req.to_tlv(&TagType::Anonymous, wb)?;
                Ok(Some(OpCode::TimedRequest.into()))
            })
            .await?;

        // Receive StatusResponse
        exchange.recv_fetch().await?;

        let rx = exchange.rx()?;
        Self::check_opcode(rx.meta().proto_opcode, OpCode::StatusResponse)?;

        // Parse and check status
        let status_resp = StatusResp::from_tlv(&TLVElement::new(rx.payload()))?;
        if status_resp.status != IMStatusCode::Success {
            error!("TimedRequest failed with status: {:?}", status_resp.status);
            return Err(ErrorCode::InvalidData.into());
        }

        Ok(())
    }

    /// Check that the received opcode matches the expected one.
    fn check_opcode(received: u8, expected: OpCode) -> Result<(), Error> {
        if received != expected as u8 {
            error!(
                "Unexpected IM opcode: received {}, expected {:?}",
                received, expected
            );
            Err(ErrorCode::InvalidOpcode.into())
        } else {
            Ok(())
        }
    }
}

// Convenience type aliases for common use cases
pub use super::{AttrId, ClusterId, EndptId};

/// Extension methods for easier single-item operations
impl ImClient {
    /// Read a single attribute from a device.
    ///
    /// This is a convenience method that wraps `read()` for the common case
    /// of reading a single attribute.
    ///
    /// # Returns
    /// The first attribute response, or an error if none was returned.
    pub async fn read_single<'a>(
        exchange: &'a mut Exchange<'_>,
        endpoint: EndptId,
        cluster: ClusterId,
        attr: AttrId,
        fabric_filtered: bool,
    ) -> Result<AttrResp<'a>, Error> {
        let path = AttrPath {
            endpoint: Some(endpoint),
            cluster: Some(cluster),
            attr: Some(attr),
            ..Default::default()
        };

        let report = Self::read(exchange, &[path], fabric_filtered).await?;

        // Extract the first attribute report
        let attr_reports = report.attr_reports.ok_or(ErrorCode::InvalidData)?;
        attr_reports
            .iter()
            .next()
            .ok_or(ErrorCode::InvalidData)?
            .map_err(|_| ErrorCode::InvalidData.into())
    }

    /// Invoke a single command on a device.
    ///
    /// This is a convenience method that wraps `invoke()` for the common case
    /// of invoking a single command.
    ///
    /// # Returns
    /// The first command response, or an error if none was returned.
    pub async fn invoke_single<'a>(
        exchange: &'a mut Exchange<'_>,
        endpoint: EndptId,
        cluster: ClusterId,
        cmd: u32,
        cmd_data: TLVElement<'_>,
        timed_timeout_ms: Option<u16>,
    ) -> Result<CmdResp<'a>, Error> {
        let path = CmdPath {
            endpoint: Some(endpoint),
            cluster: Some(cluster),
            cmd: Some(cmd),
        };

        let data = CmdData {
            path,
            data: cmd_data,
        };

        let resp = Self::invoke(exchange, &[data], timed_timeout_ms).await?;

        // Extract the first invoke response
        let invoke_responses = resp.invoke_responses.ok_or(ErrorCode::InvalidData)?;
        invoke_responses
            .iter()
            .next()
            .ok_or(ErrorCode::InvalidData)?
            .map_err(|_| ErrorCode::InvalidData.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::storage::WriteBuf;

    #[test]
    fn test_read_request_encoding() {
        let path = AttrPath {
            endpoint: Some(1),
            cluster: Some(0x0006),
            attr: Some(0x0000),
            ..Default::default()
        };

        let paths = [path];
        let req = ReadRequestBuilder::attributes(&paths, true);

        let mut buf = [0u8; 128];
        let mut wb = WriteBuf::new(&mut buf);
        req.to_tlv(&TagType::Anonymous, &mut wb).unwrap();

        assert!(!wb.as_slice().is_empty());
    }

    #[test]
    fn test_invoke_request_encoding() {
        let path = CmdPath {
            endpoint: Some(1),
            cluster: Some(0x0006),
            cmd: Some(0x02), // Toggle
        };

        let data = CmdData {
            path,
            data: TLVElement::new(&[]),
        };

        let cmds = [data];
        let req = InvokeRequestBuilder::new(&cmds, false);

        let mut buf = [0u8; 128];
        let mut wb = WriteBuf::new(&mut buf);
        req.to_tlv(&TagType::Anonymous, &mut wb).unwrap();

        assert!(!wb.as_slice().is_empty());
    }

    #[test]
    fn test_write_request_encoding() {
        let path = AttrPath {
            endpoint: Some(1),
            cluster: Some(0x0006),
            attr: Some(0x0000),
            ..Default::default()
        };

        let data = AttrData {
            data_ver: None,
            path,
            data: TLVElement::new(&[]),
        };

        let attrs = [data];
        let req = WriteRequestBuilder::new(&attrs, false);

        let mut buf = [0u8; 128];
        let mut wb = WriteBuf::new(&mut buf);
        req.to_tlv(&TagType::Anonymous, &mut wb).unwrap();

        assert!(!wb.as_slice().is_empty());
    }
}
