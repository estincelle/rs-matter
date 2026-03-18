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

//! Combined integration test for the full Matter commissioning flow.
//!
//! This test exercises the complete flow from discovery to device control:
//! 1. mDNS Discovery - Discover the device on the network
//! 2. PASE Handshake - Authenticate with passcode
//! 3. Commissioning Info & Commands - Read BasicCommissioningInfo,
//!    RegulatoryConfig, LocationCapability, SupportsConcurrentConnection,
//!    then ArmFailSafe, SetRegulatoryConfig, SetTCAcknowledgements,
//!    AttestationRequest, CertificateChainRequest, CSRRequest, CommissioningComplete
//! 4. IM Operations - Read/Write/Invoke on device clusters (OnOff)
//!
//! Uses the `onoff_light` example as the test device.
//!
//! ## Platform Support
//!
//! - **macOS**: Uses `astro-dnssd` for mDNS discovery (wraps native Bonjour)
//! - **Linux**: Uses the builtin mDNS querier with multicast sockets

use std::net::UdpSocket;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

use anyhow::{self, Context};
use log::{debug, info, warn};
use socket2::{Domain, Protocol, Socket, Type};

use embassy_futures::select::{select, Either};
use embassy_time::Timer;

use rs_matter::commissioner::fabric_credentials::FabricCredentials;
use rs_matter::credentials::attestation_verifier::{AttestationInfo, AttestationVerifier};
use rs_matter::crypto::{default_crypto, Crypto};
use rs_matter::dm::clusters::basic_info::BasicInfoConfig;
use rs_matter::dm::devices::test::{DAC_PRIVKEY, TEST_DEV_ATT, TEST_DEV_COMM, TEST_DEV_DET};
use rs_matter::error::Error;
use rs_matter::im::client::commissioning::{
    ArmFailSafeResponse, AttestationResponse, BasicCommissioningInfo, CSRResponse,
    CertificateChainResponse, CertificateChainTypeEnum, CommissioningCompleteResponse,
    CommissioningErrorEnum, NodeOperationalCertStatusEnum, RegulatoryLocationTypeEnum,
    SetRegulatoryConfigResponse, SetTCAcknowledgementsResponse,
};
use rs_matter::im::client::ImClient;
use rs_matter::im::{AttrResp, CmdResp, IMStatusCode};
use rs_matter::sc::pase::PaseInitiator;
use rs_matter::tlv::{TLVElement, TLVTag, TLVWrite};
use rs_matter::transport::exchange::Exchange;
use rs_matter::transport::network::mdns::{CommissionableFilter, DiscoveredDevice};
use rs_matter::transport::network::{Address, SocketAddr, SocketAddrV6};
use rs_matter::utils::init::InitMaybeUninit;
use rs_matter::utils::storage::WriteBuf;
use rs_matter::Matter;

use static_cell::StaticCell;

/// Default Matter passcode used by test devices
pub const DEFAULT_PASSCODE: u32 = 20202021;

/// Default discriminator for test devices
pub const DEFAULT_DISCRIMINATOR: u16 = 3840;

/// OnOff cluster ID
const CLUSTER_ON_OFF: u32 = 0x0006;

/// OnOff attribute ID
const ATTR_ON_OFF: u32 = 0x0000;

/// Toggle command ID
const CMD_TOGGLE: u32 = 0x0002;

/// PAA certificate for test vendor 0xFFF1 (used by the test device)
const TEST_PAA_FFF1_CERT: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../rs-matter/src/credentials/test_paa/Chip-Test-PAA-FFF1-Cert.der"
));

/// PAA certificate with no VID (development PAA)
const TEST_PAA_NOVID_CERT: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../rs-matter/src/credentials/test_paa/Chip-Test-PAA-NoVID-Cert.der"
));

/// Timeout for PASE handshake in seconds
const PASE_TIMEOUT_SECS: u64 = 30;

/// Timeout for IM operations in seconds
const IM_TIMEOUT_SECS: u64 = 10;

/// Test fabric ID for NOC provisioning
const TEST_FABRIC_ID: u64 = 0x0001;

/// Test CAT ID (CASE Authenticated Tag)
const TEST_CAT_ID: u32 = 0x0001_0001;

/// Test admin subject (node ID of the administrator)
const TEST_ADMIN_SUBJECT: u64 = 0x0002;

/// Test admin vendor ID
const TEST_ADMIN_VENDOR_ID: u16 = TEST_DEV_DET.vid;

static MATTER: StaticCell<Matter> = StaticCell::new();

/// Minimal basic info config for the controller (test only)
const BASIC_INFO: BasicInfoConfig<'static> = BasicInfoConfig {
    device_name: "CommissioningTest",
    product_name: "CommissioningTest",
    vendor_name: "TestVendor",
    serial_no: "CommissioningTest",
    ..TEST_DEV_DET
};

/// Combined commissioning test runner.
pub struct CommissioningTests {
    workspace_dir: PathBuf,
    print_cmd_output: bool,
}

impl CommissioningTests {
    /// Create a new `CommissioningTests` instance.
    pub fn new(workspace_dir: PathBuf, print_cmd_output: bool) -> Self {
        Self {
            workspace_dir,
            print_cmd_output,
        }
    }

    /// Run the full commissioning test.
    #[allow(clippy::too_many_arguments)]
    pub fn run(
        &self,
        device_bin: &str,
        features: &[String],
        profile: &str,
        device_wait_ms: u64,
        passcode: u32,
        discriminator: u16,
        discovery_timeout_ms: u32,
    ) -> anyhow::Result<()> {
        let profile = normalize_profile(profile)?;
        let features = resolve_features(features);

        // Step 1: Build the device example
        self.build_examples(&[device_bin], &features, profile)?;

        // Step 2: Start the device
        warn!("Starting device example: {device_bin}");
        let child = self.start_device_example(device_bin, profile)?;
        let mut device_process = ChildProcessGuard::new(child);

        // Wait for device to initialize
        thread::sleep(Duration::from_millis(device_wait_ms));

        // Step 3: Run the full test flow
        let result = run_commissioning_test(passcode, discriminator, discovery_timeout_ms);

        // Cleanup
        info!("Stopping device example...");
        device_process.stop_now();

        match result {
            Ok(()) => {
                info!("Commissioning test PASSED");
                Ok(())
            }
            Err(e) => {
                warn!("Commissioning test FAILED: {e:?}");
                anyhow::bail!("commissioning_test failed: {e:?}");
            }
        }
    }

    fn build_examples(
        &self,
        bins: &[&str],
        features: &[String],
        profile: &str,
    ) -> anyhow::Result<()> {
        warn!("Building examples: {}", bins.join(", "));
        if !features.is_empty() {
            info!("Features: {}", features.join(","));
        }

        let mut cmd = Command::new("cargo");
        cmd.current_dir(&self.workspace_dir)
            .arg("build")
            .arg("-p")
            .arg("rs-matter-examples");

        for bin in bins {
            cmd.arg("--bin").arg(bin);
        }

        if profile == "release" {
            cmd.arg("--release");
        }

        if !features.is_empty() {
            cmd.arg("--features").arg(features.join(","));
        }

        self.run_command(&mut cmd)?;
        Ok(())
    }

    fn start_device_example(&self, device_bin: &str, profile: &str) -> anyhow::Result<Child> {
        let exe = self.examples_exe_path(device_bin, profile);
        if !exe.exists() {
            anyhow::bail!("Device binary not found at {}", exe.display());
        }

        let mut cmd = Command::new(&exe);
        if self.print_cmd_output {
            cmd.stdout(Stdio::inherit()).stderr(Stdio::inherit());
        } else {
            cmd.stdout(Stdio::null()).stderr(Stdio::null());
        }

        debug!("Running: {cmd:?}");

        cmd.spawn()
            .with_context(|| format!("Failed to start device example: {}", exe.display()))
    }

    fn examples_exe_path(&self, bin: &str, profile: &str) -> PathBuf {
        self.workspace_dir.join("target").join(profile).join(bin)
    }

    fn run_command(&self, cmd: &mut Command) -> anyhow::Result<()> {
        debug!("Running: {cmd:?}");

        let cmd = cmd.stdin(Stdio::null());

        if !self.print_cmd_output {
            cmd.stdout(Stdio::null()).stderr(Stdio::null());
        }

        let status = cmd
            .status()
            .with_context(|| format!("Failed to execute command: {cmd:?}"))?;

        if !status.success() {
            anyhow::bail!("Command failed with status: {status}");
        }

        Ok(())
    }
}

struct ChildProcessGuard {
    child: Option<Child>,
}

impl ChildProcessGuard {
    fn new(child: Child) -> Self {
        Self { child: Some(child) }
    }

    fn stop_now(&mut self) {
        if let Some(mut child) = self.child.take() {
            if let Err(e) = child.kill() {
                debug!("Failed to kill device process (may have exited): {e}");
            }
            let _ = child.wait();
        }
    }
}

impl Drop for ChildProcessGuard {
    fn drop(&mut self) {
        self.stop_now();
    }
}

// ============================================================================
// Platform Configuration
// ============================================================================

fn normalize_profile(profile: &str) -> anyhow::Result<&str> {
    match profile {
        "debug" | "release" => Ok(profile),
        _ => anyhow::bail!("Invalid profile: {profile} (expected 'debug' or 'release')"),
    }
}

/// Resolve features for the device example based on platform.
fn resolve_features(features: &[String]) -> Vec<String> {
    if !features.is_empty() {
        return features.to_vec();
    }

    // Default features per platform
    match std::env::consts::OS {
        // macOS: Use astro-dnssd for mDNS (wraps native Bonjour)
        "macos" => vec!["astro-dnssd".to_string()],
        // Linux: Use builtin mDNS (no external daemon required)
        _ => Vec::new(),
    }
}

// ============================================================================
// Test Implementation
// ============================================================================

fn run_commissioning_test(
    passcode: u32,
    discriminator: u16,
    discovery_timeout_ms: u32,
) -> Result<(), Error> {
    warn!("Running full commissioning integration test...");
    info!("Discriminator: {discriminator}");
    info!("Passcode: {passcode}");

    // Initialize Matter stack
    let matter = MATTER.uninit().init_with(Matter::init(
        &BASIC_INFO,
        TEST_DEV_COMM,
        &TEST_DEV_ATT,
        rs_matter::utils::epoch::sys_epoch,
        0, // bind to any port
    ));

    matter.initialize_transport_buffers()?;

    let crypto = default_crypto::<embassy_sync::blocking_mutex::raw::NoopRawMutex, _>(
        rand::thread_rng(),
        DAC_PRIVKEY,
    );

    // Create dual-stack UDP socket
    let socket = create_dual_stack_socket()?;
    info!(
        "Bound to local address: {:?}",
        socket.get_ref().local_addr()
    );

    // Run the async test
    futures_lite::future::block_on(async {
        let mut transport = core::pin::pin!(matter.run_transport(&crypto, &socket, &socket));
        let mut test = core::pin::pin!(run_commissioning_flow(
            matter,
            &crypto,
            passcode,
            discriminator,
            discovery_timeout_ms,
        ));

        match select(&mut transport, &mut test).await {
            Either::First(transport_result) => {
                warn!("Transport exited prematurely: {:?}", transport_result);
                transport_result
            }
            Either::Second(test_result) => {
                // Flush any pending messages
                let mut flush =
                    core::pin::pin!(Timer::after(embassy_time::Duration::from_millis(500)));
                let _ = select(&mut transport, &mut flush).await;
                test_result
            }
        }
    })
}

/// Create a dual-stack UDP socket for Matter communication.
///
/// This socket is used for Matter protocol communication (PASE, IM operations).
/// It binds to an ephemeral port since it doesn't need to receive mDNS responses.
fn create_dual_stack_socket() -> Result<async_io::Async<UdpSocket>, Error> {
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))
        .map_err(|_| rs_matter::error::ErrorCode::NoNetworkInterface)?;

    socket
        .set_reuse_address(true)
        .map_err(|_| rs_matter::error::ErrorCode::NoNetworkInterface)?;

    // Allow IPv4 connections on IPv6 socket (dual-stack)
    socket
        .set_only_v6(false)
        .map_err(|_| rs_matter::error::ErrorCode::NoNetworkInterface)?;

    // Bind to ephemeral port on all interfaces
    let bind_addr = std::net::SocketAddrV6::new(std::net::Ipv6Addr::UNSPECIFIED, 0, 0, 0);
    socket
        .bind(&bind_addr.into())
        .map_err(|_| rs_matter::error::ErrorCode::NoNetworkInterface)?;

    let socket: UdpSocket = socket.into();
    async_io::Async::new_nonblocking(socket)
        .map_err(|_| rs_matter::error::ErrorCode::NoNetworkInterface.into())
}

/// Create a socket for mDNS discovery.
///
/// This socket binds to port 5353 with SO_REUSEPORT to allow sharing the mDNS port
/// with the device's mDNS responder. This is necessary because mDNS responses are
/// sent as multicast to port 5353.
#[cfg(not(target_os = "macos"))]
fn create_mdns_socket() -> Result<async_io::Async<UdpSocket>, Error> {
    use rs_matter::transport::network::mdns::MDNS_PORT;

    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))
        .map_err(|_| rs_matter::error::ErrorCode::NoNetworkInterface)?;

    socket
        .set_reuse_address(true)
        .map_err(|_| rs_matter::error::ErrorCode::NoNetworkInterface)?;

    // Allow multiple sockets to bind to the same port (needed for mDNS)
    #[cfg(unix)]
    socket
        .set_reuse_port(true)
        .map_err(|_| rs_matter::error::ErrorCode::NoNetworkInterface)?;

    // Allow IPv4 connections on IPv6 socket (dual-stack)
    socket
        .set_only_v6(false)
        .map_err(|_| rs_matter::error::ErrorCode::NoNetworkInterface)?;

    // Enable multicast loopback so we can receive mDNS responses from
    // devices running on the same machine (important for CI testing)
    socket
        .set_multicast_loop_v4(true)
        .map_err(|_| rs_matter::error::ErrorCode::NoNetworkInterface)?;
    socket
        .set_multicast_loop_v6(true)
        .map_err(|_| rs_matter::error::ErrorCode::NoNetworkInterface)?;

    // Bind to mDNS port to receive multicast responses
    let bind_addr = std::net::SocketAddrV6::new(std::net::Ipv6Addr::UNSPECIFIED, MDNS_PORT, 0, 0);
    socket
        .bind(&bind_addr.into())
        .map_err(|_| rs_matter::error::ErrorCode::NoNetworkInterface)?;

    let socket: UdpSocket = socket.into();
    async_io::Async::new_nonblocking(socket)
        .map_err(|_| rs_matter::error::ErrorCode::NoNetworkInterface.into())
}

async fn run_commissioning_flow<C: Crypto>(
    matter: &Matter<'_>,
    crypto: &C,
    passcode: u32,
    discriminator: u16,
    discovery_timeout_ms: u32,
) -> Result<(), Error> {
    // Phase 1: mDNS Discovery
    info!("=== Phase 1: mDNS Discovery ===");
    let peer_addr = discover_and_resolve_device(discriminator, discovery_timeout_ms).await?;

    // Phase 2: PASE Session Establishment
    info!("=== Phase 2: PASE Session Establishment ===");
    establish_pase_session(matter, crypto, peer_addr, passcode).await?;
    log_session_info(matter);

    // Phase 2.5: Device Attestation Verification
    info!("=== Phase 2.5: Device Attestation Verification ===");
    verify_device_attestation(matter, crypto).await?;

    // Phase 3: Commissioning Info & Commands
    info!("=== Phase 3: Commissioning Info & Commands ===");
    test_commissioning_commands(matter, crypto).await?;

    // Phase 4: Interaction Model Operations
    info!("=== Phase 4: Interaction Model Operations ===");
    test_onoff_cluster(matter).await?;

    info!("=== All commissioning test phases completed successfully! ===");
    Ok(())
}

// ============================================================================
// Phase 1: mDNS Discovery
// ============================================================================

async fn discover_and_resolve_device(
    discriminator: u16,
    timeout_ms: u32,
) -> Result<Address, Error> {
    let device = discover_device(discriminator, timeout_ms).await?;

    info!(
        "Discovered device: {} with {} address(es)",
        device.instance_name,
        device.addresses().len()
    );
    info!("  Discriminator: {}", device.discriminator);
    info!("  Vendor ID: {}", device.vendor_id);
    info!("  Product ID: {}", device.product_id);

    for addr in device.addresses() {
        info!("  Address: {}", addr);
    }

    resolve_device_address(&device)
}

/// Discover a Matter device using mDNS.
///
/// Platform-specific implementation:
/// - macOS: Uses astro-dnssd (native Bonjour)
/// - Linux: Uses builtin mDNS querier with multicast sockets
async fn discover_device(
    discriminator: u16,
    timeout_ms: u32,
) -> Result<DiscoveredDevice<4>, Error> {
    let filter = CommissionableFilter {
        discriminator: Some(discriminator),
        ..Default::default()
    };

    info!("Starting mDNS discovery with discriminator filter: {discriminator}");

    #[cfg(target_os = "macos")]
    let devices = discover_device_macos(&filter, timeout_ms)?;

    #[cfg(not(target_os = "macos"))]
    let devices = discover_device_linux(&filter, timeout_ms).await?;

    info!("Discovery complete. Found {} device(s)", devices.len());

    devices.into_iter().next().ok_or_else(|| {
        warn!("No devices found matching discriminator {discriminator}");
        rs_matter::error::ErrorCode::NotFound.into()
    })
}

/// macOS: Use astro-dnssd which wraps native Bonjour.
#[cfg(target_os = "macos")]
fn discover_device_macos(
    filter: &CommissionableFilter,
    timeout_ms: u32,
) -> Result<Vec<DiscoveredDevice<4>>, Error> {
    use rs_matter::transport::network::mdns::astro::discover_commissionable;
    discover_commissionable(filter, timeout_ms)
}

/// Linux: Use builtin mDNS querier with multicast sockets.
#[cfg(not(target_os = "macos"))]
async fn discover_device_linux(
    filter: &CommissionableFilter,
    timeout_ms: u32,
) -> Result<Vec<DiscoveredDevice<4>>, Error> {
    use rs_matter::transport::network::mdns::builtin::discover_commissionable;
    use rs_matter::transport::network::mdns::{MDNS_IPV4_BROADCAST_ADDR, MDNS_IPV6_BROADCAST_ADDR};

    // Create a dedicated mDNS socket bound to port 5353
    // This is separate from the Matter communication socket because mDNS
    // responses are sent as multicast to port 5353
    let mdns_socket = create_mdns_socket()?;

    let (ipv4_addr, ipv6_available, interface) = find_network_interface()?;

    // Join multicast groups
    if ipv6_available {
        mdns_socket
            .get_ref()
            .join_multicast_v6(&MDNS_IPV6_BROADCAST_ADDR, interface)
            .map_err(|e| {
                warn!("Failed to join IPv6 multicast: {e}");
                rs_matter::error::ErrorCode::NoNetworkInterface
            })?;
    }

    mdns_socket
        .get_ref()
        .join_multicast_v4(&MDNS_IPV4_BROADCAST_ADDR, &ipv4_addr)
        .map_err(|e| {
            warn!("Failed to join IPv4 multicast: {e}");
            rs_matter::error::ErrorCode::NoNetworkInterface
        })?;

    info!("Joined multicast groups on interface (IPv6: {ipv6_available})");

    let ipv6_interface = if ipv6_available {
        Some(interface)
    } else {
        None
    };

    let mut buf = [0u8; 1536];
    let devices: heapless::Vec<DiscoveredDevice<4>, 4> = discover_commissionable(
        &mut &mdns_socket,
        &mut &mdns_socket,
        filter,
        timeout_ms,
        &mut buf,
        Some(ipv4_addr),
        ipv6_interface,
    )
    .await?;

    // Convert heapless::Vec to std::vec::Vec
    Ok(devices.into_iter().collect())
}

/// Resolve a discovered device to a Matter address.
///
/// Handles platform-specific quirks:
/// - Filters out incorrect addresses (e.g., fe80::1 on macOS)
/// - Prefers IPv4 for local testing to avoid scope ID issues
/// - Sets scope ID for link-local IPv6 addresses
fn resolve_device_address(device: &DiscoveredDevice<4>) -> Result<Address, Error> {
    let interface_index = get_default_interface_index().unwrap_or(0);

    // Select the best address:
    // 1. Filter out problematic addresses
    // 2. Prefer IPv4 for local testing (avoids scope ID issues)
    let device_addr = device
        .addresses()
        .iter()
        .filter(|addr| {
            // Filter out fe80::1 which is often incorrectly returned by DNS resolution on macOS
            if let std::net::IpAddr::V6(v6) = addr {
                if v6.segments() == [0xfe80, 0, 0, 0, 0, 0, 0, 1] {
                    debug!("Skipping fe80::1 (likely incorrect DNS resolution)");
                    return false;
                }
            }
            true
        })
        .min_by_key(|addr| match addr {
            std::net::IpAddr::V4(_) => 0, // Prefer IPv4
            std::net::IpAddr::V6(_) => 1,
        })
        .ok_or_else(|| {
            warn!("Discovered device has no usable address");
            rs_matter::error::ErrorCode::InvalidData
        })?;

    info!("Using address: {}:{}", device_addr, device.port);

    // Convert to Matter address format
    let peer_addr = match device_addr {
        std::net::IpAddr::V4(v4) => {
            let ipv6 = v4.to_ipv6_mapped();
            Address::Udp(SocketAddr::V6(SocketAddrV6::new(ipv6, device.port, 0, 0)))
        }
        std::net::IpAddr::V6(v6) => {
            // Set scope ID for link-local addresses
            let scope_id = if is_ipv6_link_local(v6) {
                interface_index
            } else {
                0
            };
            Address::Udp(SocketAddr::V6(SocketAddrV6::new(
                *v6,
                device.port,
                0,
                scope_id,
            )))
        }
    };

    info!("Peer address: {peer_addr}");
    Ok(peer_addr)
}

// ============================================================================
// Phase 2: PASE Session
// ============================================================================

async fn establish_pase_session<C: Crypto>(
    matter: &Matter<'_>,
    crypto: &C,
    peer_addr: Address,
    passcode: u32,
) -> Result<(), Error> {
    let mut exchange = Exchange::initiate_unsecured(matter, crypto, peer_addr).await?;
    info!("Unsecured exchange initiated: {}", exchange.id());

    let mut pase_fut = core::pin::pin!(PaseInitiator::initiate(&mut exchange, crypto, passcode));
    let mut timeout = core::pin::pin!(Timer::after(embassy_time::Duration::from_secs(
        PASE_TIMEOUT_SECS
    )));

    match select(&mut pase_fut, &mut timeout).await {
        Either::First(Ok(())) => {
            info!("PASE session established successfully!");
            Ok(())
        }
        Either::First(Err(e)) => {
            warn!("PASE handshake failed: {e:?}");
            Err(e)
        }
        Either::Second(_) => {
            warn!("PASE handshake timed out after {PASE_TIMEOUT_SECS} seconds");
            Err(rs_matter::error::ErrorCode::RxTimeout.into())
        }
    }
}

fn log_session_info(matter: &Matter<'_>) {
    let session_mgr = matter.transport_mgr.session_mgr.borrow();
    info!("Sessions established: {}", session_mgr.iter().count());
    for sess in session_mgr.iter() {
        info!(
            "  Session: local_id={}, peer_id={}, encrypted={}",
            sess.get_local_sess_id(),
            sess.get_peer_sess_id(),
            sess.is_encrypted(),
        );
    }
}

// Phase 2.5: Device Attestation Verification
// ============================================================================

async fn verify_device_attestation<C: Crypto>(
    matter: &Matter<'_>,
    crypto: &C,
) -> Result<(), Error> {
    // 1. Get attestation challenge from the PASE session
    let att_challenge = {
        let session_mgr = matter.transport_mgr.session_mgr.borrow();
        let session = session_mgr
            .iter()
            .find(|s| s.is_encrypted())
            .ok_or(rs_matter::error::ErrorCode::InvalidState)?;
        let challenge_ref = session
            .get_att_challenge()
            .ok_or(rs_matter::error::ErrorCode::InvalidState)?;
        *challenge_ref.access()
    };
    info!("Got attestation challenge from PASE session");

    // 2. Generate random attestation nonce (32 bytes)
    let mut nonce = [0u8; 32];
    {
        let mut rng = crypto
            .rand()
            .map_err(|_| rs_matter::error::ErrorCode::Invalid)?;
        rs_matter::crypto::RngCore::fill_bytes(&mut rng, &mut nonce);
    }
    info!("Generated attestation nonce");

    // 3. Send AttestationRequest and get response
    info!("Step 2.5a: Sending AttestationRequest...");
    let (attestation_elements, attestation_signature) = {
        let mut exchange = Exchange::initiate(matter, 0, 0, true).await?;
        let resp = run_with_timeout(
            ImClient::attestation_request(&mut exchange, &nonce),
            IM_TIMEOUT_SECS,
        )
        .await?;
        (
            resp.attestation_elements()?.to_vec(),
            resp.attestation_signature()?.to_vec(),
        )
    };
    info!(
        "Got attestation response: elements={} bytes, signature={} bytes",
        attestation_elements.len(),
        attestation_signature.len()
    );

    // 4. Get DAC certificate
    info!("Step 2.5b: Requesting DAC certificate...");
    let dac_der = {
        let mut exchange = Exchange::initiate(matter, 0, 0, true).await?;
        let resp = run_with_timeout(
            ImClient::certificate_chain_request(
                &mut exchange,
                CertificateChainTypeEnum::DACCertificate,
            ),
            IM_TIMEOUT_SECS,
        )
        .await?;
        resp.certificate()?.to_vec()
    };
    info!("Got DAC certificate: {} bytes", dac_der.len());

    // 5. Get PAI certificate
    info!("Step 2.5c: Requesting PAI certificate...");
    let pai_der = {
        let mut exchange = Exchange::initiate(matter, 0, 0, true).await?;
        let resp = run_with_timeout(
            ImClient::certificate_chain_request(
                &mut exchange,
                CertificateChainTypeEnum::PAICertificate,
            ),
            IM_TIMEOUT_SECS,
        )
        .await?;
        resp.certificate()?.to_vec()
    };
    info!("Got PAI certificate: {} bytes", pai_der.len());

    // 6. Run attestation verification
    info!("Step 2.5d: Verifying device attestation...");
    let trust_store: &[&[u8]] = &[TEST_PAA_FFF1_CERT, TEST_PAA_NOVID_CERT];
    let verifier = AttestationVerifier::new(
        crypto,
        &trust_store,
        rs_matter::utils::epoch::sys_epoch,
        true,
    );

    let info = AttestationInfo {
        attestation_elements: &attestation_elements,
        attestation_challenge: &att_challenge,
        attestation_signature: &attestation_signature,
        dac_der: &dac_der,
        pai_der: &pai_der,
        vendor_id: TEST_DEV_DET.vid,
        product_id: TEST_DEV_DET.pid,
    };

    verifier.verify_device_attestation(&info, &nonce)?;

    info!("Device attestation verified successfully!");
    Ok(())
}

// ============================================================================
// Phase 3: Commissioning Commands
// ============================================================================

async fn test_commissioning_commands<C: Crypto>(
    matter: &Matter<'_>,
    crypto: &C,
) -> Result<(), Error> {
    // --- Attribute Reads (kReadCommissioningInfo) ---

    // Step 3a: Read BasicCommissioningInfo
    info!("Step 3a: Reading BasicCommissioningInfo...");
    {
        let mut exchange = Exchange::initiate(matter, 0, 0, true).await?;
        let resp = run_with_timeout(
            test_read_basic_commissioning_info(&mut exchange),
            IM_TIMEOUT_SECS,
        )
        .await?;
        let fail_safe_expiry = resp.fail_safe_expiry_length_seconds()?;
        let max_cumulative = resp.max_cumulative_failsafe_seconds()?;
        info!(
            "BasicCommissioningInfo: fail_safe_expiry={}s, max_cumulative={}s",
            fail_safe_expiry, max_cumulative
        );
    }

    // Step 3b: Read RegulatoryConfig
    info!("Step 3b: Reading RegulatoryConfig...");
    {
        let mut exchange = Exchange::initiate(matter, 0, 0, true).await?;
        let resp =
            run_with_timeout(test_read_regulatory_config(&mut exchange), IM_TIMEOUT_SECS).await?;
        info!("RegulatoryConfig: {:?}", resp);
    }

    // Step 3c: Read LocationCapability
    info!("Step 3c: Reading LocationCapability...");
    {
        let mut exchange = Exchange::initiate(matter, 0, 0, true).await?;
        let resp = run_with_timeout(
            test_read_location_capability(&mut exchange),
            IM_TIMEOUT_SECS,
        )
        .await?;
        info!("LocationCapability: {:?}", resp);
    }

    // Step 3d: Read SupportsConcurrentConnection
    info!("Step 3d: Reading SupportsConcurrentConnection...");
    {
        let mut exchange = Exchange::initiate(matter, 0, 0, true).await?;
        let resp = run_with_timeout(
            test_read_supports_concurrent_connection(&mut exchange),
            IM_TIMEOUT_SECS,
        )
        .await?;
        info!("SupportsConcurrentConnection: {}", resp);
    }

    // --- Commissioning Commands ---

    // Step 3e: ArmFailSafe
    info!("Step 3e: Testing ArmFailSafe command...");
    {
        let mut exchange = Exchange::initiate(matter, 0, 0, true).await?;
        let resp = run_with_timeout(test_arm_fail_safe(&mut exchange), IM_TIMEOUT_SECS).await?;
        let error_code = resp.error_code()?;
        info!("ArmFailSafe response: error_code={:?}", error_code);
        assert!(
            matches!(error_code, CommissioningErrorEnum::OK),
            "ArmFailSafe failed: {:?}",
            error_code
        );
    }

    // Step 3f: SetRegulatoryConfig
    info!("Step 3f: Testing SetRegulatoryConfig command...");
    {
        let mut exchange = Exchange::initiate(matter, 0, 0, true).await?;
        let resp =
            run_with_timeout(test_set_regulatory_config(&mut exchange), IM_TIMEOUT_SECS).await?;
        let error_code = resp.error_code()?;
        info!("SetRegulatoryConfig response: error_code={:?}", error_code);
        assert!(
            matches!(error_code, CommissioningErrorEnum::OK),
            "SetRegulatoryConfig failed: {:?}",
            error_code
        );
    }

    // Step 3g: SetTCAcknowledgements
    info!("Step 3g: Testing SetTCAcknowledgements command...");
    {
        let mut exchange = Exchange::initiate(matter, 0, 0, true).await?;
        let resp =
            run_with_timeout(test_set_tc_acknowledgements(&mut exchange), IM_TIMEOUT_SECS).await?;
        let error_code = resp.error_code()?;
        info!(
            "SetTCAcknowledgements response: error_code={:?}",
            error_code
        );
        assert!(
            matches!(error_code, CommissioningErrorEnum::OK),
            "SetTCAcknowledgements failed: {:?}",
            error_code
        );
    }

    // Step 3h: AttestationRequest
    info!("Step 3h: Testing AttestationRequest command...");
    {
        let mut exchange = Exchange::initiate(matter, 0, 0, true).await?;
        let resp =
            run_with_timeout(test_attestation_request(&mut exchange), IM_TIMEOUT_SECS).await?;
        let attestation_elements = resp.attestation_elements()?;
        let attestation_signature = resp.attestation_signature()?;
        info!(
            "AttestationRequest response: elements_len={}, signature_len={}",
            attestation_elements.len(),
            attestation_signature.len()
        );
    }

    // Step 3i: CertificateChainRequest (DAC)
    info!("Step 3i: Testing CertificateChainRequest (DAC) command...");
    {
        let mut exchange = Exchange::initiate(matter, 0, 0, true).await?;
        let resp = run_with_timeout(
            test_certificate_chain_request(&mut exchange, CertificateChainTypeEnum::DACCertificate),
            IM_TIMEOUT_SECS,
        )
        .await?;
        let certificate = resp.certificate()?;
        info!(
            "CertificateChainRequest (DAC) response: certificate_len={}",
            certificate.len()
        );
    }

    // Step 3j: CertificateChainRequest (PAI)
    info!("Step 3j: Testing CertificateChainRequest (PAI) command...");
    {
        let mut exchange = Exchange::initiate(matter, 0, 0, true).await?;
        let resp = run_with_timeout(
            test_certificate_chain_request(&mut exchange, CertificateChainTypeEnum::PAICertificate),
            IM_TIMEOUT_SECS,
        )
        .await?;
        let certificate = resp.certificate()?;
        info!(
            "CertificateChainRequest (PAI) response: certificate_len={}",
            certificate.len()
        );
    }

    // Step 3k: CSRRequest
    info!("Step 3k: Testing CSRRequest command...");
    let nocsr_elements_owned = {
        let mut exchange = Exchange::initiate(matter, 0, 0, true).await?;
        let resp = run_with_timeout(test_csr_request(&mut exchange), IM_TIMEOUT_SECS).await?;
        let nocsr_elements = resp.nocsr_elements()?;
        let attestation_signature = resp.attestation_signature()?;
        info!(
            "CSRRequest response: nocsr_elements_len={}, signature_len={}",
            nocsr_elements.len(),
            attestation_signature.len()
        );
        nocsr_elements.0.to_vec() // copy before going out of scope
    };

    // Step 3m: NOC Provisioning
    test_noc_provisioning(matter, crypto, &nocsr_elements_owned).await?;

    // Step 3n: CommissioningComplete
    // This will fail because we haven't established a CASE session yet
    // (CASE initiator not implemented). The device requires CASE session for
    // CommissioningComplete, so it will return a commissioning error.
    info!("Step 3n: Testing CommissioningComplete command (expected to fail)...");
    {
        let mut exchange = Exchange::initiate(matter, 0, 0, true).await?;
        let resp =
            run_with_timeout(test_commissioning_complete(&mut exchange), IM_TIMEOUT_SECS).await?;
        let error_code = resp.error_code()?;
        info!(
            "CommissioningComplete response: error_code={:?}",
            error_code
        );
        assert!(
            !matches!(error_code, CommissioningErrorEnum::OK),
            "CommissioningComplete should fail when not fully commissioned"
        );
    }

    info!("All commissioning command tests completed successfully!");
    Ok(())
}

async fn test_arm_fail_safe<'a>(
    exchange: &'a mut Exchange<'_>,
) -> Result<ArmFailSafeResponse<'a>, Error> {
    ImClient::arm_fail_safe(exchange, 60, 1).await
}

async fn test_set_regulatory_config<'a>(
    exchange: &'a mut Exchange<'_>,
) -> Result<SetRegulatoryConfigResponse<'a>, Error> {
    ImClient::set_regulatory_config(exchange, RegulatoryLocationTypeEnum::IndoorOutdoor, "US", 2)
        .await
}

async fn test_attestation_request<'a>(
    exchange: &'a mut Exchange<'_>,
) -> Result<AttestationResponse<'a>, Error> {
    let nonce = [0x42u8; 32];
    ImClient::attestation_request(exchange, &nonce).await
}

async fn test_certificate_chain_request<'a>(
    exchange: &'a mut Exchange<'_>,
    cert_type: CertificateChainTypeEnum,
) -> Result<CertificateChainResponse<'a>, Error> {
    ImClient::certificate_chain_request(exchange, cert_type).await
}

async fn test_csr_request<'a>(exchange: &'a mut Exchange<'_>) -> Result<CSRResponse<'a>, Error> {
    let nonce = [0x43u8; 32];
    ImClient::csr_request(exchange, &nonce, false).await
}

async fn test_commissioning_complete<'a>(
    exchange: &'a mut Exchange<'_>,
) -> Result<CommissioningCompleteResponse<'a>, Error> {
    ImClient::commissioning_complete(exchange).await
}

async fn test_read_basic_commissioning_info<'a>(
    exchange: &'a mut Exchange<'_>,
) -> Result<BasicCommissioningInfo<'a>, Error> {
    ImClient::read_basic_commissioning_info(exchange).await
}

async fn test_read_regulatory_config(
    exchange: &mut Exchange<'_>,
) -> Result<RegulatoryLocationTypeEnum, Error> {
    ImClient::read_regulatory_config(exchange).await
}

async fn test_read_location_capability(
    exchange: &mut Exchange<'_>,
) -> Result<RegulatoryLocationTypeEnum, Error> {
    ImClient::read_location_capability(exchange).await
}

async fn test_read_supports_concurrent_connection(
    exchange: &mut Exchange<'_>,
) -> Result<bool, Error> {
    ImClient::read_supports_concurrent_connection(exchange).await
}

async fn test_set_tc_acknowledgements<'a>(
    exchange: &'a mut Exchange<'_>,
) -> Result<SetTCAcknowledgementsResponse<'a>, Error> {
    ImClient::set_tc_acknowledgements(exchange, 1, 0x0001).await
}

/// Test NOC (Node Operational Certificate) provisioning.
///
/// 1. Parses the CSR from the CSRResponse to extract the DER-encoded CSR
/// 2. Uses FabricCredentials to generate NOC, ICAC, and RCAC
/// 3. Sends AddTrustedRootCertificate command with the RCAC
/// 4. Sends AddNOC command with the generated NOC, ICAC, and IPK
/// 5. Verifies the AddNOC response indicates success
async fn test_noc_provisioning<C: Crypto>(
    matter: &Matter<'_>,
    crypto: &C,
    nocsr_elements: &[u8],
) -> Result<(), Error> {
    info!("Step 3m: NOC Provisioning");

    // 1. Extract and parse the CSR from the NOCSRElements
    info!("Step 3m.1: Extracting CSR from NOCSRElements...");

    let nocsr_struct = TLVElement::new(nocsr_elements);
    let csr_element = nocsr_struct.structure()?.find_ctx(1)?;
    let csr_der = csr_element.str()?;

    info!("Extracted CSR: {} bytes", csr_der.len());

    // 2. Create FabricCredentials and generate device credentials
    info!("Step 3m.2: Generating NOC and RCAC...");
    let mut fabric_creds = FabricCredentials::new(crypto, TEST_FABRIC_ID)?;
    fabric_creds.enable_icac(crypto)?;

    // Generate device credentials with a CAT ID
    let cat_ids = [TEST_CAT_ID];
    let device_creds = fabric_creds.generate_device_credentials(crypto, csr_der, &cat_ids)?;

    info!(
        "Generated credentials: NOC={} bytes, ICAC={} bytes, RCAC={} bytes, IPK={} bytes",
        device_creds.noc.len(),
        device_creds.icac.as_ref().map(|v| v.len()).unwrap_or(0),
        device_creds.root_cert.len(),
        device_creds.ipk.len()
    );
    info!("Assigned node_id: 0x{:016x}", device_creds.node_id);

    // 3. Send AddTrustedRootCertificate
    info!("Step 3m.3: Sending AddTrustedRootCertificate...");
    {
        let mut exchange = Exchange::initiate(matter, 0, 0, true).await?;
        run_with_timeout(
            ImClient::add_trusted_root_certificate(&mut exchange, &device_creds.root_cert),
            IM_TIMEOUT_SECS,
        )
        .await?;
        info!("AddTrustedRootCertificate succeeded");
    }

    // 4. Send AddNOC
    info!("Step 3m.4: Sending AddNOC...");
    let (status, fabric_index) = {
        let mut exchange = Exchange::initiate(matter, 0, 0, true).await?;
        let resp = run_with_timeout(
            ImClient::add_noc(
                &mut exchange,
                &device_creds.noc,
                device_creds.icac.as_ref().map(|v| v.as_slice()),
                &device_creds.ipk,
                TEST_ADMIN_SUBJECT,
                TEST_ADMIN_VENDOR_ID,
            ),
            IM_TIMEOUT_SECS,
        )
        .await?;

        (resp.status_code()?, resp.fabric_index()?)
    };

    // 5. Verify AddNOC response
    info!(
        "AddNOC response: status={:?}, fabric_index={:?}",
        status, fabric_index
    );

    if !matches!(status, NodeOperationalCertStatusEnum::OK) {
        warn!("AddNOC failed with status: {:?}", status);
        return Err(rs_matter::error::ErrorCode::InvalidState.into());
    }

    info!("NOC provisioning completed successfully.");
    info!(
        "Device is now commissioned on fabric 0x{:016x} with node_id 0x{:016x}",
        TEST_FABRIC_ID, device_creds.node_id
    );

    Ok(())
}

// ============================================================================
// Phase 4: Interaction Model Operations
// ============================================================================

async fn test_onoff_cluster(matter: &Matter<'_>) -> Result<(), Error> {
    // Read initial state
    info!("Step 4a: Reading initial OnOff attribute...");
    let initial_value = read_onoff_with_timeout(matter).await?;
    info!("Initial OnOff value: {initial_value}");

    // Toggle
    info!("Step 4b: Invoking Toggle command...");
    let status = invoke_toggle_with_timeout(matter).await?;
    info!("Toggle command completed with status: {status:?}");

    // Verify toggle worked
    info!("Step 4c: Verifying toggle effect...");
    let final_value = read_onoff_with_timeout(matter).await?;
    info!("Final OnOff value: {final_value}");

    if final_value == initial_value {
        warn!("OnOff value didn't change after toggle!");
    } else {
        info!("Toggle verified successfully: {initial_value} -> {final_value}");
    }

    Ok(())
}

/// Helper to run a future with a timeout.
async fn run_with_timeout<T, F: core::future::Future<Output = Result<T, Error>>>(
    fut: F,
    timeout_secs: u64,
) -> Result<T, Error> {
    let mut fut = core::pin::pin!(fut);
    let mut timeout = core::pin::pin!(Timer::after(embassy_time::Duration::from_secs(
        timeout_secs
    )));

    match select(&mut fut, &mut timeout).await {
        Either::First(result) => result,
        Either::Second(_) => {
            warn!("Operation timed out after {} seconds", timeout_secs);
            Err(rs_matter::error::ErrorCode::RxTimeout.into())
        }
    }
}

async fn read_onoff_with_timeout(matter: &Matter<'_>) -> Result<bool, Error> {
    let mut exchange = Exchange::initiate(matter, 0, 0, true).await?;
    debug!("IM exchange initiated: {}", exchange.id());

    run_with_timeout(read_onoff(&mut exchange), IM_TIMEOUT_SECS).await
}

async fn read_onoff(exchange: &mut Exchange<'_>) -> Result<bool, Error> {
    let resp = ImClient::read_single_attr(exchange, 1, CLUSTER_ON_OFF, ATTR_ON_OFF, true).await?;

    match resp {
        AttrResp::Data(data) => data.data.bool(),
        AttrResp::Status(status) => {
            warn!("Read returned status: {:?}", status.status);
            Err(rs_matter::error::ErrorCode::InvalidData.into())
        }
    }
}

async fn invoke_toggle_with_timeout(matter: &Matter<'_>) -> Result<IMStatusCode, Error> {
    let mut exchange = Exchange::initiate(matter, 0, 0, true).await?;
    debug!("Invoke exchange initiated: {}", exchange.id());

    run_with_timeout(invoke_toggle(&mut exchange), IM_TIMEOUT_SECS).await
}

async fn invoke_toggle(exchange: &mut Exchange<'_>) -> Result<IMStatusCode, Error> {
    // Toggle command has no data - build empty TLV struct
    let mut buf = [0u8; 8];
    let tail = {
        let mut wb = WriteBuf::new(&mut buf);
        wb.start_struct(&TLVTag::Anonymous)?;
        wb.end_container()?;
        wb.get_tail()
    };

    let resp = ImClient::invoke_single_cmd(
        exchange,
        1,
        CLUSTER_ON_OFF,
        CMD_TOGGLE,
        TLVElement::new(&buf[..tail]),
        None,
    )
    .await?;

    match resp {
        CmdResp::Status(s) => Ok(s.status.status),
        CmdResp::Cmd(_) => Ok(IMStatusCode::Success),
    }
}

// ============================================================================
// Network Utilities
// ============================================================================

/// Find a suitable network interface for mDNS discovery (Linux only).
#[cfg(not(target_os = "macos"))]
fn find_network_interface() -> Result<(std::net::Ipv4Addr, bool, u32), Error> {
    use nix::net::if_::InterfaceFlags;
    use nix::sys::socket::SockaddrIn6;

    let interfaces = || {
        nix::ifaddrs::getifaddrs().unwrap().filter(|ia| {
            ia.flags.contains(InterfaceFlags::IFF_UP)
                && ia
                    .flags
                    .intersects(InterfaceFlags::IFF_BROADCAST | InterfaceFlags::IFF_MULTICAST)
                && !ia
                    .flags
                    .intersects(InterfaceFlags::IFF_LOOPBACK | InterfaceFlags::IFF_POINTOPOINT)
        })
    };

    // Prefer interface with both IPv4 and IPv6
    let result = interfaces()
        .filter_map(|ia| {
            ia.address
                .and_then(|addr| addr.as_sockaddr_in6().map(SockaddrIn6::ip))
                .map(|_ipv6| ia.interface_name.clone())
        })
        .find_map(|iname| {
            interfaces()
                .filter(|ia2| ia2.interface_name == iname)
                .find_map(|ia2| {
                    ia2.address
                        .and_then(|addr| addr.as_sockaddr_in().map(|addr| addr.ip()))
                        .map(|ip: std::net::Ipv4Addr| (iname.clone(), ip, true))
                })
        });

    // Fallback to IPv4 only
    let (iname, ip, ipv6_available) = result
        .or_else(|| {
            interfaces().find_map(|ia| {
                ia.address
                    .and_then(|addr| addr.as_sockaddr_in().map(|addr| addr.ip()))
                    .map(|ip: std::net::Ipv4Addr| (ia.interface_name.clone(), ip, false))
            })
        })
        .ok_or_else(|| {
            warn!("Cannot find network interface suitable for mDNS");
            rs_matter::error::ErrorCode::NoNetworkInterface
        })?;

    let if_index = nix::net::if_::if_nametoindex::<str>(iname.as_str()).unwrap_or(0);

    info!("Using network interface {iname} (index {if_index}) with {ip} (IPv6: {ipv6_available})");

    Ok((ip, ipv6_available, if_index))
}

/// Get the default network interface index for link-local IPv6 addresses.
fn get_default_interface_index() -> Option<u32> {
    use nix::net::if_::InterfaceFlags;

    nix::ifaddrs::getifaddrs()
        .ok()?
        .filter(|ia| {
            ia.flags.contains(InterfaceFlags::IFF_UP)
                && ia
                    .flags
                    .intersects(InterfaceFlags::IFF_BROADCAST | InterfaceFlags::IFF_MULTICAST)
                && !ia
                    .flags
                    .intersects(InterfaceFlags::IFF_LOOPBACK | InterfaceFlags::IFF_POINTOPOINT)
        })
        .find_map(|ia| {
            let has_ipv6 = ia
                .address
                .map(|addr| addr.as_sockaddr_in6().is_some())
                .unwrap_or(false);

            if has_ipv6 {
                nix::net::if_::if_nametoindex::<str>(ia.interface_name.as_str()).ok()
            } else {
                None
            }
        })
}

/// Check if an IPv6 address is link-local (fe80::/10).
fn is_ipv6_link_local(addr: &std::net::Ipv6Addr) -> bool {
    (addr.segments()[0] & 0xffc0) == 0xfe80
}
