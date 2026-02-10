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

//! Example binary for testing mDNS discovery of commissionable Matter devices.
//!
//! Usage:
//!   # Using builtin mDNS (default, requires mDNSResponder to be disabled on macOS)
//!   cargo run --bin mdns_discover
//!
//!   # Using system DNS-SD via astro-dnssd (recommended for macOS)
//!   cargo run --bin mdns_discover --features astro-dnssd
//!
//!   # Using Avahi via DBus (Linux only, requires Avahi daemon running)
//!   cargo run --bin mdns_discover --features avahi
//!
//!   # Using zeroconf crate (cross-platform, requires Avahi on Linux or Bonjour on macOS/Windows)
//!   cargo run --bin mdns_discover --features zeroconf
//!
//!   # Using systemd-resolved via DBus (Linux only, requires systemd-resolved with mDNS enabled)
//!   cargo run --bin mdns_discover --features resolve
//!
//! This will discover any Matter devices advertising on the local network
//! with the `_matterc._udp.local` service type (commissionable devices).

use log::info;

use rs_matter::error::Error;

fn main() -> Result<(), Error> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Info)
        .format_timestamp_nanos()
        .init();

    info!("mDNS Discovery Example");
    info!("Looking for commissionable Matter devices...");

    #[cfg(feature = "astro-dnssd")]
    {
        run_astro_discovery()
    }

    #[cfg(all(feature = "avahi", not(feature = "astro-dnssd")))]
    {
        futures_lite::future::block_on(run_avahi_discovery())
    }

    #[cfg(all(
        feature = "zeroconf",
        not(any(feature = "astro-dnssd", feature = "avahi"))
    ))]
    {
        run_zeroconf_discovery()
    }

    #[cfg(all(
        feature = "resolve",
        not(any(feature = "astro-dnssd", feature = "avahi", feature = "zeroconf"))
    ))]
    {
        futures_lite::future::block_on(run_resolve_discovery())
    }

    #[cfg(not(any(
        feature = "astro-dnssd",
        feature = "avahi",
        feature = "zeroconf",
        feature = "resolve"
    )))]
    {
        futures_lite::future::block_on(run_builtin_discovery())
    }
}

/// Discovery using the astro-dnssd crate (uses system DNS-SD service)
#[cfg(feature = "astro-dnssd")]
fn run_astro_discovery() -> Result<(), Error> {
    use rs_matter::transport::network::mdns::astro::discover_commissionable;
    use rs_matter::transport::network::mdns::CommissionableFilter;

    info!("Using astro-dnssd (system DNS-SD service)");

    // Discover devices with no filter (find all commissionable devices)
    let filter = CommissionableFilter::default();

    let devices = discover_commissionable(&filter, 5000)?; // 5 second timeout

    print_results(&devices);

    Ok(())
}

/// Discovery using the zeroconf crate (cross-platform)
#[cfg(all(
    feature = "zeroconf",
    not(any(feature = "astro-dnssd", feature = "avahi"))
))]
fn run_zeroconf_discovery() -> Result<(), Error> {
    use rs_matter::transport::network::mdns::zeroconf::discover_commissionable;
    use rs_matter::transport::network::mdns::CommissionableFilter;

    info!("Using zeroconf crate");

    // Discover devices with no filter (find all commissionable devices)
    let filter = CommissionableFilter::default();

    let devices = discover_commissionable(&filter, 5000)?; // 5 second timeout

    print_results(&devices);

    Ok(())
}

/// Discovery using systemd-resolved via DBus (Linux only)
#[cfg(all(
    feature = "resolve",
    not(any(feature = "astro-dnssd", feature = "avahi", feature = "zeroconf"))
))]
async fn run_resolve_discovery() -> Result<(), Error> {
    use rs_matter::transport::network::mdns::resolve::discover_commissionable;
    use rs_matter::transport::network::mdns::CommissionableFilter;

    info!("Using systemd-resolved via DBus");

    // Connect to the system DBus
    let connection = zbus::Connection::system().await.map_err(|e| {
        log::error!("Failed to connect to system DBus: {}", e);
        rs_matter::error::ErrorCode::StdIoError
    })?;

    // Discover devices with no filter (find all commissionable devices)
    let filter = CommissionableFilter::default();

    let devices = discover_commissionable(&connection, &filter).await?;

    print_results(&devices);

    Ok(())
}

/// Discovery using Avahi via DBus (Linux only)
#[cfg(all(feature = "avahi", not(feature = "astro-dnssd")))]
async fn run_avahi_discovery() -> Result<(), Error> {
    use rs_matter::transport::network::mdns::avahi::discover_commissionable;
    use rs_matter::transport::network::mdns::CommissionableFilter;

    info!("Using Avahi via DBus");

    // Connect to the system DBus
    let connection = zbus::Connection::system().await.map_err(|e| {
        log::error!("Failed to connect to system DBus: {}", e);
        rs_matter::error::ErrorCode::StdIoError
    })?;

    // Discover devices with no filter (find all commissionable devices)
    let filter = CommissionableFilter::default();

    let devices = discover_commissionable(&connection, &filter, 5000).await?; // 5 second timeout

    print_results(&devices);

    Ok(())
}

/// Discovery using the builtin mDNS implementation
#[cfg(not(any(
    feature = "astro-dnssd",
    feature = "avahi",
    feature = "zeroconf",
    feature = "resolve"
)))]
async fn run_builtin_discovery() -> Result<(), Error> {
    use socket2::{Domain, Protocol, Socket, Type};
    use std::net::UdpSocket;

    use rs_matter::transport::network::mdns::builtin::discover_commissionable;
    use rs_matter::transport::network::mdns::{
        CommissionableFilter, MDNS_IPV4_BROADCAST_ADDR, MDNS_IPV6_BROADCAST_ADDR,
    };

    info!("Using builtin mDNS implementation");

    let (ipv4_addr, ipv6_available, interface) = initialize_network()?;

    // Create UDP socket for mDNS querying
    // We bind to port 0 (ephemeral port) instead of 5353 to avoid conflicts
    // with other mDNS implementations that may be using port 5353 with SO_REUSEPORT.
    // We still join the multicast group to receive multicast responses.
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    socket.set_only_v6(false)?;
    // Bind to ephemeral port - this avoids SO_REUSEPORT load balancing issues
    let bind_addr = std::net::SocketAddrV6::new(std::net::Ipv6Addr::UNSPECIFIED, 0, 0, 0);
    socket.bind(&bind_addr.into())?;
    let socket = async_io::Async::<UdpSocket>::new_nonblocking(socket.into())?;

    let local_port = socket.get_ref().local_addr()?.port();
    info!("Socket bound to port {}", local_port);

    // Join multicast groups to receive multicast responses
    if ipv6_available {
        socket
            .get_ref()
            .join_multicast_v6(&MDNS_IPV6_BROADCAST_ADDR, interface)?;
    }
    socket
        .get_ref()
        .join_multicast_v4(&MDNS_IPV4_BROADCAST_ADDR, &ipv4_addr)?;

    info!(
        "Socket bound and multicast groups joined (IPv6: {})",
        ipv6_available
    );
    info!("Sending mDNS query for _matterc._udp.local...");

    // Discover devices with no filter (find all commissionable devices)
    let filter = CommissionableFilter::default();

    let ipv6_interface = if ipv6_available {
        Some(interface)
    } else {
        None
    };

    let devices = discover_commissionable(
        &mut &socket,
        &mut &socket,
        &filter,
        5000, // 5 second timeout
        Some(ipv4_addr),
        ipv6_interface,
    )
    .await?;

    print_results(&devices);

    Ok(())
}

/// Find a suitable network interface for mDNS discovery.
///
/// Returns the IPv4 address, whether IPv6 is available, and the interface index.
#[cfg(not(any(
    feature = "astro-dnssd",
    feature = "avahi",
    feature = "zeroconf",
    feature = "resolve"
)))]
fn initialize_network() -> Result<(rs_matter::transport::network::Ipv4Addr, bool, u32), Error> {
    use log::error;
    use nix::{net::if_::InterfaceFlags, sys::socket::SockaddrIn6};
    use rs_matter::error::ErrorCode;

    let interfaces = || {
        nix::ifaddrs::getifaddrs().unwrap().filter(|ia| {
            // Interface must be up and support either broadcast or multicast (for mDNS)
            // Docker containers typically have multicast but not broadcast
            ia.flags.contains(InterfaceFlags::IFF_UP)
                && ia
                    .flags
                    .intersects(InterfaceFlags::IFF_BROADCAST | InterfaceFlags::IFF_MULTICAST)
                && !ia
                    .flags
                    .intersects(InterfaceFlags::IFF_LOOPBACK | InterfaceFlags::IFF_POINTOPOINT)
        })
    };

    // Find a suitable network interface - first try to find one with both IPv4 and IPv6
    let result = interfaces()
        .filter_map(|ia| {
            ia.address
                .and_then(|addr| addr.as_sockaddr_in6().map(SockaddrIn6::ip))
                .map(|ipv6| (ia.interface_name, ipv6))
        })
        .filter_map(|(iname, _ipv6)| {
            interfaces()
                .filter(|ia2| ia2.interface_name == iname)
                .find_map(|ia2| {
                    ia2.address
                        .and_then(|addr| addr.as_sockaddr_in().map(|addr| addr.ip().into()))
                        .map(|ip: std::net::Ipv4Addr| (iname.clone(), ip, true))
                })
        })
        .next();

    // If no interface with both IPv4 and IPv6, try to find one with just IPv4
    let (iname, ip, ipv6_available) = result
        .or_else(|| {
            interfaces()
                .filter_map(|ia| {
                    ia.address
                        .and_then(|addr| addr.as_sockaddr_in().map(|addr| addr.ip().into()))
                        .map(|ip: std::net::Ipv4Addr| (ia.interface_name, ip, false))
                })
                .next()
        })
        .ok_or_else(|| {
            error!("Cannot find network interface suitable for mDNS");
            ErrorCode::StdIoError
        })?;

    // Get the interface index for multicast operations
    let if_index = nix::net::if_::if_nametoindex(iname.as_str()).unwrap_or(0);

    info!(
        "Using network interface {} (index {}) with {} (IPv6: {})",
        iname, if_index, ip, ipv6_available
    );

    Ok((ip.octets().into(), ipv6_available, if_index))
}

fn print_results<T: DiscoveredDeviceInfo>(devices: &[T]) {
    if devices.is_empty() {
        info!("No commissionable Matter devices found");
    } else {
        info!("Found {} commissionable device(s):", devices.len());
        for (i, device) in devices.iter().enumerate() {
            info!("  Device {}:", i + 1);
            if let Some(addr) = device.addr() {
                info!("    Address: {}", addr);
            }
            let addresses = device.addresses();
            if addresses.len() > 1 {
                info!("    All addresses ({}):", addresses.len());
                for addr in addresses {
                    info!("      - {}", addr);
                }
            }
            info!("    Discriminator: {}", device.discriminator());
            info!("    Vendor ID: {}", device.vendor_id());
            info!("    Product ID: {}", device.product_id());
            info!("    Commissioning Mode: {:?}", device.commissioning_mode());
            let device_type = device.device_type();
            if device_type != 0 {
                info!("    Device Type: {} (0x{:04X})", device_type, device_type);
            }
            if let Some(sii) = device.mrp_retry_interval_idle() {
                info!("    MRP Idle Interval: {} ms", sii);
            }
            if let Some(sai) = device.mrp_retry_interval_active() {
                info!("    MRP Active Interval: {} ms", sai);
            }
            let name = device.device_name();
            if !name.is_empty() {
                info!("    Device Name: {}", name);
            }
            info!("    Instance: {}", device.instance_name());
        }
    }
}

/// Trait to abstract over different DiscoveredDevice types
trait DiscoveredDeviceInfo {
    fn addr(&self) -> Option<std::net::SocketAddr>;
    fn addresses(&self) -> &[std::net::IpAddr];
    fn discriminator(&self) -> u16;
    fn vendor_id(&self) -> u16;
    fn product_id(&self) -> u16;
    fn commissioning_mode(&self) -> rs_matter::transport::network::mdns::CommissioningMode;
    fn device_type(&self) -> u32;
    fn mrp_retry_interval_idle(&self) -> Option<u32>;
    fn mrp_retry_interval_active(&self) -> Option<u32>;
    fn device_name(&self) -> &str;
    fn instance_name(&self) -> &str;
}

impl DiscoveredDeviceInfo for rs_matter::transport::network::mdns::DiscoveredDevice {
    fn addr(&self) -> Option<std::net::SocketAddr> {
        self.addr()
    }
    fn addresses(&self) -> &[std::net::IpAddr] {
        self.addresses()
    }
    fn discriminator(&self) -> u16 {
        self.discriminator
    }
    fn vendor_id(&self) -> u16 {
        self.vendor_id
    }
    fn product_id(&self) -> u16 {
        self.product_id
    }
    fn commissioning_mode(&self) -> rs_matter::transport::network::mdns::CommissioningMode {
        self.commissioning_mode
    }
    fn device_type(&self) -> u32 {
        self.device_type
    }
    fn mrp_retry_interval_idle(&self) -> Option<u32> {
        self.mrp_retry_interval_idle
    }
    fn mrp_retry_interval_active(&self) -> Option<u32> {
        self.mrp_retry_interval_active
    }
    fn device_name(&self) -> &str {
        &self.device_name
    }
    fn instance_name(&self) -> &str {
        &self.instance_name
    }
}
