# mDNS Testing with Docker

This directory contains Docker configurations for testing the mDNS implementations (builtin and Avahi) on systems where mDNSResponder cannot be disabled (e.g., macOS).

## Overview

On macOS, the system's mDNSResponder service is protected by SIP and cannot be disabled. The builtin mDNS implementation in rs-matter conflicts with mDNSResponder because both try to bind to port 5353.

Using Docker provides an isolated environment where we can run the mDNS implementations without conflicts.

## Supported Backends

The test container includes two mDNS discovery backends:

- **builtin**: Custom mDNS implementation using raw UDP sockets
- **avahi**: Uses the Avahi daemon via D-Bus (Linux-specific, suitable for embedded Linux)

## Options

### Option 1: Standalone Container (Recommended)

This option runs both `chip-all-clusters-app` and `mdns_discover` inside the same container, providing a fully self-contained test environment.

```bash
# Build the standalone image
docker build -t rs-matter-mdnstest-standalone \
    -f docker/mdnstest/Dockerfile.standalone .

# Run the test (tests both backends by default)
docker run --rm rs-matter-mdnstest-standalone

# Test only the builtin backend
docker run --rm -e MDNS_BACKEND=builtin rs-matter-mdnstest-standalone

# Test only the Avahi backend
docker run --rm -e MDNS_BACKEND=avahi rs-matter-mdnstest-standalone

# With custom parameters
docker run --rm \
    -e DISCRIMINATOR=3840 \
    -e PASSCODE=20202021 \
    -e MDNS_BACKEND=both \
    rs-matter-mdnstest-standalone
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `MDNS_BACKEND` | `both` | Which backend to test: `builtin`, `avahi`, or `both` |
| `DISCRIMINATOR` | `3840` | Device discriminator for chip-all-clusters-app |
| `PASSCODE` | `20202021` | Device passcode for chip-all-clusters-app |

### Option 2: Host Networking (Linux only)

On Linux, you can use host networking to discover Matter devices on your local network:

```bash
# Build the image
docker build -t rs-matter-mdnstest -f docker/mdnstest/Dockerfile .

# Run with host networking
docker run --rm --network host rs-matter-mdnstest
```

**Note:** Host networking does not work on macOS with Docker Desktop. On macOS, the container runs inside a Linux VM and `--network host` only gives access to the VM's network, not the host's.

### Option 3: Using Docker Compose

```bash
cd docker/mdnstest

# Run the standalone test
docker-compose --profile standalone up --build mdns-test-standalone

# Or on Linux with host networking
docker-compose up --build mdns-discover
```

## Troubleshooting

### "No devices found"

If running the standalone container and no devices are found:

1. Check that `chip-all-clusters-app` started successfully (look for `[chip-app]` prefixed lines in the output)
2. Increase the timeout: `docker run -e TIMEOUT=15 ...`
3. Check the container logs for any errors

### Build failures

The standalone image requires building chip-all-clusters-app from source, which can take a long time and requires significant disk space. Make sure you have:

- At least 10GB of free disk space
- A stable internet connection (for downloading connectedhomeip)

### macOS host networking

Docker Desktop on macOS doesn't support true host networking. If you need to discover devices on your local network from macOS:

1. Use the `astro-dnssd` backend instead (it uses the system's mDNSResponder)
2. Use a Linux VM with bridged networking
3. Use Colima or another Docker runtime that supports macvlan networking
