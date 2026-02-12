# Dockerfile for testing builtin mDNS implementation
#
# This container runs the mdns_discover example using the builtin mDNS
# implementation (not astro-dnssd), allowing testing on macOS where
# mDNSResponder cannot be easily disabled.
#
# Usage:
#   docker build -t rs-matter-mdnstest -f docker/mdnstest/Dockerfile .
#   docker run --rm --network host rs-matter-mdnstest
#
# On macOS with Docker Desktop, host networking doesn't work the same as Linux.
# You may need to use a Linux VM or run with specific port mappings.

FROM rust:1.83-bookworm

# Install build dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the workspace
COPY . .

# Build the mdns_discover example without astro-dnssd (uses builtin implementation)
RUN cargo build --package rs-matter-examples --bin mdns_discover --release

# Default command runs the discovery
CMD ["./target/release/mdns_discover"]
