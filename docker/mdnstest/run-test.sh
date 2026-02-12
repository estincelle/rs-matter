#!/bin/bash
# Run mDNS discovery test inside the container
#
# This script starts chip-all-clusters-app in the background,
# waits for it to initialize, then runs mDNS discovery.
#
# Environment variables:
#   MDNS_BACKEND - Which backend to test: "builtin", "avahi", "zeroconf", or "all" (default: "all")
#   DISCRIMINATOR - Device discriminator (default: 3840)
#   PASSCODE - Device passcode (default: 20202021)

set -e

DISCRIMINATOR="${DISCRIMINATOR:-3840}"
PASSCODE="${PASSCODE:-20202021}"
MDNS_BACKEND="${MDNS_BACKEND:-all}"

echo "=== mDNS Discovery Test ==="
echo "Discriminator: $DISCRIMINATOR"
echo "Passcode: $PASSCODE"
echo "Backend: $MDNS_BACKEND"
echo ""

# Debug: show network interfaces
echo "=== Network Interfaces ==="
ip addr show
echo ""

# Start dbus (required for Avahi)
echo "Starting dbus..."
mkdir -p /run/dbus
dbus-daemon --system --fork

# Start Avahi daemon for mDNS
echo "Starting Avahi daemon..."
avahi-daemon --daemonize --no-chroot

# Wait for Avahi to be ready
sleep 1

# Clean up any existing KVS
rm -f /tmp/chip_kvs

# Start chip-all-clusters-app in the background
echo "Starting chip-all-clusters-app..."
/app/chip-all-clusters-app \
    --discriminator "$DISCRIMINATOR" \
    --passcode "$PASSCODE" \
    --KVS /tmp/chip_kvs \
    2>&1 | sed 's/^/[chip-app] /' &

CHIP_PID=$!

# Wait for the app to start advertising
# chip-all-clusters-app can take 20+ seconds to fully initialize on some systems
echo "Waiting for chip-all-clusters-app to initialize..."
sleep 25

# Check if the process is still running
if ! kill -0 $CHIP_PID 2>/dev/null; then
    echo "ERROR: chip-all-clusters-app failed to start"
    exit 1
fi

OVERALL_RESULT=0

# Function to run discovery with a specific backend
run_discovery() {
    local backend=$1
    local binary="/app/mdns_discover_${backend}"

    echo ""
    echo "========================================"
    echo "=== Testing $backend mDNS backend ==="
    echo "========================================"
    echo ""

    if [ ! -x "$binary" ]; then
        echo "ERROR: Binary not found: $binary"
        return 1
    fi

    # Run the discovery with info logging
    RUST_LOG=info "$binary"
    return $?
}

# Run discovery based on selected backend
if [ "$MDNS_BACKEND" = "builtin" ] || [ "$MDNS_BACKEND" = "all" ]; then
    run_discovery "builtin"
    BUILTIN_RESULT=$?
    if [ $BUILTIN_RESULT -ne 0 ]; then
        OVERALL_RESULT=1
    fi
fi

if [ "$MDNS_BACKEND" = "avahi" ] || [ "$MDNS_BACKEND" = "all" ]; then
    # Small delay between tests to avoid mDNS response suppression
    if [ "$MDNS_BACKEND" = "all" ]; then
        echo ""
        echo "Waiting before next test..."
        sleep 2
    fi

    run_discovery "avahi"
    AVAHI_RESULT=$?
    if [ $AVAHI_RESULT -ne 0 ]; then
        OVERALL_RESULT=1
    fi
fi

if [ "$MDNS_BACKEND" = "zeroconf" ] || [ "$MDNS_BACKEND" = "all" ]; then
    # Small delay between tests to avoid mDNS response suppression
    if [ "$MDNS_BACKEND" = "all" ]; then
        echo ""
        echo "Waiting before next test..."
        sleep 2
    fi

    run_discovery "zeroconf"
    ZEROCONF_RESULT=$?
    if [ $ZEROCONF_RESULT -ne 0 ]; then
        OVERALL_RESULT=1
    fi
fi

# Check if we can see the service via avahi-browse (for comparison)
echo ""
echo "=== Checking mDNS services via avahi-browse (for comparison) ==="
timeout 3 avahi-browse -r -t _matterc._udp 2>/dev/null || echo "(avahi-browse timed out or failed)"
echo ""

# Clean up
echo ""
echo "Stopping chip-all-clusters-app..."
# Kill by name since the PID we have is for the sed pipeline, not the app itself
pkill -f chip-all-clusters-app 2>/dev/null || true
sleep 1
pkill -9 -f chip-all-clusters-app 2>/dev/null || true

# Print summary
echo ""
echo "========================================"
echo "=== TEST SUMMARY ==="
echo "========================================"

if [ "$MDNS_BACKEND" = "builtin" ] || [ "$MDNS_BACKEND" = "all" ]; then
    if [ $BUILTIN_RESULT -eq 0 ]; then
        echo "  Builtin backend:  PASSED"
    else
        echo "  Builtin backend:  FAILED"
    fi
fi

if [ "$MDNS_BACKEND" = "avahi" ] || [ "$MDNS_BACKEND" = "all" ]; then
    if [ $AVAHI_RESULT -eq 0 ]; then
        echo "  Avahi backend:    PASSED"
    else
        echo "  Avahi backend:    FAILED"
    fi
fi

if [ "$MDNS_BACKEND" = "zeroconf" ] || [ "$MDNS_BACKEND" = "all" ]; then
    if [ $ZEROCONF_RESULT -eq 0 ]; then
        echo "  Zeroconf backend: PASSED"
    else
        echo "  Zeroconf backend: FAILED"
    fi
fi

echo ""
if [ $OVERALL_RESULT -eq 0 ]; then
    echo "=== ALL TESTS PASSED ==="
else
    echo "=== SOME TESTS FAILED ==="
fi


exit $OVERALL_RESULT
