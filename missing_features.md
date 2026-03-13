Missing Features for Device Commissioning (Controller)

## Overview

This document contains analysis done by Claude Code w/ Opus on the missing features from the `rs-matter` SDK to implement device commissioning. Some of the items here (mDNS, PASE, CASE) have been independently confirmed with the maintainer team of `rs-matter` other items have not yet been confirmed and should be investigated further before moving forward with an implementation.

## Analysis

Based on my analysis of the `rs-matter` codebase, here's what would be needed to implement `chip-tool`-like commissioning functionality (specifically `pairing onnetwork`):

### Current State: Device-Side Only

`rs-matter` is a **device-side implementation**. It can:

- **Receive** PASE connections (respond to `PBKDFParamRequest`)
- **Receive** CASE connections (respond to `Sigma1`)
- **Handle** commissioning commands (`ArmFailSafe`, `AddNOC`, `CommissioningComplete`)

But it **cannot initiate** any of these - which is what a controller needs.

### Missing Components

### 1. **mDNS Client for Device Discovery**

- **Current**: `rs-matter/src/mdns.rs` only advertises (device role)
- **Needed**: DNS-SD query capability to find commissionable devices
    - Query for `_matterc._udp.local` (commissioning mode)
    - Filter by discriminator
    - Resolve IP addresses

### 2. **Client-Side PASE Session Establishment**

- **Current**: `rs-matter/src/sc/pake.rs` handles *responding* to PASE (lines 1-450+)
- **Needed**: Ability to *initiate* PASE:
    - Send `PBKDFParamRequest` with setup PIN
    - Handle `PBKDFParamResponse`
    - Execute SPAKE2+ as the initiator
    - Derive session keys

### 3. **Client-Side CASE Session Establishment**

- **Current**: `rs-matter/src/sc/case.rs` handles *responding* to CASE
- **Needed**: Ability to *initiate* CASE:
    - Send `Sigma1` message
    - Process `Sigma2` response
    - Send `Sigma3` with signature
    - Derive operational session keys

### 4. **Interaction Model Client (Command Invocation)**

- **Current**: `rs-matter/src/im/` only handles *receiving* IM messages
- **Needed**: Ability to *send* cluster commands and read/write attributes:
    
    ```rust
    // Hypothetical API
    exchange.invoke_command(
        endpoint: 0,
        cluster: GeneralCommissioning::ID,
        command: ArmFailSafe::ID,
        request: ArmFailSafeRequest { expiry_length_seconds: 900, breadcrumb: 0 }
    ).await?;
    ```
    

### 5. **Network Connection Initiation**

- **Current**: Transport layer at `rs-matter/src/transport.rs:163-185` has `initiate()` but it:
    - Requires an **existing session** (see line 173: `get_for_node()`)
    - Has a TODO at line 170-171: "once we have mDNS lookups in place, create a new session if no suitable one is found"
- **Needed**: Ability to establish a new UDP connection to a discovered device address

### 6. **Commissioning Orchestration State Machine**

The `pairing onnetwork` flow requires orchestrating these steps in order:

1. mDNS discovery → find device
2. UDP connect → establish transport
3. PASE session → secure channel with passcode
4. `ArmFailSafe` → start commissioning window
5. Device attestation → verify device authenticity
6. `CSRRequest` → get device's CSR
7. `AddTrustedRootCertificate` → install root CA
8. `AddNOC` → install operational certificate
9. `CommissioningComplete` → finalize
10. CASE session → operational secure channel

### 7. **Certificate Authority / Credential Generation**

- **Needed**: Ability to generate NOCs for devices being commissioned
- **Current**: Only stores certificates received from controllers

### 8. **Device Attestation Verification**

- **Current**: Can *respond* to attestation requests
- **Needed**: Ability to *verify* attestation from devices:
    - Validate DAC/PAI certificate chain
    - Verify attestation signatures
    - Check against CSA Device Certification List

### Existing Infrastructure That Could Be Leveraged

Some building blocks exist:

| Component | Location | Reusability |
| --- | --- | --- |
| SPAKE2+ crypto | `rs-matter/src/sc/pake/spake2p.rs` | ✅ Can be used for initiator |
| CASE crypto (ECDH, signatures) | `rs-matter/src/sc/case.rs` | ✅ Crypto is symmetric |
| TLV encoding/decoding | `rs-matter/src/tlv/` | ✅ Fully reusable |
| Certificate parsing | `rs-matter/src/cert.rs` | ✅ Fully reusable |
| Exchange infrastructure | `rs-matter/src/transport/exchange.rs:889-907` | ⚠️ `Exchange::initiate()` exists but needs session |
| Message encoding | `rs-matter/src/transport/packet.rs` | ✅ Fully reusable |
| Fabric management | `rs-matter/src/fabric.rs` | ⚠️ Designed for device fabric storage |

### Rough Effort Estimate

To implement `pairing onnetwork` functionality, you would need to add:

1. **mDNS Client** - New module (~500-800 lines)
2. **PASE Initiator** - Modify `sc/pake.rs` (~300-400 lines)
3. **CASE Initiator** - Modify `sc/case.rs` (~300-400 lines)
4. **IM Client Layer** - New module (~800-1200 lines)
5. **Commissioning Orchestrator** - New module (~600-1000 lines)
6. **Attestation Verifier** - New module (~400-600 lines)
7. **NOC Generation** - New module (~300-500 lines)

This is a significant undertaking - essentially building the other half of the Matter protocol stack.
