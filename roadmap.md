Matter Device Commissioning Implementation Roadmap
### Phase 1: Transport Layer Foundation

### Patch 1.1: Exchange Initiation

**Purpose:** Enable initiating exchanges (currently only accepting is supported)

**Components:**

- `Exchange::initiate()` method to start an exchange as initiator
- Initiator flag (`I` bit) handling in message headers
- Exchange ID generation for outgoing exchanges
- Exchange state tracking for initiator role
- Unit tests for exchange initiation

**Files to modify:**

- `rs-matter/src/transport/exchange.rs`
- `rs-matter/src/transport/proto_hdr.rs`

---

### Patch 1.2: Unsecured Session Management for Initiator

**Purpose:** Create and manage unsecured sessions for handshake initiation

**Components:**

- Create unsecured unicast session to peer address
- Session slot reservation for pending secure session
- Peer address tracking for message routing
- Session state machine for initiator flow
- Unit tests for session creation

**Files to modify:**

- `rs-matter/src/transport/session.rs`
- `rs-matter/src/transport/mrp.rs` (if MRP changes needed)

---

### Phase 2: Secure Channel - PASE Initiator

### Patch 2.1: SPAKE2+ Prover Implementation

**Purpose:** Complete the prover (initiator) side of SPAKE2+

**Components:**

- `setup_prover()` method (analogous to existing `setup_verifier()`)
- Prover-side transcript hash computation
- `verify_cb()` for prover to verify verifier's confirmation
- Prover key schedule derivation
- Comprehensive unit tests with RFC test vectors

**Files to modify:**

- `rs-matter/src/sc/pase/spake2p.rs`

---

### Patch 2.2: PASE Initiator Protocol Handler

**Purpose:** Implement commissioner-side PASE handshake

**Components:**

- `PaseInitiator` struct with state machine
- Send `PBKDFParamRequest`, receive `PBKDFParamResponse`
- Send `Pake1`, receive `Pake2`
- Send `Pake3`, receive `StatusReport`
- Session key derivation and secure session establishment
- Error handling and timeout management
- Integration tests with existing PASE responder

**Files to modify/create:**

- `rs-matter/src/sc/pase.rs` (add initiator module)
- `rs-matter/src/sc/pase/initiator.rs` (new file)

---

### Phase 3: Interaction Model Client

### Patch 3.1: IM Client Core

**Purpose:** Send IM requests and process responses

**Components:**

- `ImClient` struct for managing IM transactions
- `invoke()` method - send `InvokeRequest`, receive `InvokeResponse`
- `read()` method - send `ReadRequest`, receive `ReportData`
- `write()` method - send `WriteRequest`, receive `WriteResponse`
- Response parsing and error extraction
- Status code handling
- Unit tests with mock exchanges

**Files to create:**

- `rs-matter/src/im/client.rs`

**Files to modify:**

- `rs-matter/src/im.rs` (add client module export)

---

### Patch 3.2: Commissioning Command Types

**Purpose:** Type-safe request/response structures for commissioning commands

**Components:**

*General Commissioning Cluster (0x0030):*

- `ArmFailSafeRequest` / `ArmFailSafeResponse`
- `SetRegulatoryConfigRequest` / `SetRegulatoryConfigResponse`
- `CommissioningCompleteRequest` / `CommissioningCompleteResponse`

*Operational Credentials Cluster (0x003E):*

- `CertificateChainRequest` / `CertificateChainResponse`
- `AttestationRequest` / `AttestationResponse`
- `CSRRequest` / `CSRResponse`
- `AddTrustedRootCertificateRequest`
- `AddNOCRequest` / `NOCResponse`

*Basic Information Cluster (0x0028):*

- Attribute read types for `VendorID`, `ProductID`

**Files to create:**

- `rs-matter/src/im/client/commands.rs` (or integrate with existing cluster defs)

---

### Phase 4: Device Attestation

### Patch 4.1: X.509 Certificate Parsing Utilities

**Purpose:** Extract Matter-specific data from DER-encoded certificates

**Components:**

- Extract Subject Key Identifier (SKID)
- Extract Authority Key Identifier (AKID)
- Extract public key (P-256)
- Extract Matter Vendor ID extension (OID 1.3.6.1.4.1.37244.2.1)
- Extract Matter Product ID extension (OID 1.3.6.1.4.1.37244.2.2)
- Certificate validity period checking
- Unit tests with real DAC/PAI/PAA certificates

**Files to create:**

- `rs-matter/src/cert/x509.rs`

**Files to modify:**

- `rs-matter/src/cert.rs`

---

### Patch 4.2: PAA Trust Store

**Purpose:** Store and retrieve trusted Product Attestation Authority certificates

**Components:**

- `AttestationTrustStore` trait definition
- `ArrayAttestationTrustStore` - in-memory array implementation
- `FileAttestationTrustStore` - filesystem-based implementation (optional, feature-gated)
- PAA lookup by SKID
- Test PAA certificates for development
- Unit tests

**Files to create:**

- `rs-matter/src/credentials/trust_store.rs`
- `rs-matter/src/credentials.rs` (new module)

---

### Patch 4.3: Certification Declaration Verification

**Purpose:** Parse and verify CMS-signed Certification Declarations

**Components:**

- CMS/PKCS#7 SignedData parsing
- CD signing key store with CSA well-known keys
- CD signature verification
- CD payload parsing (TLV structure)
- CD content validation rules
- Unit tests with real CDs

**Files to create:**

- `rs-matter/src/credentials/cd.rs`
- `rs-matter/src/credentials/cd_keys.rs`

---

### Patch 4.4: Attestation Verifier

**Purpose:** Complete device attestation verification logic

**Components:**

- `AttestationVerifier` struct
- Certificate format validation
- VID/PID extraction and matching
- Attestation signature verification
- Certificate chain validation (DAC → PAI → PAA)
- Nonce freshness verification
- CD validation against device info
- `AttestationVerificationResult` error enum
- Comprehensive unit tests
- Integration tests with test device attestation data

**Files to create:**

- `rs-matter/src/credentials/attestation_verifier.rs`

---

### Phase 5: Secure Channel - CASE Initiator

### Patch 5.1: CASE Initiator Protocol Handler

**Purpose:** Implement commissioner-side CASE handshake

**Components:**

- `CaseInitiator` struct with state machine
- Destination ID computation
- Send `Sigma1`, receive `Sigma2`
- Sigma2 decryption and verification
- Send `Sigma3`, receive `StatusReport`
- Session key derivation
- Session resumption support (optional, can be separate patch)
- Integration tests with existing CASE responder

**Files to modify/create:**

- `rs-matter/src/sc/case.rs`
- `rs-matter/src/sc/case/initiator.rs` (new file)

---

### Phase 6: Commissioner State Machine

### Patch 6.1: Commissioner Core

**Purpose:** Orchestrate the complete commissioning flow

**Components:**

- `Commissioner` struct
- Commissioning state machine
- `commission()` async method orchestrating full flow
- Error handling and rollback support
- Progress callbacks/notifications
- Timeout management

**Commissioning stages:**

1. Device discovery (use existing mDNS querier)
2. PASE establishment
3. Read commissioning info
4. ArmFailSafe
5. Device attestation
6. CSR request
7. NOC generation and provisioning
8. Network setup (if applicable)
9. CASE establishment
10. CommissioningComplete

**Files to create:**

- `rs-matter/src/commissioner.rs`
- `rs-matter/src/commissioner/state.rs`

---

### Patch 6.2: NOC Generation

**Purpose:** Generate Node Operational Certificates for commissioned devices

**Components:**

- NOC generation from CSR
- ICAC generation (optional)
- Root CA management
- IPK generation
- Fabric credential management
- Unit tests

**Files to create:**

- `rs-matter/src/commissioner/noc_generator.rs`

---

### Patch 6.3: Network Commissioning Client (Optional)

**Purpose:** Configure device network credentials

**Components:**

- Network Commissioning cluster client commands
- `ScanNetworks` request/response
- `AddOrUpdateWiFiNetwork` / `AddOrUpdateThreadNetwork`
- `ConnectNetwork` request/response
- Network type detection

**Files to create:**

- `rs-matter/src/commissioner/network.rs`

---

### Phase 7: Integration & Testing

### Patch 7.1: Commissioner Integration Tests

**Purpose:** End-to-end commissioning tests

**Components:**

- Test commissioner against rs-matter device
- Test commissioner against chip-tool simulated device
- Test with various device configurations
- Failure mode testing
- Performance benchmarks

**Files to create:**

- `rs-matter/tests/commission_integration.rs`

---

### Patch 7.2: xtask Commission Tool

**Purpose:** CLI tool for commissioning devices

**Components:**

- Commission command implementation
- Device discovery with discriminator/passcode
- Progress output
- Error reporting
- Example usage documentation

**Files to modify/create:**

- `xtask/src/commission.rs`
- `xtask/src/main.rs`

---

## Summary Table

| Phase | Patch | Description | Dependencies |
| --- | --- | --- | --- |
| 1 | 1.1 | Exchange Initiation | None |
| 1 | 1.2 | Unsecured Session (Initiator) | 1.1 |
| 2 | 2.1 | SPAKE2+ Prover | None |
| 2 | 2.2 | PASE Initiator | 1.1, 1.2, 2.1 |
| 3 | 3.1 | IM Client Core | 1.1, 1.2 |
| 3 | 3.2 | Commissioning Command Types | 3.1 |
| 4 | 4.1 | X.509 Parsing Utilities | None |
| 4 | 4.2 | PAA Trust Store | None |
| 4 | 4.3 | CD Verification | 4.1 |
| 4 | 4.4 | Attestation Verifier | 4.1, 4.2, 4.3 |
| 5 | 5.1 | CASE Initiator | 1.1, 1.2 |
| 6 | 6.1 | Commissioner Core | 2.2, 3.1, 3.2, 4.4, 5.1 |
| 6 | 6.2 | NOC Generation | 4.1 |
| 6 | 6.3 | Network Commissioning Client | 3.1 |
| 7 | 7.1 | Integration Tests | 6.1 |
| 7 | 7.2 | xtask Commission Tool | 6.1 |

---

## Recommended Submission Strategy

**Wave 1 - Foundation (can be developed in parallel):**

- Patch 1.1: Exchange Initiation
- Patch 2.1: SPAKE2+ Prover
- Patch 4.1: X.509 Parsing Utilities
- Patch 4.2: PAA Trust Store

**Wave 2 - Core Protocols:**

- Patch 1.2: Unsecured Session (Initiator)
- Patch 2.2: PASE Initiator
- Patch 3.1: IM Client Core
- Patch 4.3: CD Verification

**Wave 3 - Commissioning Logic:**

- Patch 3.2: Commissioning Command Types
- Patch 4.4: Attestation Verifier
- Patch 5.1: CASE Initiator
- Patch 6.2: NOC Generation

**Wave 4 - Integration:**

- Patch 6.1: Commissioner Core
- Patch 6.3: Network Commissioning Client (optional)

**Wave 5 - Testing & Tooling:**

- Patch 7.1: Integration Tests
- Patch 7.2: xtask Commission Tool

---

## Estimated Complexity

| Patch | Complexity | Estimated Effort |
| --- | --- | --- |
| 1.1 Exchange Initiation | Medium | Medium |
| 1.2 Unsecured Session | Medium | Medium |
| 2.1 SPAKE2+ Prover | Low-Medium | Low (mostly exists) |
| 2.2 PASE Initiator | Medium-High | Medium-High |
| 3.1 IM Client Core | Medium | Medium |
| 3.2 Command Types | Low | Low |
| 4.1 X.509 Parsing | Medium | Medium |
| 4.2 PAA Trust Store | Low | Low |
| 4.3 CD Verification | Medium-High | Medium-High |
| 4.4 Attestation Verifier | High | High |
| 5.1 CASE Initiator | Medium-High | Medium-High |
| 6.1 Commissioner Core | High | High |
| 6.2 NOC Generation | Medium | Medium |
| 6.3 Network Commissioning | Low-Medium | Low-Medium |
| 7.1 Integration Tests | Medium | Medium |
| 7.2 xtask Tool | Low | Low |
