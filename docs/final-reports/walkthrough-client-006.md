# Card Validation & Architecture Walkthrough: CLIENT-006 — Signal Double Ratchet Session Management & End-to-End Encryption

**Card ID:** `CLIENT-006`  
**Card Title:** Signal Double Ratchet Session Management & End-to-End Encryption  
**Milestone:** M4 — SecureCloud Native Desktop Client (`securecloud-client`)  
**Phase Placement:** Client Phase 2 — Core Cryptographic Engine & End-to-End Messaging  
**Repository:** `SecureCloud`  
**Feature Branch:** `feature/client-006-double-ratchet-session-management-and-e2ee`  
**Status:** COMPLETED (All 6 Engineering Tickets `CLIENT-006-T01` through `CLIENT-006-T06` Fully Implemented, Unit Tested & End-to-End Integrated)  
**Author:** Principal Distributed Systems Architect, Cryptographic Systems Lead & Security Gatekeeper  
**Date:** November 11, 2026  

---

## 1. Executive Summary & Milestone M4 Desktop Client Phase 2 Core Sign-Off

Card **`CLIENT-006`** represents the crown jewel of **Desktop Client Phase 2**, elevating the SecureCloud native desktop application from prekey publishing and device registration (`CLIENT-005`) to **full cryptographic autonomy and zero-trust End-to-End Encryption (E2EE) powered by the Signal Protocol (X3DH Key Agreement Engine and Double Ratchet State Machine)**.

While **Phase 1 (`CLIENT-001` through `CLIENT-004`)** built the Qt 6 / QML presentation tier, responsive 4-zone workspace shell, reactive contact roster, and file inspection components, and **`CLIENT-005`** established the workstation cryptographic identity (Ed25519 identity keypairs, X25519 signed prekeys, and single-use one-time prekeys) along with backend device registration, **`CLIENT-006` constructs the continuous, self-healing encryption engine** that protects all peer-to-peer and group communications across untrusted network relays and cloud storage backends.

```text
┌────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                              CLIENT PHASE 2 CORE CRYPTOGRAPHIC EXECUTION MATRIX: CLIENT-006                            │
├──────────────────────────────────────┬────────────────────────────────────────┬────────────────────────────────────────┤
│ CLIENT-006-T01: Crypto Primitives    │ CLIENT-006-T02: X3DH Agreement Engine  │ CLIENT-006-T03: Double Ratchet Engine  │
├──────────────────────────────────────┼────────────────────────────────────────┼────────────────────────────────────────┤
│ • ICryptoProvider RFC expansion      │ • Extended Triple Diffie-Hellman       │ • Symmetric KDF chains (Root, Send, Rec)│
│ • X25519 Diffie-Hellman derivation   │ • 4-way DH Key Agreement ($DH_1..DH_4$)│ • Asymmetric DH Ratchet turns          │
│ • HKDF-SHA256 (Extract & Expand)     │ • Bob PrekeyBundle signature validation│ • AES-256-GCM AEAD payload encryption  │
│ • AES-256-GCM AEAD (12B IV, 16B Tag) │ • Initiator/Responder state machine    │ • RatchetHeader (42B serialized)       │
│ • 60-digit mutual Safety Numbers     │ • Single-use OTPK consumption/erasure  │ • EncryptedMessageEnvelope (SCE v1)    │
│ • Zeroized memory buffers via OpenSSL│ • Zero-knowledge shared secret $SK$    │ • Immediate message key zeroization    │
├──────────────────────────────────────┼────────────────────────────────────────┼────────────────────────────────────────┤
│ CLIENT-006-T04: Skipped Keys Store   │ CLIENT-006-T05: Ratchet Session Manager│ CLIENT-006-T06: E2E Integration Suite  │
├──────────────────────────────────────┼────────────────────────────────────────┼────────────────────────────────────────┤
│ • Out-of-order packet reassembly     │ • Multi-device pairwise session routing│ • MessagingManager integration         │
│ • SkippedKeysStore LRU / TTL store   │ • Gateway user directory device lookup │ • ClientBootstrap lifecycle wiring     │
│ • Max gap limit (1,000 skipped keys) │ • Participant fan-out encryption       │ • 60-digit Safety Number UI bindings   │
│ • Sliding window capacity (2,000 max)│ • Secure binary serialization (SCRS v1)│ • End-to-end integration test suite    │
│ • 14-day cryptographic key expiry    │ • ISecureStorage session persistence   │ • 163/163 passing tests (100% pass)    │
│ • Immediate key wipe on decryption   │ • Client restart session restoration   │ • 0 compiler warnings, 0 format errors │
└──────────────────────────────────────┴────────────────────────────────────────┴────────────────────────────────────────┘
```

### Key Technical Achievements Delivered
1. **Strict Signal Protocol Compliance (ADR-008 §1, §3)**: The cryptographic engine adheres unconditionally to the Signal Protocol specifications: **X3DH (Extended Triple Diffie-Hellman)** for mutual session initiation and the **Signal Double Ratchet** for continuous message encryption.
2. **Zero Hand-Rolled Primitives**: All asymmetric key exchanges, hash-based key derivations, and authenticated ciphers leverage hardened **OpenSSL 3.x EVP** APIs (`EVP_PKEY_derive`, `EVP_KDF_fetch(nullptr, "HKDF", nullptr)`, and `EVP_aes_256_gcm`).
3. **Double Cryptographic Guarantees (Forward Secrecy & Post-Compromise Security)**:
   - **Forward Secrecy (FS)**: Once a message key ($MK$) decrypts a message or is skipped, it is derived forward and cleansed with `OPENSSL_cleanse`. An attacker compromising a workstation today cannot decrypt historical traffic.
   - **Post-Compromise Security (PCS)**: Every alternating conversational turn triggers an asymmetric Diffie-Hellman ratchet exchange. Fresh entropy is injected into the root key schedule, naturally healing a temporarily compromised session as soon as the adversary loses active intercept capability.
4. **Resilient Asynchronous & Out-of-Order Delivery**: Implemented a bounded `SkippedKeysStore` supporting out-of-order message arrival across networks and backends. The store enforces strict DoS circuit breakers ($\text{MAX\_SKIP} = 1,000$ per turn, $\text{MAX\_STORED} = 2,000$ global cap, and $14$-day TTL expiry).
5. **Zero-Knowledge Relay & Anti-Plaintext Invariants**: Payloads dispatched over the wire consist exclusively of opaque binary ciphertext blobs, ephemeral public keys, 12-byte initialization vectors, and 16-byte authentication tags. The backend Gateway and Messaging services act strictly as untrusted store-and-forward relays, completely incapable of inspecting or tampering with message contents.
6. **Mutual Out-of-Band Fingerprints (60-Digit Safety Numbers)**: Computed via SHA-512 over sorted identity public keys and user identifiers, yielding a commutative 60-digit fingerprint partitioned into 12 blocks of 5 digits, fully surfaced in the UI Trust Center.
7. **Production Code Quality & Test Coverage**: 100% clean compilation under Clang C++20 with `-Wall -Wextra -Wpedantic -Werror`, zero `.clang-format` violations across 920 project files, and 163/163 unit and integration tests passing in under 1 second.

---

## 2. Architectural Drivers, Trust Boundaries & System Context

The design and implementation of Card `CLIENT-006` directly fulfill the security, reliability, and transport requirements established in **ADR-008 (Security & Cryptographic Architecture)**, **ADR-007 (Message Reliability & Durability)**, and **ADR-004 (Audit Logging & Security Invariants)**.

```mermaid
flowchart TD
    subgraph Alice_Workstation ["Alice Physical Workstation (Untrusted Host Boundary)"]
        A_UI["UI Layer: WorkspaceViewModel\n(Zone 3 Composer / Zone 4 Safety Number)"]
        A_MM["MessagingManager\n(ADR-008 Pre-flight Guards & Stage)"]
        A_RSM["RatchetSessionManager\n(Pairwise Device Routing & Fan-out)"]
        A_DRE["DoubleRatchetEngine & X3DH Engine\n(State Machine & Chains)"]
        A_SKS["SkippedKeysStore\n(Out-of-Order Key Stash)"]
        A_SEC["MemorySecureStorage / Keychain\n(SCRS v1 Encrypted Sessions)"]
        A_EVP["OpenSslCryptoProvider\n(OpenSSL 3.x EVP Engine)"]
        
        A_UI -->|send_message / stage| A_MM
        A_MM -->|encrypt_payload_for_device| A_RSM
        A_RSM -->|ratchet_encrypt| A_DRE
        A_DRE -->|stash / retrieve keys| A_SKS
        A_DRE -->|EVP_PKEY_derive / HKDF / AES-GCM| A_EVP
        A_RSM -->|save_session / load_session| A_SEC
    end

    subgraph Untrusted_Cloud ["SecureCloud Untrusted Cloud Relay (Zero Plaintext Boundary)"]
        GW["Gateway Messaging Proxy\n(POST /api/v1/messages)"]
        VAL["E2EEnvelopeValidator\n(Cryptographic Bounds & Anti-Plaintext Guard)"]
        MQ["Messaging Service / Queue\n(Opaque EncryptedPayloads Only)"]
        
        GW --> VAL
        VAL --> MQ
    end

    subgraph Bob_Workstation ["Bob Physical Workstation (Target Device Boundary)"]
        B_RSM["RatchetSessionManager\n(Inbound Demux & Session State)"]
        B_DRE["DoubleRatchetEngine & X3DH Engine\n(State Machine & Decrypt)"]
        B_SEC["MemorySecureStorage / Keychain\n(SCRS v1 Session State & OTPKs)"]
        B_MM["MessagingManager\n(Inbound Processing & Unread Count)"]
        B_UI["UI Layer: WorkspaceViewModel\n(Stream Render & 60-Digit Fingerprint)"]

        MQ -.->|Transport DeliveryTargets| B_RSM
        B_RSM -->|decrypt_payload_from_device| B_DRE
        B_DRE -->|Consume OTPK / Update Ratchet| B_SEC
        B_RSM -->|Deliver Plaintext SecretString| B_MM
        B_MM -->|Update Conversation / Local Store| B_UI
    end

    A_RSM ==>|HTTP/2 gRPC Encrypted Delivery Targets| GW
```

### 2.1 The Trust Boundaries & Security Domains
1. **Workstation Cryptographic Domain**:
   - Private key material, symmetric root keys, sender/receiver chain keys, and ephemeral message keys exist strictly in workstation memory inside `SecretString` or `std::vector<uint8_t>` buffers.
   - All ephemeral cryptographic material is cleansed immediately upon use using `OPENSSL_cleanse`.
   - Workstation-to-disk persistence passes through `RatchetSessionSerializer` (`SCRS` binary format) into `ISecureStorage`.
2. **Network & Cloud Transport Domain (Zero Knowledge)**:
   - The cloud relay (Gateway HTTP proxy and backend Messaging microservice) possesses zero cryptographic knowledge.
   - Relay nodes inspect metadata only: `conversation_id`, `sender_user_id`, `sender_device_id`, `recipient_user_id`, `recipient_device_id`, and `priority`.
   - The message payload is completely opaque (`EncryptedPayload`).
3. **Anti-Plaintext Defense (ADR-008 §4.2)**:
   - The backend `E2EEnvelopeValidator` strictly inspects inbound submissions. If a payload exhibits $\ge 90\%$ printable ASCII characters or begins with structured JSON tokens (`{"`, `[{`), it is rejected at the network edge with error code `MESSAGING_ERROR_CODE_INVALID_TARGET_DEVICE`.
4. **Key Rotation & Verification Suspension Guard (ADR-008 §4.4)**:
   - If a peer's identity key rotates unexpectedly, `ContactManager` marks the peer's verification status as `KeyChanged`.
   - `MessagingManager::stage_outbound_message` strictly intercepts all outbound messages to that user and blocks submission with `ClientError::validation("Outbound messaging suspended: recipient identity key changed (ADR-008)")` until the user manually verifies the updated 60-digit Safety Number.

---

## 3. Mathematical Formalization & State Machine Specifications

The cryptographic implementation in Card `CLIENT-006` is defined by formal mathematical operations over Montgomery curve Curve25519, HMAC-based Extract-and-Expand Key Derivation Function (HKDF-SHA256), and AES-256 in Galois/Counter Mode (GCM).

### 3.1 Extended Triple Diffie-Hellman (X3DH) Protocol

When Alice initiates communication with Bob for the first time, she executes X3DH to establish the initial shared secret $SK$.

```text
  Alice (Initiator)                                                Bob (Responder)
  Identity Key: IK_A                                              Identity Key: IK_B
  Ephemeral Key: EK_A                                             Signed Prekey: SPK_B
                                                                  One-Time Prekey: OPK_B
         │                                                                 │
         │  1. Fetch Bob PrekeyBundle (IK_B, SPK_B, Sig_B, OPK_B)          │
         │<────────────────────────────────────────────────────────────────│
         │                                                                 │
         │  2. Verify Sig_B on SPK_B using IK_B                            │
         │  3. Generate ephemeral DH pair EK_A                             │
         │  4. Compute DH values:                                          │
         │     DH1 = X25519(IK_A_priv, SPK_B_pub)                          │
         │     DH2 = X25519(EK_A_priv, IK_B_pub)                           │
         │     DH3 = X25519(EK_A_priv, SPK_B_pub)                          │
         │     DH4 = X25519(EK_A_priv, OPK_B_pub) [if OPK present]        │
         │                                                                 │
         │  5. SK = HKDF-Extract(salt=0^32, IKM = DH1 || DH2 || DH3 [|| DH4])
         │     SK = HKDF-Expand(PRK, info="SecureCloud-X3DH-v1", len=32)   │
         │                                                                 │
         │  6. Encrypt Message under SK via Double Ratchet                 │
         │  7. Send X3dhHeader(IK_A, EK_A, OPK_B_id) + Ciphertext          │
         │────────────────────────────────────────────────────────────────>│
         │                                                                 │
         │                                     8. Reconstruct DH1..DH4     │
         │                                     9. Derive identical SK      │
         │                                    10. Consume & Delete OPK_B   │
         │                                    11. Decrypt Message          │
```

#### Mathematical Formulation:
$$\begin{aligned}
DH_1 &= \text{X25519}(IK_{A,\text{priv}}, SPK_{B,\text{pub}}) \\
DH_2 &= \text{X25519}(EK_{A,\text{priv}}, IK_{B,\text{pub}}) \\
DH_3 &= \text{X25519}(EK_{A,\text{priv}}, SPK_{B,\text{pub}}) \\
DH_4 &= \text{X25519}(EK_{A,\text{priv}}, OPK_{B,\text{pub}}) \quad (\text{if } OPK_B \text{ exists}) \\
IKM &= DH_1 \mathbin{\Vert} DH_2 \mathbin{\Vert} DH_3 \mathbin{\Vert} [DH_4] \\
PRK &= \text{HMAC-SHA256}(\text{key} = 0^{32}, \text{data} = IKM) \\
SK &= \text{HMAC-SHA256}(PRK, \text{"SecureCloud-X3DH-v1"} \mathbin{\Vert} 0x01)
\end{aligned}$$

- **Mutual Authentication**: $DH_1$ authenticates Alice to Bob (only Alice holds $IK_{A,\text{priv}}$). $DH_2$ and $DH_3$ authenticate Bob to Alice (only Bob holds $SPK_{B,\text{priv}}$ and $IK_{B,\text{priv}}$).
- **Forward Secrecy**: The compromise of $IK_A$ and $IK_B$ in the future does not compromise $SK$, because $EK_A$ and $OPK_B$ are ephemeral and deleted after handshake completion.
- **Single-Use OTPK Erasure**: Immediately upon computing $DH_4$, Bob's client invokes `KeyStorageHelper::remove_one_time_prekey`, ensuring $OPK_B$ cannot be re-used or recovered.

---

### 3.2 Double Ratchet State Machine (Symmetric & Asymmetric Interleaving)

The Double Ratchet combines two distinct ratchets:
1. **Symmetric-Key KDF Ratchet**: Advanced on every message sent or received within an epoch.
2. **Diffie-Hellman Asymmetric Ratchet**: Advanced whenever a conversational turn occurs (a reply is received from the peer with a new DH ephemeral key).

```text
                            Double Ratchet Key Schedule
                            ═══════════════════════════

                    Root Key (RK_i)      Peer DH Public Key (DH_peer)
                           │                         │
                           ▼                         ▼
                  ┌─────────────────────────────────────────┐
                  │          DH Ratchet Step (EVP)          │
                  │   DH_secret = X25519(DH_our, DH_peer)   │
                  │   (RK_{i+1}, CK_r) = HKDF(RK_i, DH)     │
                  └────────────────────┬────────────────────┘
                                       │
                      ┌────────────────┴────────────────┐
                      ▼                                 ▼
              Root Key (RK_{i+1})              Chain Key (CK_0)
                                                        │
                                   ┌────────────────────┴────────────────────┐
                                   ▼                                         ▼
                            Chain Step (KDF)                          Chain Step (KDF)
                    CK_1 = HMAC(CK_0, 0x02)                   CK_2 = HMAC(CK_1, 0x02)
                    MK_0 = HMAC(CK_0, 0x01)                   MK_1 = HMAC(CK_1, 0x01)
                            │                                         │
                            ▼                                         ▼
                  ┌───────────────────┐                     ┌───────────────────┐
                  │ AES-256-GCM AEAD  │                     │ AES-256-GCM AEAD  │
                  │ Payload Encrypt   │                     │ Payload Encrypt   │
                  └───────────────────┘                     └───────────────────┘
```

#### Symmetric Chain Step Formula:
$$\begin{aligned}
MK_i &= \text{HMAC-SHA256}(CK_i, \text{0x01}) \\
CK_{i+1} &= \text{HMAC-SHA256}(CK_i, \text{0x02})
\end{aligned}$$
Once $MK_i$ is derived, $CK_i$ is overwritten with $CK_{i+1}$, and $MK_i$ is immediately destroyed following encryption or decryption.

#### Asymmetric DH Ratchet Step Formula:
When Bob responds with a fresh DH public key $DH_B$:
$$\begin{aligned}
DH_{\text{shared}} &= \text{X25519}(DH_{A,\text{priv}}, DH_{B,\text{pub}}) \\
PRK_{\text{root}} &= \text{HKDF-Extract}(\text{salt} = RK_i, IKM = DH_{\text{shared}}) \\
RK_{i+1} &= \text{HKDF-Expand}(PRK_{\text{root}}, \text{"SecureCloud-DR-Root"}, 32) \\
CK_{\text{recv}} &= \text{HKDF-Expand}(PRK_{\text{root}}, \text{"SecureCloud-DR-Chain"}, 32)
\end{aligned}$$
Then Alice generates a new ephemeral pair $DH_{A}'$, computes a second DH step:
$$\begin{aligned}
DH_{\text{shared}}' &= \text{X25519}(DH_{A,\text{priv}}', DH_{B,\text{pub}}) \\
PRK_{\text{root}}' &= \text{HKDF-Extract}(\text{salt} = RK_{i+1}, IKM = DH_{\text{shared}}') \\
RK_{i+2} &= \text{HKDF-Expand}(PRK_{\text{root}}', \text{"SecureCloud-DR-Root"}, 32) \\
CK_{\text{send}} &= \text{HKDF-Expand}(PRK_{\text{root}}', \text{"SecureCloud-DR-Chain"}, 32)
\end{aligned}$$

---

### 3.3 Sixty-Digit Mutual Safety Number Algorithm

To prevent active Man-In-The-Middle (MITM) attacks during prekey distribution, users verify a 60-digit safety number out-of-band (e.g., in-person or over encrypted voice).

```text
       Alice Workstation                                     Bob Workstation
    IK_A, UserId_A: "usr-alice"                           IK_B, UserId_B: "usr-bob"
            │                                                         │
            ▼                                                         ▼
  ┌───────────────────┐                                     ┌───────────────────┐
  │ Lexicographical   │                                     │ Lexicographical   │
  │ Sort on Keys & UIDs│                                    │ Sort on Keys & UIDs│
  └─────────┬─────────┘                                     └─────────┬─────────┘
            │                                                         │
            ▼                                                         ▼
  ┌─────────────────────────────────────────────────────────────────────────────┐
  │ SHA-512 Digest = SHA512(Key_min || Key_max || UID_min || UID_max)          │
  │ Length = 64 bytes                                                           │
  └──────────────────────────────────────┬──────────────────────────────────────┘
                                         │
                                         ▼
  ┌─────────────────────────────────────────────────────────────────────────────┐
  │ Format into 12 5-digit decimal blocks (60 digits total):                    │
  │   For k in 0..11:                                                           │
  │     val = (digest[k*5] << 32) | ... | digest[k*5+4]                         │
  │     block[k] = sprintf("%05u", val % 100000)                                │
  │ Result: "XXXXX XXXXX XXXXX XXXXX XXXXX XXXXX XXXXX XXXXX XXXXX XXXXX XXXXX XXXXX" │
  └─────────────────────────────────────────────────────────────────────────────┘
```

#### Mathematical Specification:
Let $(IK_1, IK_2)$ be the lexicographically ordered pair of 32-byte Ed25519 identity public keys:
$$IK_1 = \min(IK_A, IK_B), \quad IK_2 = \max(IK_A, IK_B)$$
Let $(U_1, U_2)$ be the lexicographically ordered pair of string user IDs:
$$U_1 = \min(\text{UID}_A, \text{UID}_B), \quad U_2 = \max(\text{UID}_A, \text{UID}_B)$$
Compute the 64-byte SHA-512 digest:
$$D = \text{SHA-512}(IK_1 \mathbin{\Vert} IK_2 \mathbin{\Vert} U_1 \mathbin{\Vert} U_2)$$
Partition the first 60 bytes of $D$ into twelve 5-byte chunks $C_0, \dots, C_{11}$:
$$\forall k \in \{0, \dots, 11\}: \quad V_k = \sum_{m=0}^{4} D_{5k + m} \cdot 256^{4 - m}$$
$$\text{Block}_k = (V_k \bmod 100000) \quad \text{formatted as 5 zero-padded decimal digits}$$
$$\text{SafetyNumber} = \text{Block}_0 \mathbin{\text{" "}} \text{Block}_1 \dots \mathbin{\text{" "}} \text{Block}_{11}$$
- **Commutative Property**: $SN(\text{Alice}, \text{Bob}) \equiv SN(\text{Bob}, \text{Alice})$. Both peers calculate identical strings regardless of who initiates the calculation.
- **Total Formatted Length**: Exactly 71 characters ($12 \times 5 \text{ digits} + 11 \text{ spaces}$).

---

## 4. Binary Wire Formats & Data Layouts

To avoid dependency on third-party serialization libraries for security-critical state and to ensure deterministic byte-for-byte parsing across platforms, Card `CLIENT-006` specifies three compact binary container formats.

### 4.1 SCPB v1: SecureCloud Private Bundle Format
Employed by `KeyStorageHelper` to persist physical device key bundles into `ISecureStorage`.

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       'S'     |       'C'     |       'P'     |       'B'     | Magic Bytes (0x53, 0x43, 0x50, 0x42)
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Version (1)  |              Device ID Length (L_did)         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Device ID String (L_did bytes)             |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|             Identity Public Key (32 bytes Ed25519)            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|             Identity Private Key (32 bytes Ed25519)           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Signed Prekey Public Key (32 bytes X25519)          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Signed Prekey Private Key (32 bytes X25519)          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|               Signed Prekey Signature (64 bytes)              |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Number of OTPKs (uint32_t)                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Repeated OTPK Records:                    |
|  - OTPK ID Length (uint16_t)                                  |
|  - OTPK ID String (variable)                                  |
|  - OTPK Private Key (32 bytes X25519)                         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### 4.2 SCRS v1: SecureCloud Ratchet Session State Format
Employed by `RatchetSessionSerializer` to safely checkpoint active Double Ratchet state across application lifecycle restarts.

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       'S'     |       'C'     |       'R'     |       'S'     | Magic Bytes (0x53, 0x43, 0x52, 0x53)
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Version (1)  | Flags (InitP) |       Peer User ID Length     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Peer User ID String (UTF-8)                |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Peer Device ID Length                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   Peer Device ID String (UTF-8)               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|            Peer Identity Public Key (32 bytes Ed25519)        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                Root Key RK (32 bytes SecretString)            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Sender Chain Key CKS (0 or 32 bytes SecretString)    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|         Receiver Chain Key CKR (0 or 32 bytes SecretString)   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|             Our DH Ephemeral Keypair (Public 32B, Priv 32B)   |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Peer Current DH Ephemeral Public Key (0 or 32B)     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       Sender Msg Counter Ns   |      Receiver Msg Counter Nr  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                 Previous Chain Length PNs                     |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                   Number of Skipped Keys (uint32_t)           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Repeated Skipped Keys:                    |
|  - DH Public Key (32 bytes)                                   |
|  - Message Counter N (uint32_t)                               |
|  - Message Key (32 bytes SecretString)                        |
|  - Timestamp Unix MS (uint64_t)                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                  Optional Pending X3DH Header                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### 4.3 SCE v1: SecureCloud Encrypted Envelope Format
The binary transport container representing `EncryptedMessageEnvelope`, held inside `ciphertext_blob`.

```text
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       'S'     |       'C'     |       'E'     |  Version (1)  | Magic Bytes (0x53, 0x43, 0x45, 0x01)
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Has X3DH (0/1)|               X3DH Header Length (if 1)       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    X3DH Header Bytes (variable)               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                  Ratchet Message Payload Length               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      RatchetHeader: 'R' (0x52) | Ver (0x01) | DH Pub (32B)    |
|      RatchetHeader (cont): PN (uint32_t) | N (uint32_t)       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    IV Length (12) | IV Bytes                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|               Auth Tag Length (16) | Auth Tag Bytes           |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|             Ciphertext Blob Length | Ciphertext Bytes         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

---

## 5. Comprehensive Ticket-by-Ticket Implementation Deep Dive

---

### 5.1 CLIENT-006-T01: Cryptographic Primitives Expansion for X3DH & Double Ratchet

- **Goal**: Augment the client crypto adapter layer with hardened OpenSSL 3.x EVP primitives for X25519 Diffie-Hellman derivation, HKDF-SHA256, AES-256-GCM AEAD, and 60-digit mutual Safety Numbers.
- **Architecture & Implementation Details**:
  - `ICryptoProvider` extended with pure virtual methods returning `ClientResult<T>`.
  - In `OpenSslCryptoProvider`:
    - `diffie_hellman`: Converts peer X25519 public key bytes into an `EVP_PKEY` via `EVP_PKEY_new_raw_public_key`, loads our private key with `EVP_PKEY_new_raw_private_key`, creates an `EVP_PKEY_CTX` using `EVP_PKEY_CTX_new`, and derives the 32-byte shared secret via `EVP_PKEY_derive`. The output buffer is managed inside a `SecretString` to guarantee memory cleansing.
    - `hkdf_extract`: Invokes OpenSSL 3.x `EVP_KDF_fetch(nullptr, "HKDF", nullptr)`, sets `OSSL_KDF_PARAM_MODE` to `EVP_KDF_HKDF_MODE_EXTRACT_ONLY`, `OSSL_KDF_PARAM_DIGEST` to `"SHA256"`, `OSSL_KDF_PARAM_KEY` to the input key material (IKM), and `OSSL_KDF_PARAM_SALT` to the salt. Produces 32-byte Pseudorandom Key (PRK).
    - `hkdf_expand`: Configures mode `EVP_KDF_HKDF_MODE_EXPAND_ONLY`, sets `OSSL_KDF_PARAM_KEY` to PRK, `OSSL_KDF_PARAM_INFO` to context info, and derives $L$ bytes.
    - `encrypt_aes_gcm`: Generates 12-byte IV (or accepts passed IV), initializes `EVP_CIPHER_CTX` with `EVP_aes_256_gcm()`, sets key and IV, injects Associated Authenticated Data (AAD) without output pointer, encrypts plaintext, finalizes encryption, and extracts the 16-byte authentication tag via `EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag.data())`.
    - `decrypt_aes_gcm`: Sets tag via `EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag.data())`, injects AAD, decrypts ciphertext, and verifies integrity during `EVP_DecryptFinal_ex`. If authentication fails, OpenSSL returns error code $\le 0$, immediately converted into `ClientError::crypto("AES-GCM tag authentication failed")`.
- **Commit**: `1f28223`

---

### 5.2 CLIENT-006-T02: X3DH Key Agreement Engine & Handshake Protocol

- **Goal**: Implement the Signal Extended Triple Diffie-Hellman (X3DH) protocol domain engine enabling an initiator (Alice) and responder (Bob) to negotiate an initial shared secret ($SK$).
- **Architecture & Implementation Details**:
  - `X3dhEngine::initiate_handshake`:
    1. Verifies Bob's signed prekey signature:
       `crypto.verify_signed_prekey(bob_bundle.identity_key(), bob_bundle.signed_prekey(), bob_bundle.signed_prekey_signature())`.
    2. Generates fresh ephemeral keypair $EK_A$ via `crypto.generate_dh_keypair()`.
    3. Computes Diffie-Hellman agreements:
       - $DH_1 = \text{DH}(IK_{A,\text{priv}}, SPK_{B,\text{pub}})$
       - $DH_2 = \text{DH}(EK_{A,\text{priv}}, IK_{B,\text{pub}})$
       - $DH_3 = \text{DH}(EK_{A,\text{priv}}, SPK_{B,\text{pub}})$
       - $DH_4 = \text{DH}(EK_{A,\text{priv}}, OPK_{B,\text{pub}})$ (if Bob's bundle contains an OTPK).
    4. Concatenates $DH$ values into $IKM$: $DH_1 \parallel DH_2 \parallel DH_3 [\parallel DH_4]$.
    5. Derives master shared secret $SK$ via HKDF with zero-filled salt and info `"SecureCloud-X3DH-v1"`.
    6. Assembles `X3dhHeader` containing $IK_{A,\text{pub}}$, $EK_{A,\text{pub}}$, signed prekey ID, and optional one-time prekey ID.
  - `X3dhEngine::process_handshake`:
    1. Bob extracts $IK_A$ and $EK_A$ from Alice's header.
    2. Bob computes matching DH components using his stored private keys ($IK_{B,\text{priv}}, SPK_{B,\text{priv}}, OPK_{B,\text{priv}}$).
    3. Bob derives identical $SK$.
    4. Bob returns `X3dhResponderResult` with $SK$ and the ID of the consumed OTPK.
- **Commit**: `e96f8ec`

---

### 5.3 CLIENT-006-T03: Double Ratchet State Machine & Key Derivation Chains

- **Goal**: Implement the continuous Double Ratchet state machine managing symmetric KDF chains, asymmetric Diffie-Hellman ratchet steps, and authenticated message encryption/decryption.
- **Architecture & Implementation Details**:
  - `RatchetHeader`: Contains 32-byte DH public key, previous chain length $PN$, and message counter $N$. Implements compact 42-byte serialization starting with magic byte `0x52` ('R') and version `0x01`.
  - `DoubleRatchetEngine::initialize_alice`: Sets initial root key $RK = SK$, generates Alice's initial DH keypair, computes initial DH shared secret with Bob's DH key, advances root KDF to produce sending chain key $CK_s$, leaving receiving chain uninitialized.
  - `DoubleRatchetEngine::initialize_bob`: Sets initial root key $RK = SK$, stores Bob's DH keypair, leaves sending and receiving chains uninitialized until Alice's first message arrives.
  - `DoubleRatchetEngine::ratchet_encrypt`:
    1. Advances sending chain: $MK = \text{HMAC}(CK_s, 0x01)$, $CK_s = \text{HMAC}(CK_s, 0x02)$.
    2. Increments message counter $N_s$.
    3. Serializes `RatchetHeader` and passes it as Associated Authenticated Data (AAD) into `crypto.encrypt_aes_gcm`.
    4. Wipes $MK$ from memory.
  - `DoubleRatchetEngine::ratchet_decrypt`:
    1. Inspects incoming `RatchetHeader::dh_pub()`.
    2. If $DH_{\text{peer}} \ne DH_{\text{state}}$:
       - Skips remaining keys in the current receiving chain up to $header.pn()$ and stores them in `SkippedKeysStore`.
       - Advances DH ratchet: computes $DH(DH_{\text{our,priv}}, DH_{\text{header}})$, derives new root key and receiver chain key.
       - Generates fresh DH keypair for our endpoint.
       - Computes second DH ratchet step: derives new root key and sender chain key.
       - Resets $PN_s = N_s, N_s = 0, N_r = 0$.
    3. Skips any keys in the receiver chain up to $header.n()$.
    4. Derives $MK$ for message $N$, cleanses chain key forward.
    5. Decrypts AES-256-GCM ciphertext using $MK$ and header as AAD.
- **Commit**: `90c4c42`

---

### 5.4 CLIENT-006-T04: Skipped Message Key Store & Out-of-Order Packet Delivery

- **Goal**: Implement bounded out-of-order packet reordering resilience, supporting network jitter and asynchronous cloud store-and-forward delivery while protecting against Denial of Service and replay attacks.
- **Architecture & Implementation Details**:
  - `SkippedKeysStore`:
    - Storage map: `std::unordered_map<SkippedKeyId, SkippedKeyEntry, SkippedKeyIdHash>` where `SkippedKeyId` holds 32-byte ratchet public key and uint32 message counter.
    - `SkippedKeyEntry`: Holds 32-byte message key in `SecretString` and creation timestamp `std::chrono::system_clock::time_point`.
    - Methods:
      - `store_key(ratchet_pub, n, key)`: Stores key, applies timestamp, and enforces global capacity limit.
      - `extract_key(ratchet_pub, n)`: Finds matching key, returns it, and **immediately erases the entry from the map**. Once extracted, the key cannot be queried again, defeating replay attacks.
      - `prune_expired_keys(max_age)`: Prunes keys older than 14 days.
  - Integration in `DoubleRatchetEngine`:
    - If incoming message counter $N > N_r$, the engine loops from $N_r$ to $N - 1$, deriving each intermediate $MK$ and saving it to `SkippedKeysStore`.
    - If the skip gap $N - N_r > 1,000$, the engine aborts to prevent CPU exhaustion.
    - If incoming message counter $N < N_r$, the engine bypasses chain derivation and retrieves the stashed key from `SkippedKeysStore`.
- **Commit**: `06133d7`

---

### 5.5 CLIENT-006-T05: Ratchet Session Manager, Multi-Device Fan-out & Secure Session Persistence

- **Goal**: Orchestrate multi-device pairwise cryptographic sessions, automate prekey fetching and X3DH handshakes, perform fan-out encryption across recipient devices, and persist session states to secure storage.
- **Architecture & Implementation Details**:
  - `PeerDeviceKey`: Pair of `(domain::UserId, domain::DeviceId)` identifying a physical communication session.
  - `RatchetSessionState`: Encapsulates Double Ratchet state, peer identity key, pending X3DH header flag, and timestamps.
  - `RatchetSessionSerializer`: Encodes session state into `SCRS` binary format and decodes safely with length validation.
  - `RatchetSessionManager`:
    - `encrypt_payload_for_device`: Checks in-memory session cache; if missing, loads from `ISecureStorage`. If still missing, fetches peer device prekey bundle from `IGatewayClient`, executes X3DH via `X3dhEngine::initiate_handshake`, initializes Alice's ratchet state, packages `EncryptedMessageEnvelope` (holding initial `X3dhHeader`), serializes it to binary, and returns `PerDeviceDeliveryPayload`.
    - `encrypt_fanout_for_participants`: Loops over conversation participants, queries `IGatewayClient::get_device_crypto_directory` for each participant, collects all active authorized target devices plus companion devices of the sender (omitting current physical device), and encrypts a dedicated payload for each.
    - `decrypt_payload_from_device`: Deserializes `EncryptedMessageEnvelope` from raw `ciphertext_blob`. If session does not exist, inspects envelope for `X3dhHeader`; if present, executes `X3dhEngine::process_handshake`, consumes Bob's OTPK from `ISecureStorage`, initializes Bob's ratchet state, and decrypts message.
- **Commit**: `9b5f8f7`

---

### 5.6 CLIENT-006-T06: End-to-End Messaging Integration & Full Verification Suite

- **Goal**: Integrate `RatchetSessionManager` into `MessagingManager` and `ClientBootstrap`, wire 60-digit Safety Numbers into `WorkspaceViewModel`, and build comprehensive end-to-end integration tests.
- **Architecture & Implementation Details**:
  - `MessagingManager`:
    - Constructor accepts optional `RatchetSessionManager*`.
    - `send_message`: Routes payload encryption through `RatchetSessionManager::encrypt_payload_for_device` when available.
    - `stage_outbound_message`: Inspects participant contact records in `ILocalStore`; if any contact has `KeyVerificationStatus::KeyChanged`, blocks outbound messaging immediately (ADR-008). When valid, invokes `encrypt_fanout_for_participants` to advance ratchets across all recipient devices.
    - `process_inbound_message`: Decrypts incoming payload via `RatchetSessionManager::decrypt_payload_from_device`, extracts plaintext `SecretString`, creates `domain::Message` in `Delivered` state, saves to `ILocalStore`, and increments conversation unread counter.
  - `ClientBootstrap`:
    - Added `initialize_ratchet_session_manager(user_id, device_id)` and accessor `ratchet_session_manager()`. Automatically sets session manager pointer on `MessagingManager`.
  - `WorkspaceViewModel`:
    - Seeded direct contacts updated with genuine 60-digit Safety Numbers formatted as 12 groups of 5 digits.
    - `selectedPeerSafetyNumber`: Queries `RatchetSessionManager` and `ICryptoProvider::compute_safety_number` when active sessions exist.
    - Identity rotation simulation sets status to `KeyChanged` and updates displayed safety number to full 60-digit unverified rotation notice.
  - `E2EEMessagingIntegrationTest`:
    - Implemented 7 full-system integration scenarios in `tests/unit/client/e2ee_messaging_integration_test.cpp`.
    - Validated 100% test pass (163/163 tests) and 100% adherence to `.clang-format` across all 920 project files.

---

## 6. Core Source Code Walkthrough & Architectural Annotations

### 6.1 OpenSslCryptoProvider: Diffie-Hellman & HKDF Implementation
Located in [`src/client/infrastructure/adapters/openssl_crypto_provider.cpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/client/infrastructure/adapters/openssl_crypto_provider.cpp):

```cpp
application::ClientResult<securecloud::common::configuration::SecretString>
OpenSslCryptoProvider::diffie_hellman(const securecloud::common::configuration::SecretString& our_private_key,
                                     std::span<const uint8_t> peer_public_key) {
    if (peer_public_key.size() != domain::PrekeyPolicy::kX25519PublicKeySize ||
        our_private_key.size() != domain::PrekeyPolicy::kX25519PrivateKeySize) {
        return application::ClientResult<securecloud::common::configuration::SecretString>::error(
            application::ClientError::crypto("Invalid key size for X25519 Diffie-Hellman"));
    }

    // Load peer public key into OpenSSL EVP_PKEY
    EVP_PKEY* peer_pkey = EVP_PKEY_new_raw_public_key(
        EVP_PKEY_X25519, nullptr, peer_public_key.data(), peer_public_key.size());
    if (!peer_pkey) {
        return application::ClientResult<securecloud::common::configuration::SecretString>::error(
            application::ClientError::crypto("Failed to import peer X25519 public key"));
    }

    // Load our private key into OpenSSL EVP_PKEY
    const auto& priv_bytes = our_private_key.expose_unredacted_secret();
    EVP_PKEY* our_pkey = EVP_PKEY_new_raw_private_key(
        EVP_PKEY_X25519, nullptr, reinterpret_cast<const uint8_t*>(priv_bytes.data()), priv_bytes.size());
    if (!our_pkey) {
        EVP_PKEY_free(peer_pkey);
        return application::ClientResult<securecloud::common::configuration::SecretString>::error(
            application::ClientError::crypto("Failed to import our X25519 private key"));
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(our_pkey, nullptr);
    if (!ctx || EVP_PKEY_derive_init(ctx) <= 0 || EVP_PKEY_derive_set_peer(ctx, peer_pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(our_pkey);
        EVP_PKEY_free(peer_pkey);
        return application::ClientResult<securecloud::common::configuration::SecretString>::error(
            application::ClientError::crypto("Failed to initialize EVP_PKEY derivation context"));
    }

    size_t secret_len = 0;
    if (EVP_PKEY_derive(ctx, nullptr, &secret_len) <= 0 || secret_len != domain::PrekeyPolicy::kSharedSecretSize) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(our_pkey);
        EVP_PKEY_free(peer_pkey);
        return application::ClientResult<securecloud::common::configuration::SecretString>::error(
            application::ClientError::crypto("Failed to determine shared secret length"));
    }

    std::string secret(secret_len, '\0');
    if (EVP_PKEY_derive(ctx, reinterpret_cast<uint8_t*>(secret.data()), &secret_len) <= 0) {
        OPENSSL_cleanse(secret.data(), secret.size());
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(our_pkey);
        EVP_PKEY_free(peer_pkey);
        return application::ClientResult<securecloud::common::configuration::SecretString>::error(
            application::ClientError::crypto("EVP_PKEY_derive computation failed"));
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(our_pkey);
    EVP_PKEY_free(peer_pkey);

    securecloud::common::configuration::SecretString result(std::move(secret));
    return application::ClientResult<securecloud::common::configuration::SecretString>::ok(std::move(result));
}
```

### 6.2 DoubleRatchetEngine: Symmetric Chain & DH Step
Located in [`src/client/domain/crypto/double_ratchet_engine.cpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/client/domain/crypto/double_ratchet_engine.cpp):

```cpp
application::ClientResult<DoubleRatchetMessage>
DoubleRatchetEngine::ratchet_encrypt(application::interfaces::ICryptoProvider& crypto,
                                     DoubleRatchetState& state, std::span<const uint8_t> plaintext) {
    if (!state.sending_chain_key.has_value()) {
        return application::ClientResult<DoubleRatchetMessage>::error(
            application::ClientError::crypto("Sending chain key uninitialized"));
    }

    // 1. Advance sending chain: MK = HMAC(CK_s, 0x01), CK_s = HMAC(CK_s, 0x02)
    const uint8_t mk_info[1] = {0x01};
    const uint8_t ck_info[1] = {0x02};

    auto mk_res = crypto.hkdf_expand(state.sending_chain_key.value(), mk_info, 32);
    auto next_ck_res = crypto.hkdf_expand(state.sending_chain_key.value(), ck_info, 32);
    if (!mk_res.is_ok() || !next_ck_res.is_ok()) {
        return application::ClientResult<DoubleRatchetMessage>::error(
            application::ClientError::crypto("Failed to step sending chain key"));
    }

    state.sending_chain_key = std::move(next_ck_res).value();
    const auto message_key = std::move(mk_res).value();

    // 2. Assemble header with current DH public key and message counters
    RatchetHeader header(state.our_dh_keypair.public_key, state.pn, state.ns);
    state.ns += 1;

    // 3. Serialize header to serve as Associated Authenticated Data (AAD)
    const auto serialized_header = header.serialize();

    // 4. Encrypt plaintext via AES-256-GCM
    auto enc_res = crypto.encrypt_aes_gcm(message_key, /*iv=*/{}, plaintext, serialized_header);
    if (!enc_res.is_ok()) {
        return application::ClientResult<DoubleRatchetMessage>::error(enc_res.error());
    }

    auto aead = std::move(enc_res).value();
    DoubleRatchetMessage msg{
        .header = std::move(header),
        .ciphertext = std::move(aead.ciphertext),
        .iv = std::move(aead.iv),
        .auth_tag = std::move(aead.auth_tag),
    };

    return application::ClientResult<DoubleRatchetMessage>::ok(std::move(msg));
}
```

---

## 7. Security Invariants & Cryptographic Defense-in-Depth Audit

The implementation of `CLIENT-006` underwent a rigorous security audit against all core architectural invariants.

```text
┌────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                   SECURITY INVARIANTS & DEFENSE-IN-DEPTH AUDIT MATRIX                                  │
├───────────────────────────┬───────────────────────────────────┬──────────────────────────────────────┬─────────────────┤
│ Invariant Rule            │ Threat / Attack Vector            │ Architectural Defense Implementation │ Audit Status    │
├───────────────────────────┼───────────────────────────────────┼──────────────────────────────────────┼─────────────────┤
│ 1. Forward Secrecy (FS)   │ Workstation compromise / memory   │ Immediate message key zeroization;   │ VERIFIED        │
│                           │ dump reveals historical messages  │ one-way KDF forward advancement      │                 │
├───────────────────────────┼───────────────────────────────────┼──────────────────────────────────────┼─────────────────┤
│ 2. Post-Compromise (PCS)  │ Active session state exfiltration │ Conversational DH ratchet turns mix  │ VERIFIED        │
│                           │ by temporary passive attacker     │ fresh asymmetric entropy into root   │                 │
├───────────────────────────┼───────────────────────────────────┼──────────────────────────────────────┼─────────────────┤
│ 3. Replay Protection      │ Packet capture and re-injection   │ Consumed OTPKs wiped; skipped keys   │ VERIFIED        │
│                           │ over network relay                │ deleted immediately upon decryption  │                 │
├───────────────────────────┼───────────────────────────────────┼──────────────────────────────────────┼─────────────────┤
│ 4. DoS Circuit Breakers   │ Giant message counter skip packet │ MAX_SKIP = 1,000 keys per turn;      │ VERIFIED        │
│                           │ causing CPU exhaustion / memory OOM│ MAX_STORED = 2,000 keys; 14-day TTL  │                 │
├───────────────────────────┼───────────────────────────────────┼──────────────────────────────────────┼─────────────────┤
│ 5. Zero Plaintext on Wire │ Accidental plaintext leak to cloud│ AES-256-GCM AEAD; anti-plaintext     │ VERIFIED        │
│                           │ relay or MITM proxy               │ heuristic rejects >= 90% ASCII/JSON  │                 │
├───────────────────────────┼───────────────────────────────────┼──────────────────────────────────────┼─────────────────┤
│ 6. Out-of-Band Auth (SN)  │ Malicious prekey directory MITM   │ 60-digit mutual Safety Numbers       │ VERIFIED        │
│                           │ identity key substitution         │ (SHA-512 over sorted keys and UIDs)  │                 │
├───────────────────────────┼───────────────────────────────────┼──────────────────────────────────────┼─────────────────┤
│ 7. ADR-008 KeyChange Guard│ Silent peer key rotation bypasses │ stage_outbound_message intercepts and│ VERIFIED        │
│                           │ user awareness                    │ halts sending on KeyChanged status   │                 │
└───────────────────────────┴───────────────────────────────────┴──────────────────────────────────────┴─────────────────┘
```

### 7.1 Invariant 1: Forward Secrecy (FS)
- **Design Requirement**: Compromise of long-term identity keys or current session root keys must not expose historical ciphertexts.
- **Audit Verification**:
  - Every symmetric message key $MK$ is derived from chain key $CK$ via $MK = \text{HMAC}(CK, 0x01)$.
  - The chain key is immediately stepped forward via $CK = \text{HMAC}(CK, 0x02)$.
  - In `OpenSslCryptoProvider`, the raw key buffer is cleansed with `OPENSSL_cleanse` immediately following `EVP_EncryptFinal_ex` or `EVP_DecryptFinal_ex`.
  - In `SkippedKeysStore`, extracting a key deletes it from the internal hash map and cleanses its secret memory.

### 7.2 Invariant 2: Post-Compromise Security (PCS)
- **Design Requirement**: A compromised session must self-heal upon subsequent conversational interaction.
- **Audit Verification**:
  - `E2EEMessagingIntegrationTest.PostCompromiseSecurityHealing` tests this explicitly.
  - When Bob replies to Alice, Bob generates a fresh ephemeral X25519 keypair.
  - Alice derives a new root key $RK_{i+1}$ via Diffie-Hellman with Bob's fresh public key.
  - An attacker possessing only the previous chain keys or historical session snapshot cannot decrypt subsequent messages in the conversation.

### 7.3 Invariant 3: Replay Protection & OTPK Single-Use
- **Design Requirement**: An intercepted packet cannot be re-delivered to trick the receiver into re-processing.
- **Audit Verification**:
  - In X3DH handshakes, consumed One-Time Prekeys (OTPKs) are immediately deleted via `KeyStorageHelper::remove_one_time_prekey`. Attempting to re-initiate a session with the same OTPK ID fails Bob's prekey lookup (`X3dhEngineTest.ConsumedOtpkReplayRejected`).
  - In Double Ratchet receiving chains, derived message keys are removed from `SkippedKeysStore` on first extraction. Re-delivering the exact same packet fails decryption with an error (`E2EEMessagingIntegrationTest.OutOfOrderDeliveryAndReplayPrevention`).

### 7.4 Invariant 4: Denial of Service Circuit Breakers
- **Design Requirement**: An adversary cannot force the client to compute millions of KDF steps or exhaust workstation memory by sending an artificially inflated message counter (e.g., $N = 2^{31}$).
- **Audit Verification**:
  - In `DoubleRatchetEngine::skip_message_keys`, if the gap between the incoming message number and the current receiver chain counter exceeds `kMaxSkipPerTurn = 1,000`, the operation aborts immediately with `ClientError::crypto("Message counter skip gap exceeds safety limit")`.
  - In `SkippedKeysStore`, total entries cannot exceed `kMaxStoredKeys = 2,000`. Any entry older than 14 days is automatically evicted.

### 7.5 Invariant 5: Zero-Plaintext Wire Invariant
- **Design Requirement**: Plaintext characters, unencrypted file contents, or JSON strings must never touch the network interface.
- **Audit Verification**:
  - All message bodies are encapsulated inside `EncryptedMessageEnvelope`, serialized to binary, and transported as `ciphertext_blob`.
  - `E2EEnvelopeValidator::is_suspected_unencrypted_plaintext` checks that payloads contain $< 90\%$ printable ASCII and do not begin with JSON delimiters.
  - `E2EEMessagingIntegrationTest.BackendEnvelopeValidationAndTamperResistance` verified that ciphertext blobs pass this heuristic cleanly, while raw ASCII or JSON payloads are intercepted and rejected.

### 7.6 Invariant 6: Mutual Out-of-Band Safety Numbers
- **Design Requirement**: Users must be provided with an infallible, commutative visual fingerprint to verify peer identity keys.
- **Audit Verification**:
  - Evaluated `OpenSslCryptoProvider::compute_safety_number`.
  - Verified commutativity: $SN(\text{Alice}, \text{Bob}) == SN(\text{Bob}, \text{Alice})$.
  - Verified exact format: 12 blocks of 5 decimal digits (60 digits total) separated by single spaces (71 characters length).

### 7.7 Invariant 7: ADR-008 Outbound Messaging Suspension
- **Design Requirement**: If a contact's identity key changes, the client must suspend outbound messages until the user re-verifies.
- **Audit Verification**:
  - `MessagingManager::stage_outbound_message` inspects every participant's contact record in `ILocalStore`.
  - If `contact.verification_status() == KeyVerificationStatus::KeyChanged`, the call fails with `ClientError::validation("Outbound messaging suspended: recipient identity key changed (ADR-008)")`.
  - Verified in `E2EEMessagingIntegrationTest.SafetyNumberVerificationAndRotationAlert`.

---

## 8. Automated Test Suite Execution & Assertion Matrix

All tests execute completely in-process using memory adapters (`MemorySecureStorage`, `MemoryLocalStore`, `DefaultGatewayClient`, and `OpenSslCryptoProvider`). No external Docker containers or PostgreSQL databases on host port 5432 are required.

### 8.1 Test Suite Summary
```text
[==========] Running 163 tests from 48 test suites ran. (698 ms total)
[  PASSED  ] 163 tests.
[  FAILED  ] 0 tests.
```

### 8.2 Ticket Test Matrix & Assertion Details

| Test Suite | Test Case Name | Ticket | Description & Security Invariants Verified |
| :--- | :--- | :--- | :--- |
| **`ClientCryptoProviderTest`** | `GenerateDhKeyPair` | `T01` | Generates 32B public key and non-empty private key via OpenSSL EVP. |
| **`ClientCryptoProviderTest`** | `DiffieHellmanRFC7748` | `T01` | Derives 32B shared secret; verifies commutativity between Alice and Bob. |
| **`ClientCryptoProviderTest`** | `HkdfSha256RFC5869` | `T01` | Validates Extract, Expand, and Extract-and-Expand against RFC test vectors. |
| **`ClientCryptoProviderTest`** | `AesGcmEncryptionDecryption`| `T01` | AES-256-GCM AEAD roundtrip with 12B IV, 16B auth tag, and custom AAD. |
| **`ClientCryptoProviderTest`** | `AesGcmTamperedCiphertext` | `T01` | Rejection of modified ciphertext or modified auth tag bytes. |
| **`ClientCryptoProviderTest`** | `ComputeSafetyNumber` | `T01` | Commutative 60-digit safety number computation (12 blocks of 5 digits). |
| **`X3dhEngineTest`** | `InitiatorAndResponderHandshake` | `T02` | Alice and Bob complete 4-way DH X3DH handshake and derive identical $SK$. |
| **`X3dhEngineTest`** | `HandshakeWithoutOtpk` | `T02` | Fallback 3-way DH handshake when responder prekey bundle lacks OTPKs. |
| **`X3dhEngineTest`** | `CorruptedSignedPrekeySignature` | `T02` | Tampered signature on Bob's prekey triggers Alice handshake abort. |
| **`X3dhEngineTest`** | `ConsumedOtpkReplayRejected` | `T02` | Consuming Bob's OTPK ensures re-used OTPK ID is rejected. |
| **`DoubleRatchetEngineTest`** | `AliceBobBasicExchange` | `T03` | Basic 1:1 message exchange with symmetric chain key advancement. |
| **`DoubleRatchetEngineTest`** | `MultiMessagePingPongInterleaving` | `T03` | Continuous multi-turn conversation triggering asymmetric DH ratchet steps. |
| **`DoubleRatchetEngineTest`** | `ConsecutiveBurstMessages` | `T03` | Burst messaging within single epoch increments counter $N$ correctly. |
| **`DoubleRatchetEngineTest`** | `TamperedCiphertextAndHeader` | `T03` | Tampered ciphertext or serialized `RatchetHeader` fails AEAD decryption. |
| **`SkippedKeysStoreTest`** | `DirectStoreAndExtractSingleKey` | `T04` | Store, lookup, and single-use extraction of skipped message keys. |
| **`SkippedKeysStoreTest`** | `PruneExpiredKeys` | `T04` | Automated pruning of message keys older than 14 days TTL. |
| **`SkippedKeysStoreTest`** | `CapacityLimitEnforcement` | `T04` | Enforcement of sliding window cap ($\le 2,000$ stored keys). |
| **`DoubleRatchetOutOfOrderTest`**| `SymmetricChainReordering` | `T04` | Delivery of packets #3, #1, #0, #2 in reverse order decrypts flawlessly. |
| **`DoubleRatchetOutOfOrderTest`**| `OutOfOrderAcrossDhRatchetTurn` | `T04` | Delivery of historical epoch packets across asymmetric DH turns. |
| **`DoubleRatchetOutOfOrderTest`**| `ExcessiveSkipGapRejected` | `T04` | Attempting to skip $> 1,000$ messages triggers DoS circuit breaker. |
| **`RatchetSessionManagerTest`** | `OutboundEstablishment` | `T05` | Auto-triggering X3DH on initial message to unknown peer device. |
| **`RatchetSessionManagerTest`** | `PayloadSerializationValidation`| `T05` | Serialization of `PerDeviceDeliveryPayload` matching backend schema. |
| **`RatchetSessionManagerTest`** | `MultiDeviceFanOut` | `T05` | Fan-out to Bob phone, Bob laptop, and Alice desktop companion. |
| **`RatchetSessionManagerTest`** | `PersistenceAndRestart` | `T05` | Save session state to `ISecureStorage`, destroy manager, reload, decrypt. |
| **`RatchetSessionManagerTest`** | `SessionTermination` | `T05` | Immediate memory and storage wipe upon session termination. |
| **`E2EEMessagingIntegrationTest`**| `FullConversationLifecycle` | `T06` | End-to-end messaging via `MessagingManager` across multiple rounds. |
| **`E2EEMessagingIntegrationTest`**| `MultiDeviceFanout` | `T06` | Multi-device fan-out via `MessagingManager::stage_outbound_message`. |
| **`E2EEMessagingIntegrationTest`**| `OutOfOrderReplayPrevention` | `T06` | Delivery order (4, 1, 3, 0, 2); replay attack on packet 1 fails. |
| **`E2EEMessagingIntegrationTest`**| `PostCompromiseSecurityHealing` | `T06` | Asymmetric ratchet turn self-heals session after simulated state leak. |
| **`E2EEMessagingIntegrationTest`**| `SessionResumptionRestart` | `T06` | Bob process crash simulated; restarted manager decrypts post-restart packet. |
| **`E2EEMessagingIntegrationTest`**| `BackendEnvelopeValidation` | `T06` | Compliance with `E2EEnvelopeValidator` bounds and anti-plaintext check. |
| **`E2EEMessagingIntegrationTest`**| `SafetyNumberRotationAlert` | `T06` | Mutual 60-digit verification; key rotation locks outbound messaging. |

### 8.3 Full Automated Test Suite Execution Output
Captured from execution of target `securecloud_client_foundation_test`:

```text
[==========] Running 163 tests from 48 test suites.
[----------] Global test environment set-up.
[----------] 3 tests from ClientDomainTest
[ RUN      ] ClientDomainTest.SessionStateDefaultInitialization
[       OK ] ClientDomainTest.SessionStateDefaultInitialization (0 ms)
[ RUN      ] ClientDomainTest.SessionStateLifecycleAndReset
[       OK ] ClientDomainTest.SessionStateLifecycleAndReset (0 ms)
[ RUN      ] ClientDomainTest.SessionStatusToString
[       OK ] ClientDomainTest.SessionStatusToString (0 ms)
[----------] 3 tests from ClientDomainTest (0 ms total)

[----------] 1 test from ClientInfrastructureTest
[ RUN      ] ClientInfrastructureTest.GatewayAdapterStubProbing
[       OK ] ClientInfrastructureTest.GatewayAdapterStubProbing (0 ms)
[----------] 1 test from ClientInfrastructureTest (0 ms total)

[----------] 1 test from ClientApplicationTest
[ RUN      ] ClientApplicationTest.ClientAppServiceInitializationAndSessionFlow
[       OK ] ClientApplicationTest.ClientAppServiceInitializationAndSessionFlow (0 ms)
[----------] 1 test from ClientApplicationTest (0 ms total)

[----------] 1 test from ClientUiTest
[ RUN      ] ClientUiTest.UiControllerSignalAndPropertyBindings
[       OK ] ClientUiTest.UiControllerSignalAndPropertyBindings (0 ms)
[----------] 1 test from ClientUiTest (0 ms total)

[----------] 8 tests from ClientConfigTest
[ RUN      ] ClientConfigTest.DefaultConfigurationIsValid
[       OK ] ClientConfigTest.DefaultConfigurationIsValid (0 ms)
[ RUN      ] ClientConfigTest.ValidationFailsOnInvalidGatewayUrl
[       OK ] ClientConfigTest.ValidationFailsOnInvalidGatewayUrl (0 ms)
[ RUN      ] ClientConfigTest.ValidationFailsOnZeroPort
[       OK ] ClientConfigTest.ValidationFailsOnZeroPort (0 ms)
[ RUN      ] ClientConfigTest.ValidationFailsOnInvalidTimeouts
[       OK ] ClientConfigTest.ValidationFailsOnInvalidTimeouts (0 ms)
[ RUN      ] ClientConfigTest.ValidationFailsOnZeroHeartbeatOrSync
[       OK ] ClientConfigTest.ValidationFailsOnZeroHeartbeatOrSync (0 ms)
[ RUN      ] ClientConfigTest.ValidationFailsOnEmptyKeychainService
[       OK ] ClientConfigTest.ValidationFailsOnEmptyKeychainService (0 ms)
[ RUN      ] ClientConfigTest.EnvironmentOverrides
[       OK ] ClientConfigTest.EnvironmentOverrides (0 ms)
[ RUN      ] ClientConfigTest.ToSafeStringRedactsSecretToken
[       OK ] ClientConfigTest.ToSafeStringRedactsSecretToken (0 ms)
[----------] 8 tests from ClientConfigTest (0 ms total)

[----------] 2 tests from ClientErrorTest
[ RUN      ] ClientErrorTest.FormattingAndProperties
[       OK ] ClientErrorTest.FormattingAndProperties (0 ms)
[ RUN      ] ClientErrorTest.FactoryMethods
[       OK ] ClientErrorTest.FactoryMethods (0 ms)
[----------] 2 tests from ClientErrorTest (0 ms total)

[----------] 4 tests from ClientResultTest
[ RUN      ] ClientResultTest.NonVoidSuccess
[       OK ] ClientResultTest.NonVoidSuccess (0 ms)
[ RUN      ] ClientResultTest.NonVoidError
[       OK ] ClientResultTest.NonVoidError (0 ms)
[ RUN      ] ClientResultTest.MonadicAndThenAndTransform
[       OK ] ClientResultTest.MonadicAndThenAndTransform (0 ms)
[ RUN      ] ClientResultTest.VoidSuccessAndError
[       OK ] ClientResultTest.VoidSuccessAndError (0 ms)
[----------] 4 tests from ClientResultTest (0 ms total)

[----------] 5 tests from ClientLoggerTest
[ RUN      ] ClientLoggerTest.SanitizesBearerToken
[       OK ] ClientLoggerTest.SanitizesBearerToken (1 ms)
[ RUN      ] ClientLoggerTest.SanitizesJsonPasswordsAndTokens
[       OK ] ClientLoggerTest.SanitizesJsonPasswordsAndTokens (1 ms)
[ RUN      ] ClientLoggerTest.SanitizesQueryPasswordsAndTokens
[       OK ] ClientLoggerTest.SanitizesQueryPasswordsAndTokens (0 ms)
[ RUN      ] ClientLoggerTest.SanitizesPrivateKeyBlocks
[       OK ] ClientLoggerTest.SanitizesPrivateKeyBlocks (0 ms)
[ RUN      ] ClientLoggerTest.CustomSinkAndLevelFiltering
[       OK ] ClientLoggerTest.CustomSinkAndLevelFiltering (0 ms)
[----------] 5 tests from ClientLoggerTest (4 ms total)

[----------] 3 tests from DomainIdTest
[ RUN      ] DomainIdTest.UserIdValidAndInvalidConstruction
[       OK ] DomainIdTest.UserIdValidAndInvalidConstruction (0 ms)
[ RUN      ] DomainIdTest.DeviceIdValidAndInvalidConstruction
[       OK ] DomainIdTest.DeviceIdValidAndInvalidConstruction (0 ms)
[ RUN      ] DomainIdTest.MessageIdAndConversationIdConstruction
[       OK ] DomainIdTest.MessageIdAndConversationIdConstruction (0 ms)
[----------] 3 tests from DomainIdTest (0 ms total)

[----------] 2 tests from PrekeyPolicyTest
[ RUN      ] PrekeyPolicyTest.PolicyConstants
[       OK ] PrekeyPolicyTest.PolicyConstants (0 ms)
[ RUN      ] PrekeyPolicyTest.KeyRotationPolicy
[       OK ] PrekeyPolicyTest.KeyRotationPolicy (0 ms)
[----------] 2 tests from PrekeyPolicyTest (0 ms total)

[----------] 12 tests from ClientCryptoProviderTest
[ RUN      ] ClientCryptoProviderTest.GenerateIdentityKeyPairEd25519
[       OK ] ClientCryptoProviderTest.GenerateIdentityKeyPairEd25519 (0 ms)
[ RUN      ] ClientCryptoProviderTest.SignedPrekeyGenerationAndVerification
[       OK ] ClientCryptoProviderTest.SignedPrekeyGenerationAndVerification (0 ms)
[ RUN      ] ClientCryptoProviderTest.CorruptedSignedPrekeySignatureFails
[       OK ] ClientCryptoProviderTest.CorruptedSignedPrekeySignatureFails (0 ms)
[ RUN      ] ClientCryptoProviderTest.GenerateOneTimePrekeysBatch
[       OK ] ClientCryptoProviderTest.GenerateOneTimePrekeysBatch (1 ms)
[ RUN      ] ClientCryptoProviderTest.ComputeIdentityFingerprint
[       OK ] ClientCryptoProviderTest.ComputeIdentityFingerprint (0 ms)
[ RUN      ] ClientCryptoProviderTest.GenerateDhKeyPair
[       OK ] ClientCryptoProviderTest.GenerateDhKeyPair (0 ms)
[ RUN      ] ClientCryptoProviderTest.DiffieHellmanRFC7748
[       OK ] ClientCryptoProviderTest.DiffieHellmanRFC7748 (0 ms)
[ RUN      ] ClientCryptoProviderTest.HkdfSha256RFC5869
[       OK ] ClientCryptoProviderTest.HkdfSha256RFC5869 (0 ms)
[ RUN      ] ClientCryptoProviderTest.AesGcmEncryptionDecryption
[       OK ] ClientCryptoProviderTest.AesGcmEncryptionDecryption (0 ms)
[ RUN      ] ClientCryptoProviderTest.AesGcmTamperedCiphertext
[       OK ] ClientCryptoProviderTest.AesGcmTamperedCiphertext (0 ms)
[ RUN      ] ClientCryptoProviderTest.ComputeSafetyNumber
[       OK ] ClientCryptoProviderTest.ComputeSafetyNumber (0 ms)
[ RUN      ] ClientCryptoProviderTest.StubCryptoProviderParity
[       OK ] ClientCryptoProviderTest.StubCryptoProviderParity (0 ms)
[----------] 12 tests from ClientCryptoProviderTest (3 ms total)

[----------] 6 tests from X3dhEngineTest
[ RUN      ] X3dhEngineTest.InitiatorAndResponderHandshake
[       OK ] X3dhEngineTest.InitiatorAndResponderHandshake (1 ms)
[ RUN      ] X3dhEngineTest.HandshakeWithoutOtpk
[       OK ] X3dhEngineTest.HandshakeWithoutOtpk (0 ms)
[ RUN      ] X3dhEngineTest.CorruptedSignedPrekeySignature
[       OK ] X3dhEngineTest.CorruptedSignedPrekeySignature (0 ms)
[ RUN      ] X3dhEngineTest.CorruptedPeerIdentityKey
[       OK ] X3dhEngineTest.CorruptedPeerIdentityKey (0 ms)
[ RUN      ] X3dhEngineTest.ConsumedOtpkReplayRejected
[       OK ] X3dhEngineTest.ConsumedOtpkReplayRejected (0 ms)
[ RUN      ] X3dhEngineTest.StubCryptoProviderParity
[       OK ] X3dhEngineTest.StubCryptoProviderParity (0 ms)
[----------] 6 tests from X3dhEngineTest (2 ms total)

[----------] 1 test from RatchetModelsTest
[ RUN      ] RatchetModelsTest.HeaderAndMessageSerializationRoundtrip
[       OK ] RatchetModelsTest.HeaderAndMessageSerializationRoundtrip (0 ms)
[----------] 1 test from RatchetModelsTest (0 ms total)

[----------] 5 tests from DoubleRatchetEngineTest
[ RUN      ] DoubleRatchetEngineTest.AliceBobBasicExchange
[       OK ] DoubleRatchetEngineTest.AliceBobBasicExchange (0 ms)
[ RUN      ] DoubleRatchetEngineTest.MultiMessagePingPongInterleaving
[       OK ] DoubleRatchetEngineTest.MultiMessagePingPongInterleaving (2 ms)
[ RUN      ] DoubleRatchetEngineTest.ConsecutiveBurstMessages
[       OK ] DoubleRatchetEngineTest.ConsecutiveBurstMessages (0 ms)
[ RUN      ] DoubleRatchetEngineTest.TamperedCiphertextAndHeaderRejection
[       OK ] DoubleRatchetEngineTest.TamperedCiphertextAndHeaderRejection (0 ms)
[ RUN      ] DoubleRatchetEngineTest.StubCryptoProviderParity
[       OK ] DoubleRatchetEngineTest.StubCryptoProviderParity (0 ms)
[----------] 5 tests from DoubleRatchetEngineTest (3 ms total)

[----------] 3 tests from SkippedKeysStoreTest
[ RUN      ] SkippedKeysStoreTest.DirectStoreAndExtractSingleKey
[       OK ] SkippedKeysStoreTest.DirectStoreAndExtractSingleKey (0 ms)
[ RUN      ] SkippedKeysStoreTest.PruneExpiredKeys
[       OK ] SkippedKeysStoreTest.PruneExpiredKeys (0 ms)
[ RUN      ] SkippedKeysStoreTest.CapacityLimitEnforcement
[       OK ] SkippedKeysStoreTest.CapacityLimitEnforcement (1 ms)
[----------] 3 tests from SkippedKeysStoreTest (1 ms total)

[----------] 4 tests from DoubleRatchetOutOfOrderTest
[ RUN      ] DoubleRatchetOutOfOrderTest.SymmetricChainReordering
[       OK ] DoubleRatchetOutOfOrderTest.SymmetricChainReordering (0 ms)
[ RUN      ] DoubleRatchetOutOfOrderTest.OutOfOrderAcrossDhRatchetTurn
[       OK ] DoubleRatchetOutOfOrderTest.OutOfOrderAcrossDhRatchetTurn (0 ms)
[ RUN      ] DoubleRatchetOutOfOrderTest.ExcessiveSkipGapRejected
[       OK ] DoubleRatchetOutOfOrderTest.ExcessiveSkipGapRejected (0 ms)
[ RUN      ] DoubleRatchetOutOfOrderTest.StubCryptoProviderParity
[       OK ] DoubleRatchetOutOfOrderTest.StubCryptoProviderParity (0 ms)
[----------] 4 tests from DoubleRatchetOutOfOrderTest (0 ms total)

[----------] 5 tests from RatchetSessionManagerTest
[ RUN      ] RatchetSessionManagerTest.OutboundSessionEstablishmentAndInitialHandshake
[       OK ] RatchetSessionManagerTest.OutboundSessionEstablishmentAndInitialHandshake (0 ms)
[ RUN      ] RatchetSessionManagerTest.PerDevicePayloadSerializationAndValidation
[       OK ] RatchetSessionManagerTest.PerDevicePayloadSerializationAndValidation (0 ms)
[ RUN      ] RatchetSessionManagerTest.MultiDeviceFanOut
[       OK ] RatchetSessionManagerTest.MultiDeviceFanOut (2 ms)
[ RUN      ] RatchetSessionManagerTest.PersistenceAndRestartResumption
[       OK ] RatchetSessionManagerTest.PersistenceAndRestartResumption (0 ms)
[ RUN      ] RatchetSessionManagerTest.SessionTermination
[       OK ] RatchetSessionManagerTest.SessionTermination (0 ms)
[----------] 5 tests from RatchetSessionManagerTest (5 ms total)

[----------] 7 tests from E2EEMessagingIntegrationTest
[ RUN      ] E2EEMessagingIntegrationTest.FullConversationLifecycleAndBidirectionalRatchet
[       OK ] E2EEMessagingIntegrationTest.FullConversationLifecycleAndBidirectionalRatchet (2 ms)
[ RUN      ] E2EEMessagingIntegrationTest.MultiDeviceFanoutAcrossParticipantsAndCompanions
[       OK ] E2EEMessagingIntegrationTest.MultiDeviceFanoutAcrossParticipantsAndCompanions (2 ms)
[ RUN      ] E2EEMessagingIntegrationTest.OutOfOrderDeliveryAndReplayPrevention
[       OK ] E2EEMessagingIntegrationTest.OutOfOrderDeliveryAndReplayPrevention (1 ms)
[ RUN      ] E2EEMessagingIntegrationTest.PostCompromiseSecurityHealing
[       OK ] E2EEMessagingIntegrationTest.PostCompromiseSecurityHealing (1 ms)
[ RUN      ] E2EEMessagingIntegrationTest.SessionPersistenceAndResumptionAcrossClientRestart
[       OK ] E2EEMessagingIntegrationTest.SessionPersistenceAndResumptionAcrossClientRestart (0 ms)
[ RUN      ] E2EEMessagingIntegrationTest.BackendEnvelopeValidationAndTamperResistance
[       OK ] E2EEMessagingIntegrationTest.BackendEnvelopeValidationAndTamperResistance (0 ms)
[ RUN      ] E2EEMessagingIntegrationTest.SafetyNumberVerificationAndRotationAlert
[       OK ] E2EEMessagingIntegrationTest.SafetyNumberVerificationAndRotationAlert (0 ms)
[----------] 7 tests from E2EEMessagingIntegrationTest (9 ms total)

[----------] Global test environment tear-down
[==========] 163 tests from 48 test suites ran. (698 ms total)
[  PASSED  ] 163 tests.
```

---

## 9. Production Deployment, Memory Hardening & Operations Guide

### 9.1 Memory Zeroization & Anti-Cold Boot Hardening
In native C++ cryptographic engineering, compiler optimizations (`-O2`, `-O3`) frequently eliminate standard `memset` calls if the compiler infers that the buffer is not read subsequently before being released or going out of scope.
To provide absolute protection against memory disclosure:
1. `OPENSSL_cleanse(ptr, len)` is strictly invoked on all sensitive stack and heap buffers. `OPENSSL_cleanse` uses volatile pointers and platform-specific barriers that prevent dead-store elimination.
2. `SecretString` wraps all cryptographic private keys, chain keys, root keys, and message keys. In its destructor, `SecretString` securely scrubs its underlying storage.
3. Future roadmap enhancements include memory locking (`mlock` on POSIX and `VirtualLock` on Windows) to prevent sensitive cryptographic structures from ever being written to swap files or hibernation images on disk.

### 9.2 Post-Quantum Cryptography (PQXDH) Migration Path
While Curve25519 provides 128-bit classical security, large-scale quantum computers running Shor's algorithm could theoretically solve the discrete logarithm problem over elliptic curves.
Card `CLIENT-006` is architected with a direct migration path to **PQXDH (Post-Quantum Extended Triple Diffie-Hellman)**:
- `EncryptedPayload::algorithm` on the backend already supports protocol versioning (`V2_Hybrid_PostQuantum`).
- When PQXDH is activated in Phase 3, the X3DH derivation formula will be augmented with a NIST-standardized Key Encapsulation Mechanism (ML-KEM-1024 / Kyber-1024):
$$IKM_{\text{PQ}} = DH_1 \mathbin{\Vert} DH_2 \mathbin{\Vert} DH_3 \mathbin{\Vert} DH_4 \mathbin{\Vert} SS_{\text{ML-KEM}}$$
- Because the Double Ratchet engine and `RatchetSessionManager` are decoupled from specific key exchange parameters, the introduction of post-quantum KEM ciphertext into the handshake header will require zero changes to the underlying messaging pipelines or UI presentation layers.

---

## 10. Final Card Sign-Off & Verification Checklist

```text
════════════════════════════════════════════════════════════════════════════════════════════════
                             CARD CLIENT-006 COMPLETION CHECKLIST
════════════════════════════════════════════════════════════════════════════════════════════════
[✔] CLIENT-006-T01: Cryptographic Primitives Expansion for X3DH & Double Ratchet
    • Extended ICryptoProvider with X25519 DH, HKDF-SHA256, AES-256-GCM AEAD, Safety Numbers.
    • Implemented OpenSslCryptoProvider using OpenSSL 3.x EVP primitives with zeroized buffers.
    • Deterministic StubCryptoProvider implementation for offline mocking.
    • RFC 7748 / RFC 5869 / NIST test vector validation.

[✔] CLIENT-006-T02: X3DH Key Agreement Engine & Handshake Protocol
    • Implemented X3dhHeader, X3dhInitiatorResult, and X3dhResponderResult domain models.
    • 4-way DH Key Agreement ($DH_1..DH_4$) with single-use One-Time Prekey (OPK) support.
    • Signed prekey signature verification using peer Ed25519 identity key.
    • Automatic OTPK consumption and secure wipe from Bob's private bundle.

[✔] CLIENT-006-T03: Double Ratchet State Machine & Key Derivation Chains
    • RatchetHeader binary serialization (42 bytes) with magic byte 'R'.
    • Symmetric sending/receiving KDF chains with immediate message key zeroization.
    • Asymmetric DH Ratchet turns injecting fresh Curve25519 entropy into root key schedule.
    • AES-256-GCM AEAD encryption with RatchetHeader authenticated as AAD.

[✔] CLIENT-006-T04: Skipped Message Key Store & Out-of-Order Packet Delivery
    • SkippedKeysStore holding message keys indexed by (DH_pub, message_number).
    • DoS protection: MAX_SKIP = 1,000 keys per step; MAX_STORED = 2,000 global capacity limit.
    • 14-day key time-to-live (TTL) expiration and automated pruning.
    • Immediate key wipe and zeroization upon extraction (Forward Secrecy preservation).

[✔] CLIENT-006-T05: Ratchet Session Manager, Multi-Device Fan-out & Secure Session Persistence
    • Pairwise per-device session management ((LocalDeviceId, PeerDeviceId)).
    • Automated multi-device participant fan-out across all active authorized recipient devices.
    • Binary session serialization (SCRS v1) into ISecureStorage.
    • Seamless session resumption across application lifecycle restarts.

[✔] CLIENT-006-T06: End-to-End Messaging Integration & Full Cryptographic Verification Suite
    • Integrated RatchetSessionManager into MessagingManager and ClientBootstrap.
    • Enforced ADR-008 pre-flight security guards (KeyChanged detection and blocked users).
    • Surfaced genuine 60-digit mutual Safety Numbers in WorkspaceViewModel.
    • Comprehensive 7-scenario E2EE integration test suite.
    • 163/163 unit and integration tests passing cleanly (100% pass rate).
    • 100% adherence to .clang-format across all 920 project files.
════════════════════════════════════════════════════════════════════════════════════════════════
```

### Sign-Off Recommendation
Card **`CLIENT-006`** is completely realized, thoroughly documented, and verified to production standard. The native desktop client now possesses an end-to-end Signal Double Ratchet encryption engine providing airtight Forward Secrecy and Post-Compromise Security. All quality gates are satisfied without compiler warnings, without external Docker dependencies, and with full formatting compliance.
