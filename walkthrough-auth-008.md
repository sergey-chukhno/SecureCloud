# Card Validation Report: AUTH-008 - Public Cryptographic Identity & Directory

**Card ID:** `AUTH-008`  
**Card Title:** Implement Public Cryptographic Identity & Directory  
**Phase:** Phase 1 — Authentication, Session Lifecycle, Multi-Factor Authentication & Cryptographic Identity  
**Date:** October 8, 2026  
**Status:** VALIDATED & COMPLETE  
**Repository:** `SecureCloud`  
**Branch:** `feature/auth-008-public-cryptographic-identity`  
**Test Suite Status:** 1,082 / 1,082 Tests Passed (100% Pass Rate)

---

## Table of Contents

1. [Executive Summary & Strategic Objective](#1-executive-summary--strategic-objective)
2. [Signal-Inspired Cryptographic Foundation: Detailed Mathematical & Protocol Blueprint](#2-signal-inspired-cryptographic-foundation-detailed-mathematical--protocol-blueprint)
   - 2.1 [The Fundamental Asynchronous Key Exchange Dilemma](#21-the-fundamental-asynchronous-key-exchange-dilemma)
   - 2.2 [The Extended Triple Diffie-Hellman (X3DH) Protocol Explained](#22-the-extended-triple-diffie-hellman-x3dh-protocol-explained)
   - 2.3 [Cryptographic Primitives: Ed25519 vs. X25519 Specialization](#23-cryptographic-primitives-ed25519-vs-x25519-specialization)
   - 2.4 [The Role of Prekey Bundles & One-Time Prekeys (OTKs)](#24-the-role-of-prekey-bundles--one-time-prekeys-otks)
   - 2.5 [Bridge to Forward Secrecy & The Double Ratchet](#25-bridge-to-forward-secrecy--the-double-ratchet)
   - 2.6 [The Zero Private Key Invariant: Hardware Enclave Isolation](#26-the-zero-private-key-invariant-hardware-enclave-isolation)
   - 2.7 [Mathematical Formulations of Curve25519 & Ed25519 Operations](#27-mathematical-formulations-of-curve25519--ed25519-operations)
   - 2.8 [Comprehensive Threat Modeling & Cryptographic Defenses](#28-comprehensive-threat-modeling--cryptographic-defenses)
3. [The Architectural Role of `CryptoDirectoryManager`](#3-the-architectural-role-of-cryptodirectorymanager)
   - 3.1 [Analogy: The Public Phonebook & Key Dispensary](#31-analogy-the-public-phonebook--key-dispensary)
   - 3.2 [Untrusted Key Broker Security Model](#32-untrusted-key-broker-security-model)
   - 3.3 [Atomic Single-Use Prekey Claiming & Race Prevention](#33-atomic-single-use-prekey-claiming--race-prevention)
   - 3.4 [Cryptographic Signature Verification & Gatekeeping](#34-cryptographic-signature-verification--gatekeeping)
   - 3.5 [Lifecycle State Machine & Key Depletion Handling](#35-lifecycle-state-machine--key-depletion-handling)
   - 3.6 [Detailed Architectural Sequence Diagrams](#36-detailed-architectural-sequence-diagrams)
   - 3.7 [Audit Trail & Compliance Invariants](#37-audit-trail--compliance-invariants)
4. [Ticket-by-Ticket Implementation Architecture](#4-ticket-by-ticket-implementation-architecture)
   - 4.1 [AUTH-008-T01: Domain Entities, Key Fingerprinting & Database Migrations](#41-auth-008-t01-domain-entities-key-fingerprinting--database-migrations)
   - 4.2 [AUTH-008-T02: Authoritative Directory Engine (`CryptoDirectoryManager`)](#42-auth-008-t02-authoritative-directory-engine-cryptodirectorymanager)
   - 4.3 [AUTH-008-T03: Protocol Buffer Contracts & AuthService gRPC Handlers](#43-auth-008-t03-protocol-buffer-contracts--authservice-grpc-handlers)
   - 4.4 [AUTH-008-T04: API Gateway Perimeter Routing, Security Policy & Forwarding](#44-auth-008-t04-api-gateway-perimeter-routing-security-policy--forwarding)
   - 4.5 [AUTH-008-T05: Production Wiring & Live PostgreSQL 17 E2E Integration Suite](#45-auth-008-t05-production-wiring--live-postgresql-17-e2e-integration-suite)
5. [Database Schema Evolution & Concurrency Control](#5-database-schema-evolution--concurrency-control)
   - 5.1 [Migration V4 Analysis: Schema & Index Strategy](#51-migration-v4-analysis-schema--index-strategy)
   - 5.2 [Concurrency Semantics: `FOR UPDATE SKIP LOCKED`](#52-concurrency-semantics-for-update-skip-locked)
   - 5.3 [Strict PostgreSQL Port Isolation (Port 5433 vs. 5432)](#53-strict-postgresql-port-isolation-port-5433-vs-5432)
6. [API Gateway Perimeter Integration & Route Matching](#6-api-gateway-perimeter-integration--route-matching)
   - 6.1 [Parameterized Route Regex Compilation](#61-parameterized-route-regex-compilation)
   - 6.2 [Fail-Closed Security Evaluation Precedence](#62-fail-closed-security-evaluation-precedence)
   - 6.3 [Perimeter Cross-Device Validation (`403 DEVICE_MISMATCH`)](#63-perimeter-cross-device-validation-403-device_mismatch)
   - 6.4 [RFC 7807 Problem Details Payloads & Error Invariants](#64-rfc-7807-problem-details-payloads--error-invariants)
   - 6.5 [Resilience Integration: Bulkhead Isolation, Circuit Breakers & Deadlines](#65-resilience-integration-bulkhead-isolation-circuit-breakers--deadlines)
7. [Traceability Matrix against Acceptance Criteria](#7-traceability-matrix-against-acceptance-criteria)
8. [Comprehensive Verification & Test Execution Evidence](#8-comprehensive-verification--test-execution-evidence)
   - 8.1 [Live PostgreSQL 17 E2E Integration Test Suite Execution](#81-live-postgresql-17-e2e-integration-test-suite-execution)
   - 8.2 [Detailed Scenario Breakdown of Integration Tests](#82-detailed-scenario-breakdown-of-integration-tests)
   - 8.3 [API Gateway Route & Policy Unit Test Execution](#83-api-gateway-route--policy-unit-test-execution)
   - 8.4 [AuthService gRPC & Directory Manager Unit Test Execution](#84-authservice-grpc--directory-manager-unit-test-execution)
   - 8.5 [Cryptographic Primitives & Fingerprint Test Execution](#85-cryptographic-primitives--fingerprint-test-execution)
   - 8.6 [Full Repository Test Suite (1,082 Tests Passed)](#86-full-repository-test-suite-1082-tests-passed)
   - 8.7 [Code Quality & Clang-Format Verification](#87-code-quality--clang-format-verification)
9. [Conclusion & Next Phase Transition](#9-conclusion--next-phase-transition)

---

## 1. Executive Summary & Strategic Objective

SecureCloud is an enterprise-grade cloud storage and synchronization platform built on a zero-knowledge, end-to-end encrypted (E2EE) architectural paradigm. Card **AUTH-008** establishes the authoritative foundation for cryptographic identity discovery across all clients, devices, and downstream services (such as File Storage, Chunk Synchronization, and Direct Messaging).

### The Objective of AUTH-008
In a modern multi-device zero-knowledge cloud platform, users own multiple devices (laptops, phones, tablets, workstations), and each device acts as an independent cryptographic principal. When Alice wants to share an encrypted file with Bob, or when Alice wants to synchronize an encrypted file across her own devices:
1. **The Server Must Never Possess Encryption Keys:** Under zero-knowledge guarantees, the backend cannot decrypt data, generate encryption keys on behalf of users, or participate in key exchange.
2. **Devices Are Frequently Offline:** In asynchronous cloud workflows, Bob or Alice's secondary devices may be powered off, suspended, or in airplane mode when a file or session is shared.
3. **Identity Verification & Anti-MITM:** Alice must be mathematically certain that the cryptographic keys she receives to encrypt files belong to Bob's legitimate hardware, and not to an imposter or a malicious server.
4. **Forward Secrecy & Compromise Resilience:** If Bob's temporary session keys are compromised in the future, past historical encrypted data must remain secure.

Card **AUTH-008** implements the backend public key directory infrastructure inspired by the world-standard **Signal Protocol (Extended Triple Diffie-Hellman / X3DH)**. It establishes:
- The persistent storage and lifecycle tracking of public cryptographic identities (`Ed25519` Identity Keys, `X25519` Signed Prekeys, and pools of `X25519` One-Time Prekeys).
- The `CryptoDirectoryManager` engine as an untrusted, authoritative public directory and key dispenser.
- High-performance gRPC services and API Gateway perimeter routes.
- Atomic claiming mechanics (`SELECT ... FOR UPDATE SKIP LOCKED`) guaranteeing single-use prekey consumption.
- Strict architectural isolation preventing private keys from ever reaching or traversing the Auth service.

---

## 2. Signal-Inspired Cryptographic Foundation: Detailed Mathematical & Protocol Blueprint

```
+===================================================================================+
|                        SIGNAL PROTOCOL CRYPTOGRAPHIC ALIGNMENT                     |
+===================================================================================+
|                                                                                   |
|  ALICE (Initiator / Sender)                              BOB (Recipient Device)   |
|  =========================                              ======================   |
|                                                                                   |
|  1. Generate Ephemeral Keypair (EK_A)                                             |
|  2. Query CryptoDirectoryManager -------------------> [SECURECLOUD BACKEND]       |
|     for Bob's Prekey Bundle:                             |                        |
|       - Identity Key (IK_B) [Ed25519]                    | 32-byte Ed25519 Identity|
|       - Signed Prekey (SPK_B) [X25519]                   | 32-byte X25519 Signed  |
|       - Prekey Signature (Sig_B) [64-byte Ed25519]       | 64-byte Signature      |
|       - One-Time Prekey (OPK_B) [X25519]                 | Atomically Claim 1 OTK |
|                                                          |                        |
|  3. Verify Sig_B on SPK_B using IK_B <-------------------+ (Prekey Bundle)        |
|  4. Perform X3DH Triplet/Quadruplet:                                              |
|       DH1 = DH(IK_A, SPK_B)   [Mutual Authentication]                             |
|       DH2 = DH(EK_A, IK_B)    [Ephemeral Authenticity]                            |
|       DH3 = DH(EK_A, SPK_B)   [Forward Secrecy]                                   |
|       DH4 = DH(EK_A, OPK_B)   [Single-Use Anti-Replay]                            |
|       SK  = KDF(DH1 || DH2 || DH3 || DH4)                                         |
|  5. Encrypt Initial Header & Data using SK                                        |
|  6. Transmit Encrypted Payload to Cloud ---------> Encrypted Blob Storage         |
|                                                              |                    |
|                                                     (Bob powers on device later)  |
|                                                              |                    |
|                                                     7. Bob fetches blob, reads    |
|                                                        IK_A and EK_A from header  |
|                                                     8. Bob computes identical DH: |
|                                                        DH1 = DH(SPK_B, IK_A)      |
|                                                        DH2 = DH(IK_B, EK_A)       |
|                                                        DH3 = DH(SPK_B, EK_A)      |
|                                                        DH4 = DH(OPK_B, EK_A)      |
|                                                        SK  = KDF(DH1||DH2||DH3||DH4)
|                                                     9. Bob derives SK & decrypts! |
+===================================================================================+
```

### 2.1 The Fundamental Asynchronous Key Exchange Dilemma

Traditional public-key cryptography allows two parties who are simultaneously online to negotiate a shared secret via an interactive Diffie-Hellman handshake (e.g. TLS 1.3 key exchange). However, in asynchronous distributed cloud systems:
- Alice cannot wait for Bob's laptop to wake up from sleep mode before encrypting and synchronizing files.
- If Alice encrypts files using only Bob's static public key (simple PGP/RSA style), the system suffers catastrophic security flaws:
  1. **No Forward Secrecy:** If Bob's static private key is compromised years later, an adversary who stored historical encrypted network packets or cloud blobs can decrypt every historical file.
  2. **Replay Attacks:** An adversary can replay historical handshakes and trick recipient devices into establishing repeated sessions with identical initial keys.
  3. **Weak Identity Binding:** Without cryptographic proof that sub-keys belong to the primary device, an attacker could inject rogue prekeys into directory services.

To solve this dilemma without requiring live peer-to-peer connectivity, SecureCloud adopts the **Signal Extended Triple Diffie-Hellman (X3DH)** protocol architecture.

---

### 2.2 The Extended Triple Diffie-Hellman (X3DH) Protocol Explained

X3DH establishes a shared secret key between two parties who mutually authenticate each other through public keys, even when the recipient is offline.

The protocol requires Bob to publish a **Prekey Bundle** to the server beforehand. When Alice wishes to initiate communication with Bob:
1. Alice requests Bob's Prekey Bundle from `CryptoDirectoryManager`.
2. The server dispenses:
   - $IK_B$: Bob's long-term **Identity Key** (32 bytes).
   - $SPK_B$: Bob's current **Signed Prekey** (32 bytes).
   - $Sig_B$: Bob's cryptographic signature over $SPK_B$ generated by $IK_B$ (64 bytes).
   - $OPK_B$: A fresh, single-use **One-Time Prekey** (32 bytes), atomically removed from Bob's pool upon dispatch.
3. Alice validates $Sig_B$ using $IK_B$. If invalid, Alice aborts immediately (preventing man-in-the-middle key substitution).
4. Alice generates an ephemeral keypair $(EK_A, ek_A)$.
5. Alice computes four Diffie-Hellman calculations:
   $$\begin{aligned}
   DH_1 &= \text{X25519}(ik_A, SPK_B) && \text{(Provides mutual authentication)} \\
   DH_2 &= \text{X25519}(ek_A, IK_B) && \text{(Provides forward secrecy vs Alice's identity)} \\
   DH_3 &= \text{X25519}(ek_A, SPK_B) && \text{(Provides forward secrecy vs Bob's signed prekey)} \\
   DH_4 &= \text{X25519}(ek_A, OPK_B) && \text{(Provides single-use forward secrecy and anti-replay)}
   \end{aligned}$$
6. Alice derives the Master Shared Key ($SK$) using a cryptographic Key Derivation Function (HKDF-SHA256):
   $$SK = \text{HKDF-Extract-and-Expand}(DH_1 \parallel DH_2 \parallel DH_3 \parallel DH_4, \text{info}=\text{"SecureCloud-X3DH-v1"})$$
7. When Bob eventually comes online, he reads Alice's public keys ($IK_A$ and $EK_A$) and his $OPK_B$ identifier from the message metadata, evaluates the exact same DH calculations using his private keys $(spk_B, ik_B, opk_B)$, and arrives at the identical shared secret $SK$.
8. Bob immediately destroys his private $opk_B$, permanently guaranteeing that past sessions can never be decrypted even if Bob's device is subsequently compromised.

---

### 2.3 Cryptographic Primitives: Ed25519 vs. X25519 Specialization

A common architectural vulnerability in naive implementations is attempting to use the same elliptic curve key for both digital signatures and Diffie-Hellman key agreement. In SecureCloud:

| Primitive | Mathematical Curve | Purpose | Key Size | Format |
| :--- | :--- | :--- | :--- | :--- |
| **Ed25519** | Twisted Edwards Curve: $-x^2 + y^2 = 1 - \frac{121665}{121666} x^2 y^2$ over $2^{255}-19$ | Digital Signatures & Long-Term Identity | 32 bytes (Pub), 64 bytes (Sig) | RFC 8032 Raw Octets |
| **X25519** | Montgomery Curve: $v^2 = u^3 + 486662 u^2 + u$ over $2^{255}-19$ | Diffie-Hellman Key Agreement (Prekeys) | 32 bytes (Pub / Ephemeral) | RFC 7748 Raw Octets |

#### Why Ed25519 for Identity?
- **High-Speed Signatures:** Verification requires minimal CPU cycles without compromising security.
- **Deterministic Signatures:** Eliminates random number generator (RNG) vulnerabilities during signing (unlike ECDSA, which leaks private keys if the nonce $k$ is reused or biased).
- **Strong Tamper Resistance:** Signatures are 64 bytes and non-malleable.

#### Why X25519 for Prekeys?
- **Montgomery Ladder:** Permits constant-time scalar multiplication protecting against side-channel timing attacks.
- **Universal Point Acceptance:** Every 32-byte string is a valid Montgomery curve coordinate or maps cleanly, eliminating small-subgroup validation attacks.

---

### 2.4 The Role of Prekey Bundles & One-Time Prekeys (OTKs)

Why cannot an asynchronous system rely only on the long-term identity key and signed prekey?
If only $IK$ and $SPK$ were used:
- An attacker recording ciphertext could capture messages sent to Bob.
- If Bob's device is compromised while $SPK$ is active (or if $SPK$ was compromised after 7 days of rotation), the attacker could compute $DH_1, DH_2, DH_3$ and decrypt **every single message or file** exchanged during that period!
- Furthermore, if Alice sends multiple files to Bob while Bob is offline, all files would share the same prekey material.

**The Role of One-Time Prekeys (OTKs):**
- Bob generates 50 to 100 ephemeral X25519 keypairs and uploads only their public components to `CryptoDirectoryManager`.
- Each OTK is used **exactly once**.
- The server dispenses $OPK_1$ to Alice, and immediately removes or marks $OPK_1$ as `Claimed`.
- When Charlie asks for Bob's bundle 10 milliseconds later, the server dispenses $OPK_2$.
- Because $DH_4 = \text{X25519}(EK_A, OPK_1)$, even if Bob's signed prekey is compromised later, an attacker cannot compute $DH_4$ because Bob destroyed the private half of $OPK_1$ immediately upon first reading Alice's message!
- If the server runs out of OTKs (the pool is depleted), the system gracefully degrades to 3-party DH ($DH_1, DH_2, DH_3$) until Bob reconnects and replenishes his pool.

---

### 2.5 Bridge to Forward Secrecy & The Double Ratchet

Once the initial master shared secret ($SK$) is calculated via X3DH, it serves as the input root key for the **Double Ratchet Algorithm**:
1. **Symmetric Ratchet (KDF Chain):** Every message or block encrypted advances a Hash-based KDF chain. Once a message key is used, it is deleted.
2. **Diffie-Hellman Ratchet:** With each round-trip communication, new ephemeral Diffie-Hellman keys are exchanged, continuously restoring forward secrecy and providing *Break-in Recovery* (Future Secrecy).

AUTH-008 lays the bedrock for this entire architecture by providing the authoritative, tamper-proof directory that distributes the prekey bundles required to initialize the very first step of the ratchet.

---

### 2.6 The Zero Private Key Invariant: Hardware Enclave Isolation

A paramount security constraint enforced throughout SecureCloud:
> **INVARIANT 1: Zero Private Key Ingress**  
> Device private keys never enter the Auth service, never traverse the API Gateway, and are never written to any database or cache. Private keys remain exclusively inside client hardware security enclaves (Apple Secure Enclave, Android StrongBox / KeyStore, TPM 2.0 / HSM).

The backend stores and dispenses **only public cryptographic material**:
- 32-byte Ed25519 public identity keys
- 32-byte X25519 public signed prekeys
- 64-byte Ed25519 signatures
- 32-byte X25519 public one-time prekeys
- Opaque UUIDs identifying keys and devices

---

### 2.7 Mathematical Formulations of Curve25519 & Ed25519 Operations

#### 1. Ed25519 Digital Signature Algorithm (RFC 8032)
Let $B$ be the base point on the twisted Edwards curve $-x^2 + y^2 = 1 - \frac{121665}{121666}x^2y^2$ over $\mathbb{F}_{2^{255}-19}$.
Let $\ell = 2^{252} + 27742317777372353535851937790883648493$ be the prime group order.

1. **Key Generation:**
   - Private seed $k \in \{0, 1\}^{256}$.
   - $h = \text{SHA-512}(k) = (h_0, h_1, \dots, h_{63})$.
   - Prune scalar $a$: clear bits 0, 1, 2 of $h_0$; clear bit 7 of $h_{31}$; set bit 6 of $h_{31}$.
   - Public key $A = a \cdot B$.
2. **Signing Message $M$:**
   - Deterministic nonce $r = \text{SHA-512}(h_{32..63} \parallel M) \pmod \ell$.
   - Commitment point $R = r \cdot B$.
   - Challenge scalar $e = \text{SHA-512}(\underline{R} \parallel \underline{A} \parallel M) \pmod \ell$.
   - Signature scalar $s = (r + e \cdot a) \pmod \ell$.
   - Signature is 64 octets: $\underline{R} \parallel \underline{s}$.
3. **Verification of $(R, s)$ with Public Key $A$:**
   - Check $s < \ell$. If false, reject.
   - Decompress $R$ and $A$ to curve points. If invalid coordinates, reject.
   - Recompute $e = \text{SHA-512}(\underline{R} \parallel \underline{A} \parallel M) \pmod \ell$.
   - Verify curve equation:
     $$8s \cdot B = 8R + 8e \cdot A$$
   - If equality holds, the signature is mathematically authentic.

#### 2. X25519 Diffie-Hellman Key Agreement (RFC 7748)
Let $u$ be the coordinate on the Montgomery curve $v^2 = u^3 + 486662u^2 + u$ over $\mathbb{F}_{2^{255}-19}$.
Base point $u = 9$.

1. **Scalar Clamping:**
   - Scalar $s \in \{0, 1\}^{256}$.
   - Clear bits 0, 1, 2 of $s[0]$ (ensures scalar is a multiple of cofactor 8).
   - Clear bit 7 of $s[31]$ and set bit 6 of $s[31]$ (ensures scalar magnitude is bounded).
2. **Montgomery Ladder:**
   - Calculates $X25519(s, u)$ in constant time using $255$ ladder steps, each consisting of 1 differential addition and 1 point doubling.
   - Requires zero $y$-coordinate computations.
   - Side-channel resilient: exact same execution path regardless of bit pattern in $s$.

---

### 2.8 Comprehensive Threat Modeling & Cryptographic Defenses

| Threat Vector | Attack Scenario | Defense Implemented in AUTH-008 |
| :--- | :--- | :--- |
| **T-1: Untrusted Server / DB Compromise** | An adversary compromises the PostgreSQL database or Auth daemon memory. | **Zero Private Key Invariant:** Only public keys ($IK, SPK, OPK$) are stored. The attacker cannot decrypt historical or future file ciphertexts. |
| **T-2: Man-in-the-Middle (MitM) Key Injection** | A rogue proxy attempts to replace Bob's signed prekey with an attacker-controlled X25519 key. | **Cryptographic Proof of Ownership:** Bob's $SPK$ is signed by Bob's long-term $IK$. Alice verifies the signature; `CryptoDirectoryManager` verifies the signature prior to database persistence. Rejection is guaranteed. |
| **T-3: Cross-Device Prekey Tampering** | Device A attempts to overwrite or exhaust prekeys belonging to Device B. | **Perimeter & Service Authorization Checks:** The API Gateway enforces `ctx.device_id() == target_device_id` with `403 DEVICE_MISMATCH`; `CryptoDirectoryManager` enforces `caller_user_id == dev.user_id` with `PERMISSION_DENIED`. |
| **T-4: Future Device Compromise** | Bob's device is seized or forensically analyzed in 2028. | **Forward Secrecy via Single-Use OTKs:** Historical sessions utilized unique $OPK$s destroyed by Bob upon session establishment. The adversary cannot reconstruct $DH_4$. |
| **T-5: Concurrent Key Claim Race** | 100 simultaneous clients attempt to claim Bob's OTKs at the exact same instant. | **Pessimistic Locking (`FOR UPDATE SKIP LOCKED`):** PostgreSQL serializes row claims without thread contention or deadlocks, ensuring zero duplicate key distributions. |

---

## 3. The Architectural Role of `CryptoDirectoryManager`

### 3.1 Analogy: The Public Phonebook & Key Dispensary

To clearly understand the role of `CryptoDirectoryManager`, consider the analogy of an old-fashioned public telephone directory combined with a physical single-use token dispensary:

```
+-----------------------------------------------------------------------------------+
|                         THE PUBLIC PHONEBOOK & KEY DISPENSARY                     |
+-----------------------------------------------------------------------------------+
|                                                                                   |
|  [ PUBLIC PHONEBOOK ]                                                             |
|  - Published Names & Numbers: Alice looks up Bob's name to find his devices.      |
|  - Verified Signatures: The phone company verifies Bob's notary stamp before      |
|    updating his published number.                                                 |
|                                                                                   |
|  [ ONE-TIME KEY DISPENSARY ]                                                      |
|  - Like numbered paper tickets at a deli counter:                                 |
|    * Bob places 100 single-use keys into his slot.                                |
|    * Alice takes ticket #1. It is stamped CLAIMED and gone forever.               |
|    * Charlie takes ticket #2.                                                     |
|    * If the tickets run out, customers can still use Bob's main desk phone        |
|      (Signed Prekey), but they are alerted to replenish tickets soon.             |
|                                                                                   |
|  [ UNTRUSTED OPERATOR ]                                                           |
|  - The dispensary operator cannot listen to phone calls because calls are         |
|    encrypted with keys the operator never possesses (private keys).               |
+-----------------------------------------------------------------------------------+
```

1. **The Public Phonebook (Directory Lookups):**
   When Alice wants to encrypt a file for Bob, she does not know Bob's device hardware keys. She queries `CryptoDirectoryManager`. The manager looks up all active, approved devices belonging to Bob and compiles their public prekey bundles.
2. **The Key Dispensary (One-Time Prekey Vending):**
   Inside Bob's entry in the phonebook, there is a dispensary containing numbered, single-use keys (OTKs). Every time Alice queries Bob's directory to start an encryption session, `CryptoDirectoryManager` pulls exactly one OTK out of the dispensary, marks it as `Claimed`, and hands it to Alice. No other caller will ever receive that exact same OTK.
3. **The Notary Gatekeeper (Signature Verification):**
   When Bob rotates his intermediate signed prekey, `CryptoDirectoryManager` acts as a strict notary: it checks whether Bob's long-term identity key signed the new prekey. If the signature does not match, the update is rejected on the spot.

---

### 3.2 Untrusted Key Broker Security Model

In zero-knowledge architecture, the backend server is treated as an **untrusted broker**.
- The server could be compromised by an adversary, or a rogue administrator might inspect database rows.
- Because `CryptoDirectoryManager` stores only public keys, an attacker with full read access to the database gains **zero ability to decrypt user files or messages**.
- Furthermore, because Alice cryptographically validates the prekey signature using Bob's long-term identity key (and can verify Bob's identity key fingerprint out-of-band via QR code or safety numbers), a rogue server cannot substitute Bob's prekeys with malicious keys without causing Alice's client to reject the signature immediately!

---

### 3.3 Atomic Single-Use Prekey Claiming & Race Prevention

In a high-throughput multi-user cloud, multiple clients may simultaneously query the directory for the same recipient device (e.g. Alice and Charlie simultaneously sharing files with Bob).

If two concurrent database transactions read the same one-time prekey, both sessions would compute identical $DH_4$ terms, degrading the forward secrecy guarantee of X3DH.

`CryptoDirectoryManager` solves this via PostgreSQL pessimistic locking with skip-locked concurrency:
```sql
SELECT key_id, device_id, key_type, public_key, key_status, created_at, revoked_at, replaced_by_key_id, signature
FROM device_public_keys
WHERE device_id = $1 AND key_type = 'ONE_TIME_PREKEY' AND key_status = 'Active'
ORDER BY created_at ASC
LIMIT 1 FOR UPDATE SKIP LOCKED;
```
- `FOR UPDATE`: Locks the selected row exclusively against concurrent transactions.
- `SKIP LOCKED`: If another concurrent transaction is already claiming the oldest OTK, the second transaction does not block; it immediately skips the locked row and claims the *next available* active OTK in the pool!
- The selected key is immediately updated to `key_status = 'Claimed'` in the same atomic transaction.
- High-concurrency throughput is maximized while strictly eliminating race conditions and duplicate key vending.

---

### 3.4 Cryptographic Signature Verification & Gatekeeping

When a device rotates its signed prekey, it must submit:
- `target_device_id`
- `new_signed_prekey` (32 bytes X25519)
- `new_signature` (64 bytes Ed25519)

`CryptoDirectoryManager` acts as the authoritative gatekeeper:
```cpp
// 1. Fetch active Ed25519 identity key
auto id_key_opt = public_key_repo_->find_active_identity_key(target_device_id, tx);
if (!id_key_opt.has_value()) {
    return UpdateCryptoPrekeysResult::failure(
        UpdateCryptoPrekeysResult::Status::DeviceNotFound, "No active identity key found for device");
}

// 2. Mathematically verify Ed25519 signature over X25519 prekey bytes
bool sig_valid = crypto::PrekeySignatureVerifier::verify_ed25519_signature(
    id_key_opt->public_key, new_signed_prekey, new_signature);
if (!sig_valid) {
    return UpdateCryptoPrekeysResult::failure(
        UpdateCryptoPrekeysResult::Status::InvalidPrekeySignature,
        "Cryptographic signature verification failed for signed prekey rotation");
}

// 3. Mark old signed prekey as Replaced, insert new signed prekey as Active
```

If an attacker tries to inject a rogue signed prekey for Bob's device without possessing Bob's private identity key, the verification fails mathematically, and the database remains untouched.

---

### 3.5 Lifecycle State Machine & Key Depletion Handling

```
+-----------------------------------------------------------------------------------+
|                        DEVICE & PUBLIC KEY LIFECYCLE STATES                       |
+-----------------------------------------------------------------------------------+
|                                                                                   |
|  Device Status:                                                                   |
|  [PendingAuthorization] ----(MFA Approved)----> [Active] ----(Revoked)----> [Revoked]
|           |                                       |                           |
|           | (Omitted from Directory)              | (Prekey Bundle Dispensed) | (Omitted from Dir;
|           v                                       v                           |  Flags REVOKED in
|      No Bundle                               Bundle Returned                  v  Identity queries)
|                                                                           All Keys Revoked
|                                                                                   |
|  Key Lifecycle States:                                                            |
|  - Identity Key:      [Active]  ------------(Device Revocation)------------> [Revoked]
|  - Signed Prekey:     [Active]  ------------(Rotation / Replacement)-------> [Replaced]
|  - One-Time Prekey:   [Active]  ------------(Directory Discovery Claim)-----> [Claimed]
|                                                                                   |
+-----------------------------------------------------------------------------------+
```

- **Graceful Depletion Fallback:**
  When all one-time prekeys are claimed (`remaining_one_time_prekeys == 0`):
  - `CryptoDirectoryManager` does not fail the directory query.
  - It constructs the bundle containing the active Identity Key and Signed Prekey, sets `one_time_prekey = std::nullopt`, and reports `remaining_one_time_prekeys = 0`.
  - The client proceeds using 3-party Diffie-Hellman ($DH_1, DH_2, DH_3$), maintaining security while notifying Bob to replenish his OTK pool.

---

### 3.6 Detailed Architectural Sequence Diagrams

#### Sequence Diagram 1: Multi-Device Prekey Bundle Discovery & Atomic Vending
```text
Alice (Client)       API Gateway         AuthService gRPC     CryptoDirectoryMgr    Postgres DB (17)
      |                    |                    |                     |                     |
      |-- GET /directory ->|                    |                     |                     |
      |   (Bearer Token)   |-- Authenticate --->|                     |                     |
      |                    |-- gRPC Call ------>|                     |                     |
      |                    |   GetDeviceCryptoDirectory               |                     |
      |                    |                    |-- query dev ------>|                     |
      |                    |                    |                     |-- SELECT devices -->|
      |                    |                    |                     |<-- active dev list -|
      |                    |                    |                     |                     |
      |                    |                    |                     |-- [For each dev] -->|
      |                    |                    |                     |   SELECT keys       |
      |                    |                    |                     |   CLAIM 1 OTK       |
      |                    |                    |                     |   (SKIP LOCKED) --->|
      |                    |                    |                     |<-- claimed OTK -----|
      |                    |                    |                     |                     |
      |                    |                    |<-- bundles array ---|                     |
      |                    |<-- gRPC Resp ------|                     |                     |
      |<-- HTTP 200 (JSON)-|                    |                     |                     |
      |    (Prekey Bundles)|                    |                     |                     |
```

#### Sequence Diagram 2: Signed Prekey Rotation & Cryptographic Gatekeeping
```text
Bob (Device)         API Gateway         AuthService gRPC     CryptoDirectoryMgr    Postgres DB (17)
      |                    |                    |                     |                     |
      |-- POST /prekeys -->|                    |                     |                     |
      |   (new SPK + Sig)  |-- Check Ownership -|                     |                     |
      |                    |   dev_id == ctx_id |                     |                     |
      |                    |-- gRPC Call ------>|                     |                     |
      |                    |   UpdateCryptoPrekeys                    |                     |
      |                    |                    |-- verify & update ->|                     |
      |                    |                    |                     |-- fetch ID key ---->|
      |                    |                    |                     |<-- ID pubkey -------|
      |                    |                    |                     |                     |
      |                    |                    |                     |-- Ed25519 Verify ---+
      |                    |                    |                     |   (OpenSSL EVP)     |
      |                    |                    |                     |   [Valid / Match]   |
      |                    |                    |                     |                     |
      |                    |                    |                     |-- UPDATE old SPK -->|
      |                    |                    |                     |-- INSERT new SPK -->|
      |                    |                    |                     |<-- Commit TX -------|
      |                    |                    |<-- success result --|                     |
      |                    |<-- gRPC Resp ------|                     |                     |
      |<-- HTTP 200 (JSON)-|                    |                     |                     |
```

---

### 3.7 Audit Trail & Compliance Invariants

Every cryptographic lifecycle transition triggers structured audit events:
1. `AuditEvent::prekeys_updated`: Emitted when one-time prekeys are uploaded or replenished.
   - Payload captures `user_id`, `device_id`, `added_otk_count`, `active_otk_count`, `client_ip`, and `timestamp`.
2. `AuditEvent::signed_prekey_rotated`: Emitted upon successful rotation of intermediate signed prekeys.
   - Payload captures `user_id`, `device_id`, `old_key_id`, `new_key_id`, `client_ip`, and `timestamp`.

These events are routed through `AuditEventPublisher` to secure audit log pipelines for SIEM monitoring and forensic non-repudiation.

---

## 4. Ticket-by-Ticket Implementation Architecture

### 4.1 AUTH-008-T01: Domain Entities, Key Fingerprinting & Database Migrations
- **Domain Models ([`src/auth/domain/entities.hpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/auth/domain/entities.hpp)):**
  - Added `DevicePublicKeyEntity` with `key_id`, `device_id`, `key_type`, `public_key`, `key_status`, `created_at`, `revoked_at`, `replaced_by_key_id`, and `signature`.
  - Added `PrekeyBundle` representing an authoritative multi-device prekey package.
- **Cryptographic Fingerprinting ([`src/auth/crypto/key_fingerprint.hpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/auth/crypto/key_fingerprint.hpp) & [`key_fingerprint.cpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/auth/crypto/key_fingerprint.cpp)):**
  - Implemented `KeyFingerprint::compute_sha256` producing standard colon-separated hex representations (`SHA256:XX:XX:...`).
  - Implemented `KeyFingerprint::compute_raw_sha256` producing 32-byte binary digests.
- **Prekey Signature Verifier ([`src/auth/crypto/prekey_signature_verifier.hpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/auth/crypto/prekey_signature_verifier.hpp) & [`prekey_signature_verifier.cpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/auth/crypto/prekey_signature_verifier.cpp)):**
  - High-performance constant-time Ed25519 signature verification using OpenSSL `EVP_DigestVerifyInit` / `EVP_DigestVerify`.
- **Database Repository Extensions ([`src/auth/repository/device_public_key_repository.hpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/auth/repository/device_public_key_repository.hpp) & [`device_public_key_repository.cpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/auth/repository/device_public_key_repository.cpp)):**
  - `claim_one_time_prekey`: Atomically queries and marks 1 OTK as `Claimed` using `FOR UPDATE SKIP LOCKED`.
  - `count_active_one_time_prekeys`: Counts active OTKs for depletion monitoring.
  - `find_active_identity_key`: Retrieves active Ed25519 identity key.
  - `find_active_signed_prekey`: Retrieves active X25519 signed prekey.
  - `store_one_time_prekeys`: Batch inserts newly uploaded OTKs.
- **Database Migration ([`src/auth/db/migrations/V4__create_device_prekey_bundles.sql`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/auth/db/migrations/V4__create_device_prekey_bundles.sql)):**
  - Schema migration adding `signature BYTEA` and partial index `idx_device_public_keys_active_otk`.

### 4.2 AUTH-008-T02: Authoritative Directory Engine (`CryptoDirectoryManager`)
- **Interface & Service ([`src/auth/service/crypto_directory_manager.hpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/auth/service/crypto_directory_manager.hpp) & [`crypto_directory_manager.cpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/auth/service/crypto_directory_manager.cpp)):**
  - `get_crypto_identity(device_id)`: Single device identity lookup with revocation awareness.
  - `get_device_crypto_directory(user_id, filter_device_ids)`: Multi-device discovery assembling prekey bundles and claiming single-use OTKs.
  - `update_crypto_prekeys(...)`: Authoritative prekey rotation and pool replenishment with caller authorization verification, Ed25519 signature validation, and audit event publishing.

### 4.3 AUTH-008-T03: Protocol Buffer Contracts & AuthService gRPC Handlers
- **Protobuf Enhancements ([`proto/securecloud/auth/v1/auth.proto`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/proto/securecloud/auth/v1/auth.proto)):**
  - Updated `DeviceCryptoRecord` with `identity_key_fingerprint`, `signed_prekey_created_at_epoch_ms`, `remaining_one_time_prekeys`, and `one_time_prekey_id`.
  - Updated `GetCryptoIdentityResponse` and `UpdateCryptoPrekeysResponse`.
- **gRPC Service Implementation ([`src/auth/service/auth_service_impl.hpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/auth/service/auth_service_impl.hpp) & [`auth_service_impl.cpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/auth/service/auth_service_impl.cpp)):**
  - Implemented `GetDeviceCryptoDirectory`, `GetCryptoIdentity`, and `UpdateCryptoPrekeys` handlers.
  - Integrated caller authentication extraction (`extract_caller_user_id`, `extract_caller_device_id`).
  - Added in-process test helpers (`set_caller_identity_for_testing`).

### 4.4 AUTH-008-T04: API Gateway Perimeter Routing, Security Policy & Forwarding
- **Parameterized Regex Routing ([`src/gateway/http/auth/gateway_security_policy.hpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/gateway/http/auth/gateway_security_policy.hpp) & [`gateway_security_policy.cpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/gateway/http/auth/gateway_security_policy.cpp)):**
  - Extended policy engine with compiled regex matching for path parameters (`:param` / `{param}`).
  - Enforced deterministic precedence: `Exact` $\to$ `Parameterized` $\to$ `Longest Prefix` $\to$ `Fail-closed Protected`.
  - Registered protected routes (`min_auth_level = PRIMARY`):
    * `GET /api/v1/users/:user_id/devices/crypto-directory`
    * `GET /api/v1/devices/:device_id/crypto-identity`
    * `POST /api/v1/devices/:device_id/prekeys`
- **Reverse Proxy Handlers ([`src/gateway/http/proxy/auth_proxy_handler.hpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/gateway/http/proxy/auth_proxy_handler.hpp) & [`auth_proxy_handler.cpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/gateway/http/proxy/auth_proxy_handler.cpp)):**
  - Route parameter extraction and perimeter validation.
  - Cross-device security enforcement (`ctx.device_id() != device_id` $\to$ `403 FORBIDDEN` / `DEVICE_MISMATCH`).
  - Bulkhead isolation, circuit breaker failure tracking, and RFC 7807 problem details error mapping.
- **gRPC Client Extension ([`src/gateway/grpc/auth_service_client.cpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/gateway/grpc/auth_service_client.cpp) & [`client_call_context.hpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/gateway/grpc/client_call_context.hpp)):**
  - Added metadata header propagation (`x-user-id`, `x-device-id`, `x-auth-level`).

### 4.5 AUTH-008-T05: Production Wiring & Live PostgreSQL 17 E2E Integration Suite
- **Production Server Wiring ([`src/auth/main.cpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/auth/main.cpp)):**
  - Instantiated `CryptoDirectoryManager` with live production database connection pool.
  - Injected `crypto_directory_mgr` into `AuthServiceImpl` for production gRPC serving.
- **Live Integration Test Suite ([`tests/integration/auth_crypto_identity_integration_test.cpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/tests/integration/auth_crypto_identity_integration_test.cpp)):**
  - 9 live scenarios executed against containerized PostgreSQL 17 on port 5433 with strict port 5432 preflight protection.

---

## 5. Database Schema Evolution & Concurrency Control

### 5.1 Migration V4 Analysis: Schema & Index Strategy

The migration script `V4__create_device_prekey_bundles.sql` was integrated into the migration runner pipeline:

```sql
-- Migration: V4__create_device_prekey_bundles.sql
-- Description: Add prekey bundle support and cryptographic signature tracking

-- 1. Add signature column to device_public_keys if not present
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'device_public_keys' AND column_name = 'signature'
    ) THEN
        ALTER TABLE device_public_keys ADD COLUMN signature BYTEA;
    END IF;
END $$;

-- 2. Partial Index for high-concurrency OTK claiming
-- Index strictly active one-time prekeys ordered by creation timestamp for FIFO claiming
CREATE INDEX IF NOT EXISTS idx_device_public_keys_active_otk
ON device_public_keys (device_id, created_at ASC)
WHERE key_type = 'ONE_TIME_PREKEY' AND key_status = 'Active';
```

**Index Strategy Justification:**
- The partial index `idx_device_public_keys_active_otk` indexes *only* rows where `key_type = 'ONE_TIME_PREKEY' AND key_status = 'Active'`.
- As keys are claimed, their status transitions to `'Claimed'`, automatically evicting them from the index tree.
- Consequently, the index size remains tiny (only equal to the number of active, unconsumed OTKs), keeping index scans in memory and execution time below 1 millisecond.

---

### 5.2 Concurrency Semantics: `FOR UPDATE SKIP LOCKED`

Under high concurrency, multiple requests claiming OTKs for the same device must never contend or deadlock:

```
Transaction A (Alice)                      Transaction B (Charlie)
--------------------                       ----------------------
BEGIN;                                     BEGIN;
SELECT ... WHERE device_id = Bob           SELECT ... WHERE device_id = Bob
  AND key_type = 'ONE_TIME_PREKEY'           AND key_type = 'ONE_TIME_PREKEY'
  AND key_status = 'Active'                  AND key_status = 'Active'
ORDER BY created_at ASC                    ORDER BY created_at ASC
LIMIT 1 FOR UPDATE SKIP LOCKED;            LIMIT 1 FOR UPDATE SKIP LOCKED;
--> Locks OTK #1                           --> Skips locked OTK #1, locks OTK #2!

UPDATE ... SET key_status = 'Claimed'      UPDATE ... SET key_status = 'Claimed'
WHERE key_id = OTK #1;                     WHERE key_id = OTK #2;
COMMIT;                                    COMMIT;
(Alice receives OTK #1)                    (Charlie receives OTK #2)
```

Both transactions complete concurrently without blocking, zero deadlocks, and zero duplicate prekey distributions.

---

### 5.3 Strict PostgreSQL Port Isolation (Port 5433 vs. 5432)

SecureCloud strictly enforces environment isolation across test and production boundaries:
- **Port 5432:** Host system default PostgreSQL port. Connecting to port 5432 from any integration or unit test is strictly forbidden.
- **Port 5433:** Dedicated containerized PostgreSQL 17 test environment (`securecloud-postgres-dev`).
- **Enforcement Mechanism:**
  - `PostgresConnectionPool` verifies `config.db_port != 5432`. If port 5432 is configured, it immediately throws `db::PortForbiddenException`.
  - Every integration test suite starts with a dedicated preflight test (`AuthCryptoIdentityPreflightTest.StrictPort5432Protection`) asserting that port 5432 throws `PortForbiddenException`.

---

## 6. API Gateway Perimeter Integration & Route Matching

### 6.1 Parameterized Route Regex Compilation

The API Gateway routes inbound REST requests from external clients to downstream gRPC services. Card AUTH-008 introduced parameterized routes requiring wildcard path variables:
- `GET /api/v1/users/:user_id/devices/crypto-directory`
- `GET /api/v1/devices/:device_id/crypto-identity`
- `POST /api/v1/devices/:device_id/prekeys`

To support these efficiently without breaking existing exact and prefix matching:
1. `GatewaySecurityPolicy` compiles parameterized routes into regex expressions at startup:
   - Tokens `:param` or `{param}` are converted to `([^/]+)`.
   - Pattern `/api/v1/devices/:device_id/crypto-identity` becomes `^/api/v1/devices/([^/]+)/crypto-identity$`.
2. Matches are executed using `std::regex_match` during request evaluation.

---

### 6.2 Fail-Closed Security Evaluation Precedence

The security policy enforces a deterministic 4-tier evaluation hierarchy:

$$\text{Exact Match} \longrightarrow \text{Parameterized Match} \longrightarrow \text{Longest Prefix Match} \longrightarrow \text{Fail-Closed Protected}$$

```
                +---------------------------------------+
                | Inbound HTTP Request (Method, Path)   |
                +---------------------------------------+
                                    |
                                    v
                    [ 1. Exact Route Match? ]
                           /        \
                     YES  /          \  NO
                         v            v
                   Apply Rule   [ 2. Parameterized Regex Match? ]
                                       /        \
                                 YES  /          \  NO
                                     v            v
                               Apply Rule   [ 3. Prefix Match? ]
                                                   /        \
                                             YES  /          \  NO
                                                 v            v
                                           Apply Rule   [ 4. Default Fail-Closed ]
                                                        (RouteAccess::Protected)
```

If an unregistered route is accessed, the gateway fails closed by treating it as `RouteAccess::Protected` requiring primary authentication, preventing unauthorized data leakage.

---

### 6.3 Perimeter Cross-Device Validation (`403 DEVICE_MISMATCH`)

A critical perimeter invariant enforced in `AuthProxyHandler::handle_update_crypto_prekeys`:
- When an authenticated client calls `POST /api/v1/devices/:device_id/prekeys`, the gateway extracts the authenticated `device_id` from the validated session/JWT claims in `AuthenticatedContext`.
- If `ctx.device_id() != path_device_id`, the request is rejected immediately at the gateway perimeter with HTTP `403 Forbidden` and error code `DEVICE_MISMATCH`.
- This prevents a compromised Device A from exhausting or corrupting prekeys for Device B before the request ever touches downstream gRPC networks.

---

### 6.4 RFC 7807 Problem Details Payloads & Error Invariants

The API Gateway strictly transforms downstream failures into deterministic RFC 7807 JSON Problem Details structures:

#### 1. Unauthenticated Perimeter Request (401)
```json
{
  "type": "https://api.securecloud.com/errors/unauthenticated",
  "title": "Unauthorized",
  "status": 401,
  "detail": "Missing, expired, or invalid authorization token",
  "instance": "/api/v1/devices/0192a5b6-7c8d-7e9f-8081-828384858687/crypto-identity",
  "error": {
    "code": "UNAUTHENTICATED",
    "timestamp_epoch_ms": 1728424567890
  }
}
```

#### 2. Cross-Device Perimeter Mismatch (403)
```json
{
  "type": "https://api.securecloud.com/errors/forbidden",
  "title": "Forbidden",
  "status": 403,
  "detail": "Authenticated device does not match the target device path parameter",
  "instance": "/api/v1/devices/0192a5b6-7c8d-7e9f-8081-828384858687/prekeys",
  "error": {
    "code": "DEVICE_MISMATCH",
    "timestamp_epoch_ms": 1728424567890
  }
}
```

#### 3. Malformed Request JSON Body (400)
```json
{
  "type": "https://api.securecloud.com/errors/bad-request",
  "title": "Bad Request",
  "status": 400,
  "detail": "Malformed JSON payload: unexpected token",
  "instance": "/api/v1/devices/0192a5b6-7c8d-7e9f-8081-828384858687/prekeys",
  "error": {
    "code": "MALFORMED_JSON",
    "timestamp_epoch_ms": 1728424567890
  }
}
```

---

### 6.5 Resilience Integration: Bulkhead Isolation, Circuit Breakers & Deadlines

Every crypto directory route in `AuthProxyHandler` participates in gateway resilience guarantees:
1. **Bulkhead Concurrency Permits:** Requests acquire a semaphore permit from the `auth` bulkhead pool prior to invoking downstream gRPC stubs. If saturated, requests reject immediately with `503 SERVICE_UNAVAILABLE` and `Retry-After: 1` header.
2. **Circuit Breaker Tracking:** Downstream gRPC errors (`UNAVAILABLE`, `DEADLINE_EXCEEDED`) increment the circuit breaker failure counter. Upon tripping, the circuit opens, failing requests fast at the perimeter without wasting network cycles.
3. **Dynamic Deadline Budgets:** Gateway requests compute elapsed wall-clock time and pass downstream gRPC deadlines bounded by remaining client timeout budgets.

---

## 7. Traceability Matrix against Acceptance Criteria

The following matrix maps every Acceptance Criterion defined in Card **AUTH-008** to its implementing tickets, code files, and automated verification targets:

| Acceptance Criterion | Implementing Ticket(s) | Primary Code Files | Automated Verification Target | Status |
| :--- | :--- | :--- | :--- | :--- |
| **AC-1: Backend stores only public cryptographic material** | AUTH-008-T01, AUTH-008-T02 | [`entities.hpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/auth/domain/entities.hpp), [`device_public_key_repository.cpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/auth/repository/device_public_key_repository.cpp), [`V4__create_device_prekey_bundles.sql`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/auth/db/migrations/V4__create_device_prekey_bundles.sql) | `DevicePublicKeyRepositoryTest.*`, `AuthPersistenceIntegrationTest.DevicePublicKeyRepositoryFidelityAndReplacement` | **VERIFIED** |
| **AC-2: Device private keys never enter Auth** | AUTH-008-T01, AUTH-008-T03, AUTH-008-T05 | [`auth.proto`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/proto/securecloud/auth/v1/auth.proto), [`auth_service_impl.cpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/auth/service/auth_service_impl.cpp) | Protobuf Wire Inspection, `FullMultiDeviceDirectoryDiscoveryE2E` | **VERIFIED** |
| **AC-3: Clients can retrieve approved public device identity information** | AUTH-008-T02, AUTH-008-T03, AUTH-008-T04, AUTH-008-T05 | [`crypto_directory_manager.cpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/auth/service/crypto_directory_manager.cpp), [`auth_proxy_handler.cpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/gateway/http/proxy/auth_proxy_handler.cpp) | `CryptoDirectoryManagerTest.GetDeviceCryptoDirectory_MultiDeviceBundleAssembly`, `FullMultiDeviceDirectoryDiscoveryE2E` | **VERIFIED** |
| **AC-4: Revoked devices are represented correctly** | AUTH-008-T02, AUTH-008-T03, AUTH-008-T05 | [`crypto_directory_manager.cpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/auth/service/crypto_directory_manager.cpp), [`auth_service_impl.cpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/auth/service/auth_service_impl.cpp) | `CryptoDirectoryManagerTest.RevokedDeviceExcludedFromDirectory`, `AuthCryptoIdentityIntegrationTest.RevokedDeviceHandling` | **VERIFIED** |
| **AC-5: Key changes are detectable by clients** | AUTH-008-T01, AUTH-008-T02, AUTH-008-T05 | [`key_fingerprint.cpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/auth/crypto/key_fingerprint.cpp), [`crypto_directory_manager.cpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/auth/service/crypto_directory_manager.cpp) | `KeyFingerprintTest.Sha256FingerprintFormatting`, `AuthCryptoIdentityIntegrationTest.KeyChangeDetectability` | **VERIFIED** |
| **AC-6: Authorization protects key-management operations** | AUTH-008-T02, AUTH-008-T03, AUTH-008-T04, AUTH-008-T05 | [`auth_proxy_handler.cpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/gateway/http/proxy/auth_proxy_handler.cpp), [`gateway_security_policy.cpp`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/gateway/http/auth/gateway_security_policy.cpp) | `GatewayCryptoDirectoryPolicyTest.*`, `AuthCryptoIdentityIntegrationTest.UnauthorizedKeyManagementRejection` | **VERIFIED** |

---

## 8. Comprehensive Verification & Test Execution Evidence

### 8.1 Live PostgreSQL 17 E2E Integration Test Suite Execution

The live integration test suite connects directly to PostgreSQL 17 container on port 5433:

```text
$ ./build/dev-debug/tests/integration/securecloud_auth_crypto_identity_integration_test
Running main() from googletest-1.18.0/googletest/src/gtest_main.cc
[==========] Running 9 tests from 2 test suites.
[----------] Global test environment set-up.
[----------] 1 test from AuthCryptoIdentityPreflightTest
[ RUN      ] AuthCryptoIdentityPreflightTest.StrictPort5432Protection
[       OK ] AuthCryptoIdentityPreflightTest.StrictPort5432Protection (0 ms)
[----------] 1 test from AuthCryptoIdentityPreflightTest (0 ms total)

[----------] 8 tests from AuthCryptoIdentityIntegrationTest
[ RUN      ] AuthCryptoIdentityIntegrationTest.FullMultiDeviceDirectoryDiscoveryE2E
[SecureCloud] [auth] RPC=GetDeviceCryptoDirectory | PeerSAN=anonymous | Status=0 | Duration=23170us
[       OK ] AuthCryptoIdentityIntegrationTest.FullMultiDeviceDirectoryDiscoveryE2E (448 ms)
[ RUN      ] AuthCryptoIdentityIntegrationTest.SingleUseOtkClaimingAndDepletionFallback
[SecureCloud] [auth] RPC=GetDeviceCryptoDirectory | PeerSAN=anonymous | Status=0 | Duration=9984us
[SecureCloud] [auth] RPC=GetDeviceCryptoDirectory | PeerSAN=anonymous | Status=0 | Duration=6907us
[SecureCloud] [auth] RPC=GetDeviceCryptoDirectory | PeerSAN=anonymous | Status=0 | Duration=5658us
[       OK ] AuthCryptoIdentityIntegrationTest.SingleUseOtkClaimingAndDepletionFallback (378 ms)
[ RUN      ] AuthCryptoIdentityIntegrationTest.RevokedDeviceHandling
[SecureCloud] [auth] RPC=GetDeviceCryptoDirectory | PeerSAN=anonymous | Status=0 | Duration=6825us
[SecureCloud] [auth] RPC=GetCryptoIdentity | PeerSAN=anonymous | Status=0 | Duration=3029us
[       OK ] AuthCryptoIdentityIntegrationTest.RevokedDeviceHandling (370 ms)
[ RUN      ] AuthCryptoIdentityIntegrationTest.SignedPrekeyRotationWithSignatureVerification
[SecureCloud] [auth] RPC=UpdateCryptoPrekeys | PeerSAN=anonymous | Status=0 | Duration=9639us
[SecureCloud] [auth] RPC=GetCryptoIdentity | PeerSAN=anonymous | Status=0 | Duration=5240us
[SecureCloud] [auth] RPC=UpdateCryptoPrekeys | PeerSAN=anonymous | Status=3 | Duration=2370us
[       OK ] AuthCryptoIdentityIntegrationTest.SignedPrekeyRotationWithSignatureVerification (366 ms)
[ RUN      ] AuthCryptoIdentityIntegrationTest.OneTimePrekeyReplenishment
[SecureCloud] [auth] RPC=GetDeviceCryptoDirectory | PeerSAN=anonymous | Status=0 | Duration=10898us
[SecureCloud] [auth] RPC=UpdateCryptoPrekeys | PeerSAN=anonymous | Status=0 | Duration=10885us
[SecureCloud] [auth] RPC=GetDeviceCryptoDirectory | PeerSAN=anonymous | Status=0 | Duration=7230us
[       OK ] AuthCryptoIdentityIntegrationTest.OneTimePrekeyReplenishment (404 ms)
[ RUN      ] AuthCryptoIdentityIntegrationTest.UnauthorizedKeyManagementRejection
[SecureCloud] [auth] RPC=UpdateCryptoPrekeys | PeerSAN=anonymous | Status=7 | Duration=1366us
[SecureCloud] [auth] RPC=UpdateCryptoPrekeys | PeerSAN=anonymous | Status=16 | Duration=1us
[       OK ] AuthCryptoIdentityIntegrationTest.UnauthorizedKeyManagementRejection (554 ms)
[ RUN      ] AuthCryptoIdentityIntegrationTest.KeyChangeDetectability
[SecureCloud] [auth] RPC=GetCryptoIdentity | PeerSAN=anonymous | Status=0 | Duration=7172us
[SecureCloud] [auth] RPC=UpdateCryptoPrekeys | PeerSAN=anonymous | Status=0 | Duration=14391us
[SecureCloud] [auth] RPC=GetCryptoIdentity | PeerSAN=anonymous | Status=0 | Duration=5909us
[       OK ] AuthCryptoIdentityIntegrationTest.KeyChangeDetectability (430 ms)
[ RUN      ] AuthCryptoIdentityIntegrationTest.DurabilityAcrossServiceRestart
[SecureCloud] [auth] RPC=GetDeviceCryptoDirectory | PeerSAN=anonymous | Status=0 | Duration=9547us
[SecureCloud] [auth] RPC=GetDeviceCryptoDirectory | PeerSAN=anonymous | Status=0 | Duration=17580us
[       OK ] AuthCryptoIdentityIntegrationTest.DurabilityAcrossServiceRestart (437 ms)
[----------] 8 tests from AuthCryptoIdentityIntegrationTest (3391 ms total)

[----------] Global test environment tear-down
[==========] 9 tests from 2 test suites ran. (3391 ms total)
[  PASSED  ] 9 tests.
```

---

### 8.2 Detailed Scenario Breakdown of Integration Tests

1. `StrictPort5432Protection`:
   - Configures `db_port = 5432`.
   - Asserts that instantiating `PostgresConnectionPool` immediately throws `db::PortForbiddenException`, preventing accidental connection to host databases.
2. `FullMultiDeviceDirectoryDiscoveryE2E`:
   - Seeds a user with 3 active devices.
   - Generates distinct Ed25519 identity keys, X25519 signed prekeys, signatures, and 5 OTKs per device.
   - Calls `GetDeviceCryptoDirectory`.
   - Verifies all 3 devices returned with matching public keys, fingerprints, and 1 claimed OTK each (remaining = 4).
3. `SingleUseOtkClaimingAndDepletionFallback`:
   - Device provisioned with exactly 2 OTKs.
   - Lookup 1 claims OTK 1; remaining count becomes 1.
   - Lookup 2 claims OTK 2; remaining count becomes 0; OTK 2 differs from OTK 1.
   - Lookup 3 encounters empty pool; falls back gracefully to signed prekey only; reports count 0.
4. `RevokedDeviceHandling`:
   - User has Device 1 (active) and Device 2 (active).
   - Device 2 is revoked via `device_repo_->revoke_device` and `public_key_repo_->revoke_all_device_keys`.
   - Directory discovery returns only Device 1.
   - Direct identity lookup on Device 2 returns `DEVICE_STATUS_REVOKED` and omits active prekeys.
5. `SignedPrekeyRotationWithSignatureVerification`:
   - Generates new X25519 prekey, signs with device's private Ed25519 key.
   - Calls `UpdateCryptoPrekeys`. Verifies success and updated timestamp.
   - Verifies `GetCryptoIdentity` reflects the new signed prekey.
   - Corrupts the signature byte and submits again: verifies rejected with `INVALID_ARGUMENT`.
6. `OneTimePrekeyReplenishment`:
   - Device pool depleted to 0 OTKs.
   - Calls `UpdateCryptoPrekeys` with 10 new OTKs.
   - Verifies active OTK count increases to 10.
   - Subsequent directory query dispenses a new OTK; remaining count decreases to 9.
7. `UnauthorizedKeyManagementRejection`:
   - User A (Device A) attempts to update prekeys for Device B (belonging to User B).
   - Rejected with `PERMISSION_DENIED`.
   - Unauthenticated call with no identity metadata rejected with `UNAUTHENTICATED`.
8. `KeyChangeDetectability`:
   - Client queries identity key fingerprint (`SHA256:xx:xx:...`).
   - Device rotates signed prekey.
   - Client detects update via `signed_prekey_created_at_epoch_ms` strictly greater than previous timestamp, while identity fingerprint remains constant.
9. `DurabilityAcrossServiceRestart`:
   - Claims 1 OTK (remaining count = 2).
   - Completely terminates and destroys `auth_service`, `crypto_directory_mgr`, repositories, and connection pool.
   - Reconstructs all components against PostgreSQL 17.
   - Queries directory again: verifies persisted identity key, fingerprint, and remaining count = 1 (after second claim).

---

### 8.3 API Gateway Route & Policy Unit Test Execution

```text
$ ctest --test-dir build/dev-debug -R "GatewayCryptoDirectoryPolicy|AuthProxyHandler"
Test project /Users/sergeychukhno/Desktop/C:C++/SecureCloud/build/dev-debug
    Start  616: AuthProxyHandlerTest.GetDeviceCryptoDirectorySuccess
 1/15 Test  #616: AuthProxyHandlerTest.GetDeviceCryptoDirectorySuccess ...............................................   Passed    0.08 sec
    Start  617: AuthProxyHandlerTest.GetDeviceCryptoDirectoryWithFilterParams
 2/15 Test  #617: AuthProxyHandlerTest.GetDeviceCryptoDirectoryWithFilterParams ......................................   Passed    0.08 sec
    Start  618: AuthProxyHandlerTest.GetCryptoIdentitySuccess
 3/15 Test  #618: AuthProxyHandlerTest.GetCryptoIdentitySuccess ......................................................   Passed    0.08 sec
    Start  619: AuthProxyHandlerTest.GetCryptoIdentityNotFoundReturns404
 4/15 Test  #619: AuthProxyHandlerTest.GetCryptoIdentityNotFoundReturns404 ...........................................   Passed    0.08 sec
    Start  620: AuthProxyHandlerTest.UpdateCryptoPrekeysSuccess
 5/15 Test  #620: AuthProxyHandlerTest.UpdateCryptoPrekeysSuccess ....................................................   Passed    0.08 sec
    Start  621: AuthProxyHandlerTest.UpdateCryptoPrekeysMismatchedDeviceReturns403
 6/15 Test  #621: AuthProxyHandlerTest.UpdateCryptoPrekeysMismatchedDeviceReturns403 .................................   Passed    0.08 sec
    Start  622: AuthProxyHandlerTest.UpdateCryptoPrekeysMalformedJsonReturns400
 7/15 Test  #622: AuthProxyHandlerTest.UpdateCryptoPrekeysMalformedJsonReturns400 ....................................   Passed    0.08 sec
    Start  713: GatewayCryptoDirectoryPolicyTest.PolicyEvaluatesCryptoRoutesAsProtectedPrimary
 8/15 Test  #713: GatewayCryptoDirectoryPolicyTest.PolicyEvaluatesCryptoRoutesAsProtectedPrimary .....................   Passed    0.09 sec
    Start  714: GatewayCryptoDirectoryPolicyTest.UnauthenticatedGetCryptoDirectoryReturns401
 9/15 Test  #714: GatewayCryptoDirectoryPolicyTest.UnauthenticatedGetCryptoDirectoryReturns401 .......................   Passed    0.09 sec
    Start  715: GatewayCryptoDirectoryPolicyTest.UnauthenticatedGetCryptoIdentityReturns401
10/15 Test  #715: GatewayCryptoDirectoryPolicyTest.UnauthenticatedGetCryptoIdentityReturns401 ........................   Passed    0.08 sec
    Start  716: GatewayCryptoDirectoryPolicyTest.UnauthenticatedPostPrekeysReturns401
11/15 Test  #716: GatewayCryptoDirectoryPolicyTest.UnauthenticatedPostPrekeysReturns401 ..............................   Passed    0.08 sec
    Start  717: GatewayCryptoDirectoryPolicyTest.AuthenticatedGetCryptoDirectorySuccessAndMetadataInjected
12/15 Test  #717: GatewayCryptoDirectoryPolicyTest.AuthenticatedGetCryptoDirectorySuccessAndMetadataInjected .........   Passed    0.08 sec
    Start  718: GatewayCryptoDirectoryPolicyTest.AuthenticatedGetCryptoIdentitySuccess
13/15 Test  #718: GatewayCryptoDirectoryPolicyTest.AuthenticatedGetCryptoIdentitySuccess .............................   Passed    0.08 sec
    Start  719: GatewayCryptoDirectoryPolicyTest.PrekeyUpdatePerimeterRejectsDeviceMismatchWith403
14/15 Test  #719: GatewayCryptoDirectoryPolicyTest.PrekeyUpdatePerimeterRejectsDeviceMismatchWith403 .................   Passed    0.08 sec
    Start  720: GatewayCryptoDirectoryPolicyTest.PrekeyUpdateMatchingDeviceDispatchesDownstreamSuccess
15/15 Test  #720: GatewayCryptoDirectoryPolicyTest.PrekeyUpdateMatchingDeviceDispatchesDownstreamSuccess .............   Passed    0.08 sec

100% tests passed, 0 tests failed out of 15
```

---

### 8.4 AuthService gRPC & Directory Manager Unit Test Execution

```text
$ ctest --test-dir build/dev-debug -R "AuthServiceCryptoTest|CryptoDirectoryManagerTest"
Test project /Users/sergeychukhno/Desktop/C:C++/SecureCloud/build/dev-debug
    Start  245: AuthServiceCryptoTest.GetDeviceCryptoDirectory_Success
 1/14 Test  #245: AuthServiceCryptoTest.GetDeviceCryptoDirectory_Success ............................................   Passed    0.08 sec
    Start  246: AuthServiceCryptoTest.GetDeviceCryptoDirectory_EmptyDirectory_ReturnsEmptyList
 2/14 Test  #246: AuthServiceCryptoTest.GetDeviceCryptoDirectory_EmptyDirectory_ReturnsEmptyList ....................   Passed    0.08 sec
    Start  247: AuthServiceCryptoTest.GetCryptoIdentity_Success
 3/14 Test  #247: AuthServiceCryptoTest.GetCryptoIdentity_Success ...................................................   Passed    0.08 sec
    Start  248: AuthServiceCryptoTest.GetCryptoIdentity_RevokedDevice_ReturnsRevokedStatus
 4/14 Test  #248: AuthServiceCryptoTest.GetCryptoIdentity_RevokedDevice_ReturnsRevokedStatus ........................   Passed    0.08 sec
    Start  249: AuthServiceCryptoTest.UpdateCryptoPrekeys_Success
 5/14 Test  #249: AuthServiceCryptoTest.UpdateCryptoPrekeys_Success .................................................   Passed    0.08 sec
    Start  250: AuthServiceCryptoTest.UpdateCryptoPrekeys_CrossDeviceMismatch_ReturnsPermissionDenied
 6/14 Test  #250: AuthServiceCryptoTest.UpdateCryptoPrekeys_CrossDeviceMismatch_ReturnsPermissionDenied ..............   Passed    0.08 sec
    Start  260: CryptoDirectoryManagerTest.GetDeviceCryptoDirectory_MultiDeviceBundleAssembly
 7/14 Test  #260: CryptoDirectoryManagerTest.GetDeviceCryptoDirectory_MultiDeviceBundleAssembly ....................   Passed    0.09 sec
    Start  261: CryptoDirectoryManagerTest.GetDeviceCryptoDirectory_ClaimsOneTimePrekeysAtomically
 8/14 Test  #261: CryptoDirectoryManagerTest.GetDeviceCryptoDirectory_ClaimsOneTimePrekeysAtomically ................   Passed    0.08 sec
    Start  262: CryptoDirectoryManagerTest.GetDeviceCryptoDirectory_DepletedOtkPool_GracefulFallback
 9/14 Test  #262: CryptoDirectoryManagerTest.GetDeviceCryptoDirectory_DepletedOtkPool_GracefulFallback .............   Passed    0.08 sec
    Start  263: CryptoDirectoryManagerTest.RevokedDeviceExcludedFromDirectory
10/14 Test  #263: CryptoDirectoryManagerTest.RevokedDeviceExcludedFromDirectory .....................................   Passed    0.08 sec
    Start  264: CryptoDirectoryManagerTest.UpdateCryptoPrekeys_RotatesSignedPrekeyWithValidSignature
11/14 Test  #264: CryptoDirectoryManagerTest.UpdateCryptoPrekeys_RotatesSignedPrekeyWithValidSignature ..............   Passed    0.08 sec
    Start  265: CryptoDirectoryManagerTest.UpdateCryptoPrekeys_RejectsInvalidSignature
12/14 Test  #265: CryptoDirectoryManagerTest.UpdateCryptoPrekeys_RejectsInvalidSignature ...........................   Passed    0.08 sec
    Start  266: CryptoDirectoryManagerTest.UpdateCryptoPrekeys_ReplenishesOtkPool
13/14 Test  #266: CryptoDirectoryManagerTest.UpdateCryptoPrekeys_ReplenishesOtkPool .................................   Passed    0.08 sec
    Start  267: CryptoDirectoryManagerTest.UpdateCryptoPrekeys_UnauthorizedCaller_RejectsPermissionDenied
14/14 Test  #267: CryptoDirectoryManagerTest.UpdateCryptoPrekeys_UnauthorizedCaller_RejectsPermissionDenied ..........   Passed    0.08 sec

100% tests passed, 0 tests failed out of 14
```

---

### 8.5 Cryptographic Primitives & Fingerprint Test Execution

```text
$ ctest --test-dir build/dev-debug -R "KeyFingerprintTest|PrekeySignatureVerifierTest|DevicePublicKeyRepositoryTest"
Test project /Users/sergeychukhno/Desktop/C:C++/SecureCloud/build/dev-debug
    Start  280: KeyFingerprintTest.Sha256FingerprintFormatting
 1/9 Test  #280: KeyFingerprintTest.Sha256FingerprintFormatting ....................................................   Passed    0.08 sec
    Start  281: KeyFingerprintTest.DeterministicDigests
 2/9 Test  #281: KeyFingerprintTest.DeterministicDigests ............................................................   Passed    0.07 sec
    Start  282: KeyFingerprintTest.RawDigestMatchesExpectedSize
 3/9 Test  #282: KeyFingerprintTest.RawDigestMatchesExpectedSize ....................................................   Passed    0.08 sec
    Start  285: PrekeySignatureVerifierTest.ValidEd25519SignatureAccepted
 4/9 Test  #285: PrekeySignatureVerifierTest.ValidEd25519SignatureAccepted .........................................   Passed    0.08 sec
    Start  286: PrekeySignatureVerifierTest.CorruptedSignatureRejected
 5/9 Test  #286: PrekeySignatureVerifierTest.CorruptedSignatureRejected .............................................   Passed    0.08 sec
    Start  287: PrekeySignatureVerifierTest.MismatchedIdentityKeyRejected
 6/9 Test  #287: PrekeySignatureVerifierTest.MismatchedIdentityKeyRejected ..........................................   Passed    0.08 sec
    Start  290: DevicePublicKeyRepositoryTest.ClaimOneTimePrekeyLifecycleAndDepletion
 7/9 Test  #290: DevicePublicKeyRepositoryTest.ClaimOneTimePrekeyLifecycleAndDepletion .............................   Passed    0.08 sec
    Start  291: DevicePublicKeyRepositoryTest.SignedPrekeyRotationMarksOldKeyReplaced
 8/9 Test  #291: DevicePublicKeyRepositoryTest.SignedPrekeyRotationMarksOldKeyReplaced .............................   Passed    0.08 sec
    Start  292: DevicePublicKeyRepositoryTest.RevokeAllDeviceKeysTransitionsActiveToRevoked
 9/9 Test  #292: DevicePublicKeyRepositoryTest.RevokeAllDeviceKeysTransitionsActiveToRevoked .......................   Passed    0.08 sec

100% tests passed, 0 tests failed out of 9
```

---

### 8.6 Full Repository Test Suite (1,082 Tests Passed)

```text
$ ctest --test-dir build/dev-debug --output-on-failure
Test project /Users/sergeychukhno/Desktop/C:C++/SecureCloud/build/dev-debug
...
1074/1082 Test #1074: AuthCryptoIdentityPreflightTest.StrictPort5432Protection ...................................   Passed    0.09 sec
1075/1082 Test #1075: AuthCryptoIdentityIntegrationTest.FullMultiDeviceDirectoryDiscoveryE2E .....................   Passed    0.55 sec
1076/1082 Test #1076: AuthCryptoIdentityIntegrationTest.SingleUseOtkClaimingAndDepletionFallback .................   Passed    0.54 sec
1077/1082 Test #1077: AuthCryptoIdentityIntegrationTest.RevokedDeviceHandling ....................................   Passed    0.53 sec
1078/1082 Test #1078: AuthCryptoIdentityIntegrationTest.SignedPrekeyRotationWithSignatureVerification ............   Passed    0.52 sec
1079/1082 Test #1079: AuthCryptoIdentityIntegrationTest.OneTimePrekeyReplenishment ...............................   Passed    0.54 sec
1080/1082 Test #1080: AuthCryptoIdentityIntegrationTest.UnauthorizedKeyManagementRejection .......................   Passed    0.70 sec
1081/1082 Test #1081: AuthCryptoIdentityIntegrationTest.KeyChangeDetectability ...................................   Passed    0.60 sec
1082/1082 Test #1082: AuthCryptoIdentityIntegrationTest.DurabilityAcrossServiceRestart ...........................   Passed    0.55 sec

100% tests passed, 0 tests failed out of 1082

Total Test time (real) = 123.93 sec
```

---

### 8.7 Code Quality & Clang-Format Verification

```text
$ ninja -C build/dev-debug format && ninja -C build/dev-debug check-format
[0/2] Re-checking globbed directories...
[1/2] Applying clang-format to project C++ files in-place...
ninja: Entering directory `build/dev-debug'
[0/2] Re-checking globbed directories...
[1/2] Checking project C++ formatting (read-only)...
(Exited with status code 0 - No formatting violations detected)
```

---

## 9. Conclusion & Next Phase Transition

Card **AUTH-008: Implement Public Cryptographic Identity & Directory** has been fully implemented, validated, and hardened to production standards:
1. **Mathematical Soundness:** Fully aligned with the Signal X3DH cryptographic specifications using RFC 8032 Ed25519 signatures and RFC 7748 X25519 key agreements.
2. **Untrusted Server Paradigm:** Enforces the Zero Private Key Invariant. The server operates solely as an untrusted public phonebook and atomic key dispenser.
3. **High Concurrency & Durability:** Pessimistic row locking (`FOR UPDATE SKIP LOCKED`) combined with PostgreSQL 17 transaction isolation guarantees race-free, single-use OTK dispensing.
4. **Perimeter Defense:** Parameterized regex routing with fail-closed priority ensures perimeter verification of authentication levels, token validity, and device ownership.
5. **Zero Regressions:** 1,082 out of 1,082 unit, resilience, and live PostgreSQL 17 integration tests pass with 100% success.

Card **AUTH-008 is hereby declared COMPLETE and VALIDATED.**
