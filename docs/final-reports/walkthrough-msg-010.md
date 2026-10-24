# Card Validation & Architecture Walkthrough: MSG-010 — Presence & Real-Time Messaging Optimization

**Card ID:** `MSG-010`  
**Card Title:** Presence & Real-Time Messaging Optimization  
**Milestone:** M3 — Secure Messaging Platform  
**Repository:** `SecureCloud`  
**Branch:** `feature/msg-010-presence-and-realtime-optimization`  
**Status:** IN PROGRESS (MSG-010-T01 Under Active Implementation)  
**Author:** Principal Distributed Systems Architect, Security Gatekeeper & Systems Lead  
**Date:** October 23, 2026  

---

## 1. Executive Summary & Foundational Architecture

Card **MSG-010** establishes the real-time connection lifecycle and ephemeral presence subsystem for SecureCloud Messaging (`securecloud-messaging`), adhering strictly to **ADR-001** (Microservices Architecture), **ADR-004** (gRPC Inter-Process Communication), **ADR-007** (Message Reliability & Durability), **ADR-008** (Security & Cryptographic Architecture), **ADR-009** (Distributed Failure & Resilience), and **ADR-010** (Performance, Capacity & Optimization Strategy).

While **MSG-007** established online delivery and worker dispatching, **MSG-008** established multi-device delivery state tracking and read receipts, and **MSG-009** established sequence-based synchronization, **MSG-010 optimizes real-time responsiveness by exploiting active client connections while strictly preserving the decoupling between transient network connections and durable message state.**

---

## 2. Core Architectural Questions & Authoritative Resolutions

### 2.1 Decoupling Analysis: `DeviceConnection` vs. Auth Service `SessionEntity`

A critical architectural distinction exists between **Auth Sessions** and **Messaging Transport Connections**. They must not be conflated:

```text
┌───────────────────────────────────────────────┐       ┌───────────────────────────────────────────────┐
│           Auth Service `SessionEntity`        │       │         Messaging `DeviceConnection`          │
├───────────────────────────────────────────────┤       ├───────────────────────────────────────────────┤
│ • Represents User Authentication State        │       │ • Represents Ephemeral Transport Channel      │
│ • Stored durably in PostgreSQL                │       │ • Stored ephemerally in-memory only           │
│ • Valid for days/weeks (e.g., 30-day lease)   │       │ • Valid for seconds/minutes (active TCP pipe) │
│ • Tracks JWTs, refresh tokens, MFA step-up    │       │ • Tracks socket liveliness, pings, heartbeats │
│ • Identified by `session_id` (Auth UUID)      │       │ • Identified by `connection_id` (UUIDv7)      │
└───────────────────────────────────────────────┘       └───────────────────────────────────────────────┘
```

#### The "Elevator / Tunnel" Scenario
Consider a humanitarian responder carrying a mobile field device:
1. **Network Disruption**: When the responder steps into an elevator, tunnel, or degraded cellular dead-zone, the underlying TCP / HTTP/2 transport connection drops immediately.
2. **Messaging Layer Action**: The Messaging service detects transport termination (or idle lease timeout), transitions the connection to `TERMINATED`, and unregisters it from [`DeviceConnectionRegistry`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/messaging/delivery/device_connection_registry.hpp). The device is marked `OFFLINE`.
3. **Auth Layer Invariant**: The user's **Auth Session is NOT terminated**. Their login status, cryptographic device binding, and refresh token verifiers in PostgreSQL remain active and valid.
4. **Reconnection & Re-establishment**: When the device emerges into Wi-Fi coverage, it issues an authenticated request to the Gateway presenting its existing valid Bearer token. The Gateway authenticates the token via [`AuthenticatedContext`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/src/gateway/http/auth/authenticated_context.hpp#L21) (`user_id`, `device_id`, `session_id`), and Messaging registers a **brand-new transport connection**.
5. **Architectural Naming**: To make this distinction mathematically unambiguous and prevent semantic pollution across service boundaries, the Messaging entity is named **`DeviceConnection`** (governed by `ConnectionState`), holding `auth_session_id` strictly as an immutable audit trace.

---

### 2.2 User Presence Semantics & Custom Statuses

#### Approved Contract
In strict accordance with [`proto/securecloud/messaging/v1/messaging.proto`](file:///Users/sergeychukhno/Desktop/C:C++/SecureCloud/proto/securecloud/messaging/v1/messaging.proto#L76-L82):
```protobuf
message UserPresence {
  string user_id = 1;                  // Canonical UUIDv4/v7
  PresenceStatus status = 2;           // ONLINE, AWAY, BUSY, OFFLINE
  int64 last_active_unix_ms = 3;       // Milliseconds since Unix epoch
  string custom_status_message = 4;    // e.g., "Deploying field clinic", "Urgent only"
}
```

#### Operational & Domain Rules:
1. **Humanitarian Utility**: Field responders and coordinators require expressive availability signaling (e.g., *"In transit — satellite degraded"*, *"Operating room triage"*).
2. **Input Sanitization & Length Guard**: Custom status strings must be valid UTF-8 and are strictly capped at **$\le 140$ characters**. Excess characters are rejected or safely truncated to prevent memory bloat and application-layer denial-of-service.
3. **Explicit Override**: An explicit user status (e.g., `BUSY` or `AWAY` with custom message) takes precedence over the default `ONLINE` state while connected. When all devices disconnect, the user automatically decays to `OFFLINE`.

---

### 2.3 Derivation & Mechanics of `last_active_at`

The `last_active_at` timestamp is an ephemeral operational indicator computed with **zero ScyllaDB read/write amplification**:

#### 1. Monotonic Liveliness "Touch"
A device's timestamp in `DeviceConnectionRegistry` is monotonically refreshed (`touch_channel()`) upon:
- **Keepalive Heartbeats**: Regular periodic transport pings received from the client.
- **Active Messaging Operations**: The device submits a message (`SendMessage`), acknowledges ciphertext receipt (`AcknowledgeDelivery`), submits a read receipt (`SendReadReceipt`), or synchronizes (`SyncDeviceMessages`).
- **Explicit Presence Updates**: The user updates availability via `UpdatePresence`.

#### 2. Multi-Device User Aggregation
For users with multiple concurrent devices (e.g., phone, rugged tablet, operations console):
$$\text{last\_active\_unix\_ms}_{\text{user}} = \max_{d \in \text{ActiveDevices}(u)} \left( \text{last\_active}(d) \right)$$
- **Online State**: While at least one device is connected, the user reports the most recent activity across their active fleet.
- **Offline State**: When the last device disconnects or expires past the lease timeout ($60\,\text{s}$), the system preserves that final timestamp. Contacts see accurate *"Last seen 15 minutes ago"* information without triggering background database sweeps.

---

## 3. The Non-Conflation Axiom

SecureCloud strictly enforces orthogonal separation across all state planes:

$$\mathbf{Presence} \neq \mathbf{Delivery\ (Per\text{-}Device)} \neq \mathbf{Read\ (Per\text{-}User)} \neq \mathbf{Synchronization\ (Per\text{-}Device)}$$

1. **Presence $\not\Rightarrow$ Delivery**: A client device being connected (`ONLINE`) must **never** mark a message as `DELIVERED`. Delivery requires an affirmative cryptographic acknowledgment (`AcknowledgeDelivery`) from the client.
2. **Disconnection $\not\Rightarrow$ State Loss**: Dropping a connection or timing out an idle lease must **never** regress or erase durable `DELIVERED` or `READ` states in ScyllaDB.
3. **Absence of Presence $\not\Rightarrow$ Blocked Delivery**: If presence is unknown or reports `OFFLINE`, messages remain durably queued in ScyllaDB and are dispatched via durable recovery loops.
4. **Zero Persistent Storage for Presence**: Presence state is purely transient, ephemeral, and stored in-memory. No Kafka, Redis, or ScyllaDB tables are used for presence, preserving maximum database I/O bandwidth for durable message payloads.

---

## 4. Implementation Ticket Tracking

| Ticket ID | Status | Focus Area | Deliverables |
| :--- | :--- | :--- | :--- |
| **MSG-010-T01** | **COMPLETED** | Domain Models & Contracts | `domain/presence_types.hpp`, `domain/connection_session.hpp`, 12 unit tests (100% pass) |
| **MSG-010-T02** | **COMPLETED** | Presence Coordinator Engine | `PresenceCoordinator`, multi-device aggregation, in-memory lease decay, 10 unit tests (100% pass) |
| **MSG-010-T03** | PENDING | Connection Lifecycle & Reaper | `ConnectionLifecycleManager`, capacity guards, background stale reaper |
| **MSG-010-T04** | PENDING | Reconnect Fast-Track Pipeline | Fast-track delivery sweep upon device reconnect, latency reduction |
| **MSG-010-T05** | PENDING | gRPC Service & Privacy Guard | `UpdatePresence`, `GetPresence`, `BatchGetPresence`, mutual-conversation filter |
| **MSG-010-T06** | PENDING | Gateway REST Proxy Routing | `MessagingProxyHandler` routes, OpenAPI documentation |
| **MSG-010-T07** | PENDING | Verification & Telemetry | Integration test suite, Prometheus metrics, chaos reconnect tests |

---

## 5. Detailed Ticket Execution Reports

### 5.1 MSG-010-T01 — Presence & Connection Domain Models, Lifecycle State Machine & Contracts

#### 1. Architectural Scope & Implementation Deliverables
1. **`src/messaging/domain/presence_types.hpp`**:
   - `PresenceStatus` enum class: `Unspecified (0)`, `Online (1)`, `Away (2)`, `Busy (3)`, `Offline (4)`.
   - String serialization & parsing: `to_string()`, `parse_presence_status()`.
   - Protobuf contract mapping: Bidirectional conversions `to_proto()`, `from_proto()` to `securecloud::messaging::v1::PresenceStatus` and `UserPresence`.
   - Custom status sanitization: Whitespace trimming and strict length bounding ($\le 140$ characters via `k_max_custom_status_length`).
   - Value objects: `UserPresence` (with `is_online()` helper) and `UpdatePresenceCommand`.
2. **`src/messaging/domain/connection_session.hpp`**:
   - `ConnectionState` enum class: `Connecting (0)`, `Active (1)`, `Stale (2)`, `Terminated (3)`.
   - Lifecycle state machine transition validator: `is_valid_connection_transition(from, to)`.
     - Valid: `Connecting` $\to$ `Active` / `Terminated`, `Active` $\to$ `Stale` / `Terminated`, `Stale` $\to$ `Active` / `Terminated`.
     - Terminal invariant: `Terminated` cannot transition anywhere; resurrection requires creating a new entity.
   - `DeviceConnection` entity: Ephemeral transport record holding `connection_id` (UUIDv7), `device_id`, `user_id`, `client_ip`, `user_agent`, `protocol_version`, `state`, timestamps, and optional `auth_session_id` audit trace.
3. **`tests/unit/messaging/presence_types_test.cpp`**:
   - Dedicated 12-test suite validating all enum conversions, custom status sanitization, Protobuf roundtrips, state transition boundaries, and value semantics.

#### 2. Unit Test Verification Transcript
```text
[==========] Running 12 tests from 1 test suite.
[----------] Global test environment set-up.
[----------] 12 tests from PresenceTypesTest
[ RUN      ] PresenceTypesTest.PresenceStatusToStringRoundtrip
[       OK ] PresenceTypesTest.PresenceStatusToStringRoundtrip (0 ms)
[ RUN      ] PresenceTypesTest.PresenceStatusProtoConversion
[       OK ] PresenceTypesTest.PresenceStatusProtoConversion (0 ms)
[ RUN      ] PresenceTypesTest.StatusMessageSanitizationTrimsWhitespace
[       OK ] PresenceTypesTest.StatusMessageSanitizationTrimsWhitespace (0 ms)
[ RUN      ] PresenceTypesTest.StatusMessageBoundsEnforcedTo140Chars
[       OK ] PresenceTypesTest.StatusMessageBoundsEnforcedTo140Chars (0 ms)
[ RUN      ] PresenceTypesTest.UserPresenceDefaultAndOnlineChecks
[       OK ] PresenceTypesTest.UserPresenceDefaultAndOnlineChecks (0 ms)
[ RUN      ] PresenceTypesTest.UserPresenceProtoRoundtrip
[       OK ] PresenceTypesTest.UserPresenceProtoRoundtrip (0 ms)
[ RUN      ] PresenceTypesTest.UpdatePresenceCommandValidity
[       OK ] PresenceTypesTest.UpdatePresenceCommandValidity (0 ms)
[ RUN      ] PresenceTypesTest.ConnectionStateToStringAndParse
[       OK ] PresenceTypesTest.ConnectionStateToStringAndParse (0 ms)
[ RUN      ] PresenceTypesTest.LegalConnectionStateTransitions
[       OK ] PresenceTypesTest.LegalConnectionStateTransitions (0 ms)
[ RUN      ] PresenceTypesTest.IllegalConnectionStateTransitions
[       OK ] PresenceTypesTest.IllegalConnectionStateTransitions (0 ms)
[ RUN      ] PresenceTypesTest.DeviceConnectionLifecycleTransitions
[       OK ] PresenceTypesTest.DeviceConnectionLifecycleTransitions (0 ms)
[ RUN      ] PresenceTypesTest.DeviceConnectionEqualityAndCopyMoveSemantics
[       OK ] PresenceTypesTest.DeviceConnectionEqualityAndCopyMoveSemantics (0 ms)
[----------] 12 tests from PresenceTypesTest (0 ms total)

[----------] Global test environment tear-down
[==========] 12 tests from 1 test suite ran. (0 ms total)
[  PASSED  ] 12 tests.
```

### 5.2 MSG-010-T02 — Thread-Safe Multi-Device Presence Coordinator & Leased Ephemeral State Engine

#### 1. Architectural Scope & Implementation Deliverables
1. **`src/messaging/service/presence_coordinator_interface.hpp`**:
   - `IPresenceCoordinator` pure virtual contract:
     - `get_user_presence(user_id)`
     - `batch_get_presence(user_ids)`
     - `set_user_override(user_id, status, custom_message)`
     - `clear_user_override(user_id)`
     - `on_device_connected(user_id, device_id)`
     - `on_device_disconnected(user_id, device_id)`
     - `on_device_heartbeat(user_id, device_id)`
     - `lease_timeout()`
2. **`src/messaging/service/presence_coordinator.hpp` & `.cpp`**:
   - Thread-safe production engine using `std::shared_mutex` for high-concurrency read operations (`std::shared_lock`).
   - Bidirectional multi-device tracking index: `user_devices_` (`UserId -> std::unordered_set<DeviceId>`) and `device_states_` (`DeviceId -> DeviceEntry`).
   - Explicit user override registry (`user_overrides_`) allowing manual statuses (`BUSY`, `AWAY`) to override default computed availability while active.
   - Offline preservation (`user_last_seen_`) maintaining accurate last-active timestamps after full fleet disconnection.
   - Dynamic ephemeral lease evaluation: automatic decay to `OFFLINE` if idle elapsed time exceeds `lease_timeout_` without persistent storage I/O.
   - Inspection telemetry helpers: `tracked_users_count()`, `tracked_devices_count()`, and `online_users_count()`.
3. **`tests/unit/messaging/presence_coordinator_test.cpp`**:
   - Comprehensive 10-test suite validating single device lifecycle, multi-device aggregation, explicit overrides, lease timeout decay, heartbeat refresh, batch queries, and a 12-thread concurrent read/write stress test.

#### 2. Unit Test Verification Transcript
```text
[==========] Running 10 tests from 1 test suite.
[----------] Global test environment set-up.
[----------] 10 tests from PresenceCoordinatorTest
[ RUN      ] PresenceCoordinatorTest.UnobservedUserReturnsUnspecified
[       OK ] PresenceCoordinatorTest.UnobservedUserReturnsUnspecified (0 ms)
[ RUN      ] PresenceCoordinatorTest.SingleDeviceConnectAndDisconnect
[       OK ] PresenceCoordinatorTest.SingleDeviceConnectAndDisconnect (0 ms)
[ RUN      ] PresenceCoordinatorTest.MultiDeviceAggregationIndependentTransitions
[       OK ] PresenceCoordinatorTest.MultiDeviceAggregationIndependentTransitions (0 ms)
[ RUN      ] PresenceCoordinatorTest.UserStatusOverrideWhileConnected
[       OK ] PresenceCoordinatorTest.UserStatusOverrideWhileConnected (0 ms)
[ RUN      ] PresenceCoordinatorTest.StatusOverrideDecaysWhenAllDevicesDisconnect
[       OK ] PresenceCoordinatorTest.StatusOverrideDecaysWhenAllDevicesDisconnect (0 ms)
[ RUN      ] PresenceCoordinatorTest.LeaseTimeoutDecaysInactiveDeviceToOffline
[       OK ] PresenceCoordinatorTest.LeaseTimeoutDecaysInactiveDeviceToOffline (75 ms)
[ RUN      ] PresenceCoordinatorTest.HeartbeatRefreshesLeaseWindow
[       OK ] PresenceCoordinatorTest.HeartbeatRefreshesLeaseWindow (80 ms)
[ RUN      ] PresenceCoordinatorTest.BatchGetPresenceEvaluation
[       OK ] PresenceCoordinatorTest.BatchGetPresenceEvaluation (0 ms)
[ RUN      ] PresenceCoordinatorTest.OperationalInspectionCounts
[       OK ] PresenceCoordinatorTest.OperationalInspectionCounts (0 ms)
[ RUN      ] PresenceCoordinatorTest.ConcurrentReadWriteStressTest
[       OK ] PresenceCoordinatorTest.ConcurrentReadWriteStressTest (150 ms)
[----------] 10 tests from PresenceCoordinatorTest (306 ms total)

[----------] Global test environment tear-down
[==========] 10 tests from 1 test suite ran. (306 ms total)
[  PASSED  ] 10 tests.
```

---

### 5.3 MSG-010-T03 — Connection Lifecycle Manager, Heartbeat Reaper & Resource Capacity Controller

#### 1. Architectural Scope & Implementation Deliverables
1. **`src/messaging/delivery/device_connection_registry.hpp` & `.cpp`**:
   - `ConnectionCapacityConfig`:
     - `max_devices_per_user` (default: 10 devices per user).
     - `max_global_connections` (default: 100,000 global connections).
     - `default_lease_timeout` (default: 60s).
   - `ConnectionLimitExceededException`: typed exception thrown when capacity boundaries are breached.
   - Enforced per-user device tracking via `user_to_devices_` and atomic superseding of existing devices without dropping or corrupting user device counts.
   - `user_device_count(user_id)` inspection method.
2. **`src/messaging/delivery/connection_lifecycle_manager.hpp` & `.cpp`**:
   - High-level coordinator linking physical delivery channels, session metadata, heartbeats, and presence.
   - `establish_connection`: registers channel in registry, creates rich `ConnectionSession`, and notifies `PresenceCoordinator::on_device_connected`.
   - `terminate_connection`: unregisters channel from registry and cascades disconnect notifications.
   - `record_heartbeat`: touches active channel, updates session timestamps, and notifies `PresenceCoordinator::on_device_heartbeat`.
   - Background reaper thread (`reaper_loop`): runs on configurable interval (e.g., $15\,\text{s}$), calls `registry_->evict_stale_channels(lease_timeout_)`, and cleanly cleans up expired sessions without resource leaks.
   - Graceful thread lifecycle management: `start()`, `stop()`, and `sweep_stale_connections()`.
3. **`tests/unit/messaging/connection_lifecycle_manager_test.cpp` & `device_connection_registry_test.cpp`**:
   - 9 new unit tests for `ConnectionLifecycleManager` verifying session population, null channel rejection, termination cascade, atomic superseding, heartbeat refresh, background reaper eviction, and thread safety.
   - 3 new unit tests in `DeviceConnectionRegistryTest` validating per-user limits, global connection capacity, and atomic superseding.

#### 2. Unit Test Verification Transcript
```text
[==========] Running 13 tests from 1 test suite.
[----------] Global test environment set-up.
[----------] 13 tests from DeviceConnectionRegistryTest
[ RUN      ] DeviceConnectionRegistryTest.RegisterAndLookupLifecycle
[       OK ] DeviceConnectionRegistryTest.RegisterAndLookupLifecycle (0 ms)
[ RUN      ] DeviceConnectionRegistryTest.IgnoresNullChannelRegistration
[       OK ] DeviceConnectionRegistryTest.IgnoresNullChannelRegistration (0 ms)
[ RUN      ] DeviceConnectionRegistryTest.UnregisterLifecycle
[       OK ] DeviceConnectionRegistryTest.UnregisterLifecycle (0 ms)
[ RUN      ] DeviceConnectionRegistryTest.BatchOnlineFilter
[       OK ] DeviceConnectionRegistryTest.BatchOnlineFilter (0 ms)
[ RUN      ] DeviceConnectionRegistryTest.DeviceReconnectReplacesPreviousChannel
[       OK ] DeviceConnectionRegistryTest.DeviceReconnectReplacesPreviousChannel (0 ms)
[ RUN      ] DeviceConnectionRegistryTest.InactiveChannelTreatedAsOffline
[       OK ] DeviceConnectionRegistryTest.InactiveChannelTreatedAsOffline (0 ms)
[ RUN      ] DeviceConnectionRegistryTest.HeartbeatAndStaleEviction
[       OK ] DeviceConnectionRegistryTest.HeartbeatAndStaleEviction (125 ms)
[ RUN      ] DeviceConnectionRegistryTest.DisconnectCallbackNotification
[       OK ] DeviceConnectionRegistryTest.DisconnectCallbackNotification (105 ms)
[ RUN      ] DeviceConnectionRegistryTest.ConcurrentReadWriteStress
[       OK ] DeviceConnectionRegistryTest.ConcurrentReadWriteStress (154 ms)
[ RUN      ] DeviceConnectionRegistryTest.MockChannelDispatchAndInspection
[       OK ] DeviceConnectionRegistryTest.MockChannelDispatchAndInspection (4 ms)
[ RUN      ] DeviceConnectionRegistryTest.EnforcesMaxDevicesPerUserCapacityLimit
[       OK ] DeviceConnectionRegistryTest.EnforcesMaxDevicesPerUserCapacityLimit (0 ms)
[ RUN      ] DeviceConnectionRegistryTest.EnforcesGlobalCapacityLimit
[       OK ] DeviceConnectionRegistryTest.EnforcesGlobalCapacityLimit (0 ms)
[ RUN      ] DeviceConnectionRegistryTest.AtomicSupersedingDoesNotIncrementUserDeviceCount
[       OK ] DeviceConnectionRegistryTest.AtomicSupersedingDoesNotIncrementUserDeviceCount (0 ms)
[----------] 13 tests from DeviceConnectionRegistryTest (390 ms total)

[----------] Global test environment tear-down
[==========] 13 tests from 1 test suite ran. (390 ms total)
[  PASSED  ] 13 tests.

[==========] Running 9 tests from 1 test suite.
[----------] Global test environment set-up.
[----------] 9 tests from ConnectionLifecycleManagerTest
[ RUN      ] ConnectionLifecycleManagerTest.EstablishConnectionPopulatesSessionAndPresence
[       OK ] ConnectionLifecycleManagerTest.EstablishConnectionPopulatesSessionAndPresence (0 ms)
[ RUN      ] ConnectionLifecycleManagerTest.RejectEstablishWithNullChannel
[       OK ] ConnectionLifecycleManagerTest.RejectEstablishWithNullChannel (0 ms)
[ RUN      ] ConnectionLifecycleManagerTest.TerminateConnectionEvictsSessionAndUpdatesPresence
[       OK ] ConnectionLifecycleManagerTest.TerminateConnectionEvictsSessionAndUpdatesPresence (0 ms)
[ RUN      ] ConnectionLifecycleManagerTest.AtomicSupersedingMaintainsPresenceAndUpdatesSession
[       OK ] ConnectionLifecycleManagerTest.AtomicSupersedingMaintainsPresenceAndUpdatesSession (0 ms)
[ RUN      ] ConnectionLifecycleManagerTest.HeartbeatTouchesRegistryAndRefreshesSessionTimestamp
[       OK ] ConnectionLifecycleManagerTest.HeartbeatTouchesRegistryAndRefreshesSessionTimestamp (12 ms)
[ RUN      ] ConnectionLifecycleManagerTest.BackgroundReaperEvictsStaleConnection
[       OK ] ConnectionLifecycleManagerTest.BackgroundReaperEvictsStaleConnection (302 ms)
[ RUN      ] ConnectionLifecycleManagerTest.HeartbeatKeepsConnectionAliveDuringReaperCycles
[       OK ] ConnectionLifecycleManagerTest.HeartbeatKeepsConnectionAliveDuringReaperCycles (333 ms)
[ RUN      ] ConnectionLifecycleManagerTest.ManualSweepStaleConnections
[       OK ] ConnectionLifecycleManagerTest.ManualSweepStaleConnections (225 ms)
[ RUN      ] ConnectionLifecycleManagerTest.CleanStartAndStop
[       OK ] ConnectionLifecycleManagerTest.CleanStartAndStop (0 ms)
[----------] 9 tests from ConnectionLifecycleManagerTest (874 ms total)

[----------] Global test environment tear-down
[==========] 9 tests from 1 test suite ran. (874 ms total)
[  PASSED  ] 9 tests.
```

