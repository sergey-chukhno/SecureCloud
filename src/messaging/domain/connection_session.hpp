#pragma once

#include "domain/conversation_types.hpp"
#include "domain/message_types.hpp"

#include <chrono>
#include <compare>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace securecloud::messaging::domain {

/// Lifecycle state of a client device's physical transport connection channel.
enum class ConnectionState : uint8_t {
    Connecting = 0, ///< Transport handshake / channel registration initiated.
    Active = 1,     ///< Authenticated channel actively streaming and leased.
    Stale = 2,      ///< Idle window exceeded without heartbeat / ping.
    Terminated = 3, ///< Transport closed gracefully or evicted by reaper.
};

/// Validates legal state transitions according to the connection state machine.
[[nodiscard]] constexpr bool is_valid_connection_transition(ConnectionState from, ConnectionState to) noexcept {
    switch (from) {
    case ConnectionState::Connecting:
        // Handshake succeeds -> Active; handshake fails / aborts -> Terminated
        return to == ConnectionState::Active || to == ConnectionState::Terminated;
    case ConnectionState::Active:
        // Idle timeout -> Stale; disconnect / unregister -> Terminated
        return to == ConnectionState::Stale || to == ConnectionState::Terminated;
    case ConnectionState::Stale:
        // Heartbeat received -> Active; reaper eviction -> Terminated
        return to == ConnectionState::Active || to == ConnectionState::Terminated;
    case ConnectionState::Terminated:
        // Terminal state; a new connection requires a fresh DeviceConnection entity.
        return false;
    }
    return false;
}

/// Converts ConnectionState to canonical string representation.
[[nodiscard]] constexpr std::string_view to_string(ConnectionState state) noexcept {
    switch (state) {
    case ConnectionState::Connecting:
        return "CONNECTING";
    case ConnectionState::Active:
        return "ACTIVE";
    case ConnectionState::Stale:
        return "STALE";
    case ConnectionState::Terminated:
        return "TERMINATED";
    }
    return "UNKNOWN";
}

/// Parses canonical string to ConnectionState.
[[nodiscard]] inline std::optional<ConnectionState> parse_connection_state(std::string_view sv) noexcept {
    if (sv == "CONNECTING" || sv == "connecting") {
        return ConnectionState::Connecting;
    }
    if (sv == "ACTIVE" || sv == "active") {
        return ConnectionState::Active;
    }
    if (sv == "STALE" || sv == "stale") {
        return ConnectionState::Stale;
    }
    if (sv == "TERMINATED" || sv == "terminated") {
        return ConnectionState::Terminated;
    }
    return std::nullopt;
}

/// Represents an active or historical transport connection for a client device.
/// Distinct from Auth Service SessionEntity: DeviceConnection represents the transient
/// TCP/HTTP stream, whereas SessionEntity represents the long-lived login authentication state.
struct DeviceConnection {
    std::string connection_id{};  ///< Ephemeral transport session UUID (v7).
    DeviceId device_id{};         ///< Connected physical device.
    UserId user_id{};             ///< Authenticated user owning the device.
    std::string client_ip{};      ///< Remote peer IP address.
    std::string user_agent{};     ///< Client software identifier.
    uint32_t protocol_version{1}; ///< Negotiated protocol version.
    ConnectionState state{ConnectionState::Connecting};
    std::chrono::steady_clock::time_point connected_at{};
    std::chrono::steady_clock::time_point last_heartbeat_at{};
    std::optional<std::string> auth_session_id{}; ///< Optional correlation to Auth SessionEntity.

    [[nodiscard]] bool is_active() const noexcept { return state == ConnectionState::Active; }

    /// Attempts to transition the connection state, returning true on legal transition.
    bool transition_to(ConnectionState new_state) noexcept {
        if (!is_valid_connection_transition(state, new_state)) {
            return false;
        }
        state = new_state;
        return true;
    }

    auto operator<=>(const DeviceConnection& other) const noexcept = default;
    bool operator==(const DeviceConnection& other) const noexcept = default;
};

/// Type alias for ConnectionSession mapping to DeviceConnection
using ConnectionSession = DeviceConnection;

} // namespace securecloud::messaging::domain
