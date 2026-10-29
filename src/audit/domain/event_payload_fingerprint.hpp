#pragma once

#include "audit_event.hpp"

#include <array>
#include <cstdint>
#include <string>

namespace securecloud::audit::domain {

    class EventPayloadFingerprint {
    public:
        using digest_type = std::array<uint8_t, 32>; // SHA-256

        constexpr EventPayloadFingerprint() noexcept = default;
        constexpr explicit EventPayloadFingerprint(const digest_type& digest) noexcept : digest_(digest) {}

        /// Computes canonical SHA-256 digest over all immutable AuditEvent fields
        /// (event_id, occurred_at_ms, event_type, severity, producer_service,
        ///  producer_instance, actor_type, actor_id, target_type, target_id,
        ///  correlation_id, causation_id, and lexicographically sorted metadata).
        /// Explicitly excludes service-assigned received_at.
        [[nodiscard]] static EventPayloadFingerprint compute(const AuditEvent& event);

        [[nodiscard]] constexpr const digest_type& bytes() const noexcept { return digest_; }
        [[nodiscard]] std::string to_hex_prefix(size_t byte_count = 8) const;

        constexpr bool operator==(const EventPayloadFingerprint& other) const noexcept = default;
        constexpr auto operator<=>(const EventPayloadFingerprint& other) const noexcept = default;

    private:
        digest_type digest_{};
    };

} // namespace securecloud::audit::domain