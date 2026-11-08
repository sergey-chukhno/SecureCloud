#pragma once

#include "domain/audit_event.hpp"

#include <cstdint>

namespace securecloud::audit::security {

/// Returns the global atomic count of prevented recursive recording attempts.
[[nodiscard]] std::uint64_t get_recursion_prevented_count() noexcept;

/// Resets the global atomic counter for prevented recursive recording attempts.
void reset_recursion_prevented_count() noexcept;

/// Thread-local RAII guard preventing recursive re-entrancy into internal security event recording.
class AntiRecursionGuard {
  public:
    /// Returns true if internal security event recording is currently active on the calling thread.
    [[nodiscard]] static bool is_recording_in_progress() noexcept;

    explicit AntiRecursionGuard() noexcept;
    ~AntiRecursionGuard() noexcept;

    AntiRecursionGuard(const AntiRecursionGuard&) = delete;
    AntiRecursionGuard& operator=(const AntiRecursionGuard&) = delete;
    AntiRecursionGuard(AntiRecursionGuard&&) = delete;
    AntiRecursionGuard& operator=(AntiRecursionGuard&&) = delete;

    /// Returns true if this guard instance successfully acquired the recording slot.
    [[nodiscard]] bool acquired() const noexcept { return acquired_; }

  private:
    bool acquired_{false};
};

/// Evaluates whether a candidate event can be safely recorded without creating recursive loops.
[[nodiscard]] bool should_record_internal_event(const domain::AuditEvent& candidate) noexcept;

} // namespace securecloud::audit::security
