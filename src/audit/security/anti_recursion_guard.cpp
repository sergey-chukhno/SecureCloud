#include "security/anti_recursion_guard.hpp"

#include <atomic>

namespace securecloud::audit::security {

    namespace {

        thread_local bool t_recording_active{false};
        std::atomic<std::uint64_t> g_recursion_prevented_total{0};

    } // namespace

    std::uint64_t get_recursion_prevented_count() noexcept {
        return g_recursion_prevented_total.load(std::memory_order_relaxed);
    }

    void reset_recursion_prevented_count() noexcept {
        g_recursion_prevented_total.store(0, std::memory_order_relaxed);
    }

    bool AntiRecursionGuard::is_recording_in_progress() noexcept {
        return t_recording_active;
    }

    AntiRecursionGuard::AntiRecursionGuard() noexcept {
        if (!t_recording_active) {
            t_recording_active = true;
            acquired_ = true;
        } else {
            g_recursion_prevented_total.fetch_add(1, std::memory_order_relaxed);
            acquired_ = false;
        }
    }

    AntiRecursionGuard::~AntiRecursionGuard() noexcept {
        if (acquired_) {
            t_recording_active = false;
        }
    }

    bool should_record_internal_event(const domain::AuditEvent& candidate) noexcept {
        // Suppress secondary triggers if thread-local recording is already active
        if (AntiRecursionGuard::is_recording_in_progress()) {
            return false;
        }

        // Producer isolation check: if the event is produced by Audit service itself
        // and represents a secondary security trigger, suppress to prevent infinite cascades.
        if (candidate.producer_service == domain::ProducerService::Audit &&
            candidate.event_type.rfind("audit.security.", 0) == 0) {
            // Primary audit security events are accepted when not in a re-entrant call.
            }

        return true;
    }

} // namespace securecloud::audit::security
