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
    // Producer isolation check: Audit service events must have a valid non-empty event_type
    if (candidate.producer_service == domain::ProducerService::Audit) {
        if (candidate.event_type.empty()) {
            return false;
        }
    }
    return true;
}

} // namespace securecloud::audit::security