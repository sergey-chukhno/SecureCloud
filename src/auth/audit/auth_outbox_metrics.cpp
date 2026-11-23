#include "auth/audit/auth_outbox_metrics.hpp"

#include <algorithm>
#include <sstream>

namespace securecloud::auth::audit {

AuthOutboxMetrics& AuthOutboxMetrics::instance() noexcept {
    static AuthOutboxMetrics metrics;
    return metrics;
}

void AuthOutboxMetrics::record_event_staged(StagingCategory category, uint64_t count) noexcept {
    const auto idx = static_cast<size_t>(category);
    if (idx < static_cast<size_t>(StagingCategory::Count)) {
        events_staged_total_[idx].fetch_add(count, std::memory_order_relaxed);
    }
}

void AuthOutboxMetrics::record_events_delivered(uint64_t count) noexcept {
    events_delivered_total_.fetch_add(count, std::memory_order_relaxed);
}

void AuthOutboxMetrics::record_delivery_batch(BatchOutcome outcome, uint64_t count) noexcept {
    const auto idx = static_cast<size_t>(outcome);
    if (idx < static_cast<size_t>(BatchOutcome::Count)) {
        delivery_batches_total_[idx].fetch_add(count, std::memory_order_relaxed);
    }
}

void AuthOutboxMetrics::record_retry(uint64_t count) noexcept {
    retries_total_.fetch_add(count, std::memory_order_relaxed);
}

void AuthOutboxMetrics::record_quarantined(QuarantineReason reason, uint64_t count) noexcept {
    const auto idx = static_cast<size_t>(reason);
    if (idx < static_cast<size_t>(QuarantineReason::Count)) {
        quarantined_total_[idx].fetch_add(count, std::memory_order_relaxed);
    }
}

void AuthOutboxMetrics::record_purged(uint64_t count) noexcept {
    purged_total_.fetch_add(count, std::memory_order_relaxed);
}

void AuthOutboxMetrics::set_pending_events(int64_t count) noexcept {
    pending_events_.store(std::max<int64_t>(0, count), std::memory_order_relaxed);
}

void AuthOutboxMetrics::increment_pending_events(int64_t delta) noexcept {
    if (delta > 0) {
        pending_events_.fetch_add(delta, std::memory_order_relaxed);
    }
}

void AuthOutboxMetrics::decrement_pending_events(int64_t delta) noexcept {
    if (delta <= 0) {
        return;
    }
    int64_t current = pending_events_.load(std::memory_order_relaxed);
    while (true) {
        const int64_t next = current > delta ? (current - delta) : 0;
        if (pending_events_.compare_exchange_weak(current, next, std::memory_order_relaxed)) {
            break;
        }
    }
}

void AuthOutboxMetrics::set_oldest_pending_age_seconds(double age_seconds) noexcept {
    oldest_pending_age_seconds_.store(age_seconds > 0.0 ? age_seconds : 0.0, std::memory_order_relaxed);
}

int64_t AuthOutboxMetrics::pending_events() const noexcept {
    return pending_events_.load(std::memory_order_relaxed);
}

uint64_t AuthOutboxMetrics::events_staged_total(StagingCategory category) const noexcept {
    const auto idx = static_cast<size_t>(category);
    if (idx < static_cast<size_t>(StagingCategory::Count)) {
        return events_staged_total_[idx].load(std::memory_order_relaxed);
    }
    return 0;
}

uint64_t AuthOutboxMetrics::events_delivered_total() const noexcept {
    return events_delivered_total_.load(std::memory_order_relaxed);
}

uint64_t AuthOutboxMetrics::delivery_batches_total(BatchOutcome outcome) const noexcept {
    const auto idx = static_cast<size_t>(outcome);
    if (idx < static_cast<size_t>(BatchOutcome::Count)) {
        return delivery_batches_total_[idx].load(std::memory_order_relaxed);
    }
    return 0;
}

uint64_t AuthOutboxMetrics::retries_total() const noexcept {
    return retries_total_.load(std::memory_order_relaxed);
}

uint64_t AuthOutboxMetrics::quarantined_total(QuarantineReason reason) const noexcept {
    const auto idx = static_cast<size_t>(reason);
    if (idx < static_cast<size_t>(QuarantineReason::Count)) {
        return quarantined_total_[idx].load(std::memory_order_relaxed);
    }
    return 0;
}

uint64_t AuthOutboxMetrics::purged_total() const noexcept {
    return purged_total_.load(std::memory_order_relaxed);
}

double AuthOutboxMetrics::oldest_pending_age_seconds() const noexcept {
    return oldest_pending_age_seconds_.load(std::memory_order_relaxed);
}

void AuthOutboxMetrics::reset() noexcept {
    pending_events_.store(0, std::memory_order_relaxed);
    for (auto& cell : events_staged_total_) {
        cell.store(0, std::memory_order_relaxed);
    }
    events_delivered_total_.store(0, std::memory_order_relaxed);
    for (auto& cell : delivery_batches_total_) {
        cell.store(0, std::memory_order_relaxed);
    }
    retries_total_.store(0, std::memory_order_relaxed);
    for (auto& cell : quarantined_total_) {
        cell.store(0, std::memory_order_relaxed);
    }
    purged_total_.store(0, std::memory_order_relaxed);
    oldest_pending_age_seconds_.store(0.0, std::memory_order_relaxed);
}

std::string AuthOutboxMetrics::to_prometheus_text() const {
    std::ostringstream ss;

    // 1. auth_outbox_pending_events
    ss << "# HELP auth_outbox_pending_events Instantaneous count of pending events in Auth outbox\n";
    ss << "# TYPE auth_outbox_pending_events gauge\n";
    ss << "auth_outbox_pending_events " << pending_events_.load(std::memory_order_relaxed) << "\n";

    // 2. auth_outbox_events_staged_total
    ss << "# HELP auth_outbox_events_staged_total Total number of audit events staged into Auth outbox\n";
    ss << "# TYPE auth_outbox_events_staged_total counter\n";
    for (size_t c = 0; c < static_cast<size_t>(StagingCategory::Count); ++c) {
        const uint64_t val = events_staged_total_[c].load(std::memory_order_relaxed);
        ss << "auth_outbox_events_staged_total{category=\"" << to_string(static_cast<StagingCategory>(c)) << "\"} "
           << val << "\n";
    }

    // 3. auth_outbox_events_delivered_total
    ss << "# HELP auth_outbox_events_delivered_total Total number of outbox events acknowledged by Audit Service\n";
    ss << "# TYPE auth_outbox_events_delivered_total counter\n";
    ss << "auth_outbox_events_delivered_total " << events_delivered_total_.load(std::memory_order_relaxed) << "\n";

    // 4. auth_outbox_delivery_batches_total
    ss << "# HELP auth_outbox_delivery_batches_total Total number of outbox gRPC batch delivery attempts by outcome\n";
    ss << "# TYPE auth_outbox_delivery_batches_total counter\n";
    for (size_t o = 0; o < static_cast<size_t>(BatchOutcome::Count); ++o) {
        const uint64_t val = delivery_batches_total_[o].load(std::memory_order_relaxed);
        ss << "auth_outbox_delivery_batches_total{outcome=\"" << to_string(static_cast<BatchOutcome>(o)) << "\"} "
           << val << "\n";
    }

    // 5. auth_outbox_retries_total
    ss << "# HELP auth_outbox_retries_total Total number of transient outbox event retry attempts\n";
    ss << "# TYPE auth_outbox_retries_total counter\n";
    ss << "auth_outbox_retries_total " << retries_total_.load(std::memory_order_relaxed) << "\n";

    // 6. auth_outbox_quarantined_total
    ss << "# HELP auth_outbox_quarantined_total Total number of permanently quarantined outbox events by reason\n";
    ss << "# TYPE auth_outbox_quarantined_total counter\n";
    for (size_t r = 0; r < static_cast<size_t>(QuarantineReason::Count); ++r) {
        const uint64_t val = quarantined_total_[r].load(std::memory_order_relaxed);
        ss << "auth_outbox_quarantined_total{reason=\"" << to_string(static_cast<QuarantineReason>(r)) << "\"} " << val
           << "\n";
    }

    // 7. auth_outbox_purged_total
    ss << "# HELP auth_outbox_purged_total Total number of historical published outbox records purged\n";
    ss << "# TYPE auth_outbox_purged_total counter\n";
    ss << "auth_outbox_purged_total " << purged_total_.load(std::memory_order_relaxed) << "\n";

    // 8. auth_outbox_oldest_pending_age_seconds
    ss << "# HELP auth_outbox_oldest_pending_age_seconds Age in seconds of the oldest pending event in Auth outbox\n";
    ss << "# TYPE auth_outbox_oldest_pending_age_seconds gauge\n";
    ss << "auth_outbox_oldest_pending_age_seconds " << oldest_pending_age_seconds_.load(std::memory_order_relaxed)
       << "\n";

    return ss.str();
}

} // namespace securecloud::auth::audit
