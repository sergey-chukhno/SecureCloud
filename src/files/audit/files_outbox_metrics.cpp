#include "files/audit/files_outbox_metrics.hpp"

#include <algorithm>
#include <sstream>

namespace securecloud::files::audit {
namespace {
constexpr const char* category_name[] = {"transactional", "autonomous"};
constexpr const char* outcome_name[] = {"success", "retryable", "rejected"};
constexpr const char* quarantine_name[] = {"validation", "conflict", "mapper", "rejected"};
}

FilesOutboxMetrics& FilesOutboxMetrics::instance() noexcept {
    static FilesOutboxMetrics metrics;
    return metrics;
}

void FilesOutboxMetrics::record_staged(FilesOutboxCategory c, uint64_t n) noexcept { staged_[static_cast<size_t>(c)].fetch_add(n, std::memory_order_relaxed); }
void FilesOutboxMetrics::record_delivered(uint64_t n) noexcept { delivered_.fetch_add(n, std::memory_order_relaxed); }
void FilesOutboxMetrics::record_batch(FilesOutboxOutcome o, uint64_t n) noexcept { batches_[static_cast<size_t>(o)].fetch_add(n, std::memory_order_relaxed); }
void FilesOutboxMetrics::record_retry(uint64_t n) noexcept { retries_.fetch_add(n, std::memory_order_relaxed); }
void FilesOutboxMetrics::record_quarantined(FilesOutboxQuarantineReason r, uint64_t n) noexcept { quarantined_[static_cast<size_t>(r)].fetch_add(n, std::memory_order_relaxed); }
void FilesOutboxMetrics::record_purged(uint64_t n) noexcept { purged_.fetch_add(n, std::memory_order_relaxed); rows_purged.fetch_add(n, std::memory_order_relaxed); }
void FilesOutboxMetrics::set_pending(int64_t n) noexcept { pending_.store(std::max<int64_t>(0, n), std::memory_order_relaxed); }
void FilesOutboxMetrics::set_oldest_pending_age(double n) noexcept { oldest_pending_age_.store(std::max(0.0, n), std::memory_order_relaxed); }
uint64_t FilesOutboxMetrics::staged(FilesOutboxCategory c) const noexcept { return staged_[static_cast<size_t>(c)].load(std::memory_order_relaxed); }
uint64_t FilesOutboxMetrics::delivered() const noexcept { return delivered_.load(std::memory_order_relaxed); }
uint64_t FilesOutboxMetrics::batches(FilesOutboxOutcome o) const noexcept { return batches_[static_cast<size_t>(o)].load(std::memory_order_relaxed); }
uint64_t FilesOutboxMetrics::retries() const noexcept { return retries_.load(std::memory_order_relaxed); }
uint64_t FilesOutboxMetrics::quarantined(FilesOutboxQuarantineReason r) const noexcept { return quarantined_[static_cast<size_t>(r)].load(std::memory_order_relaxed); }

std::string FilesOutboxMetrics::to_prometheus_text() const {
    std::ostringstream out;
    out << "# HELP files_outbox_pending_events Number of pending Files audit events.\n# TYPE files_outbox_pending_events gauge\n"
        << "files_outbox_pending_events " << pending_.load(std::memory_order_relaxed) << "\n"
        << "# HELP files_outbox_events_staged_total Files audit events staged.\n# TYPE files_outbox_events_staged_total counter\n";
    for (size_t i = 0; i < 2; ++i) out << "files_outbox_events_staged_total{category=\"" << category_name[i] << "\"} " << staged_[i].load(std::memory_order_relaxed) << "\n";
    out << "# HELP files_outbox_events_delivered_total Files audit events delivered.\n# TYPE files_outbox_events_delivered_total counter\nfiles_outbox_events_delivered_total " << delivered() << "\n"
        << "# HELP files_outbox_delivery_batches_total Files audit delivery batches by outcome.\n# TYPE files_outbox_delivery_batches_total counter\n";
    for (size_t i = 0; i < 3; ++i) out << "files_outbox_delivery_batches_total{outcome=\"" << outcome_name[i] << "\"} " << batches_[i].load(std::memory_order_relaxed) << "\n";
    out << "# HELP files_outbox_retries_total Files audit retry events.\n# TYPE files_outbox_retries_total counter\nfiles_outbox_retries_total " << retries() << "\n"
        << "# HELP files_outbox_quarantined_total Files audit quarantined events.\n# TYPE files_outbox_quarantined_total counter\n";
    for (size_t i = 0; i < 4; ++i) out << "files_outbox_quarantined_total{reason=\"" << quarantine_name[i] << "\"} " << quarantined_[i].load(std::memory_order_relaxed) << "\n";
    out << "# HELP files_outbox_purged_total Published Files audit events purged.\n# TYPE files_outbox_purged_total counter\nfiles_outbox_purged_total " << purged_.load(std::memory_order_relaxed) << "\n"
        << "# HELP files_outbox_oldest_pending_age_seconds Age of the oldest pending Files audit event.\n# TYPE files_outbox_oldest_pending_age_seconds gauge\nfiles_outbox_oldest_pending_age_seconds " << oldest_pending_age_.load(std::memory_order_relaxed) << "\n# EOF\n";
    return out.str();
}
} // namespace securecloud::files::audit
