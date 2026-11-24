#pragma once

#include <array>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <string>

namespace securecloud::files::audit {

enum class FilesOutboxCategory : uint8_t { Transactional, Autonomous, Count };
enum class FilesOutboxOutcome : uint8_t { Success, Retryable, Rejected, Count };
enum class FilesOutboxQuarantineReason : uint8_t { Validation, Conflict, Mapper, Rejected, Count };

class FilesOutboxMetrics {
  public:
    [[nodiscard]] static FilesOutboxMetrics& instance() noexcept;
    std::atomic<uint64_t> batches_dispatched{0};
    std::atomic<uint64_t> events_published{0};
    std::atomic<uint64_t> events_quarantined{0};
    std::atomic<uint64_t> transient_failures{0};
    std::atomic<uint64_t> security_auth_failures{0};
    std::atomic<uint64_t> rows_purged{0};

    void record_staged(FilesOutboxCategory category, uint64_t count = 1) noexcept;
    void record_delivered(uint64_t count = 1) noexcept;
    void record_batch(FilesOutboxOutcome outcome, uint64_t count = 1) noexcept;
    void record_retry(uint64_t count = 1) noexcept;
    void record_quarantined(FilesOutboxQuarantineReason reason, uint64_t count = 1) noexcept;
    void record_purged(uint64_t count) noexcept;
    void set_pending(int64_t value) noexcept;
    void set_oldest_pending_age(double value) noexcept;
    [[nodiscard]] uint64_t staged(FilesOutboxCategory category) const noexcept;
    [[nodiscard]] uint64_t delivered() const noexcept;
    [[nodiscard]] uint64_t batches(FilesOutboxOutcome outcome) const noexcept;
    [[nodiscard]] uint64_t retries() const noexcept;
    [[nodiscard]] uint64_t quarantined(FilesOutboxQuarantineReason reason) const noexcept;
    [[nodiscard]] std::string to_prometheus_text() const;

  private:
    std::array<std::atomic<uint64_t>, static_cast<size_t>(FilesOutboxCategory::Count)> staged_{};
    std::atomic<uint64_t> delivered_{0};
    std::array<std::atomic<uint64_t>, static_cast<size_t>(FilesOutboxOutcome::Count)> batches_{};
    std::atomic<uint64_t> retries_{0};
    std::array<std::atomic<uint64_t>, static_cast<size_t>(FilesOutboxQuarantineReason::Count)> quarantined_{};
    std::atomic<uint64_t> purged_{0};
    std::atomic<int64_t> pending_{0};
    std::atomic<double> oldest_pending_age_{0.0};
};

} // namespace securecloud::files::audit
