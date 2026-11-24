#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <ostream>
#include <string>
#include <string_view>

namespace securecloud::files::audit {

enum class FilesDiagnosticCategory : uint8_t { Batch, Lease, Quarantine, Outage, Recovery, Purge, Count };

class FilesOutboxDiagnostics {
  public:
    [[nodiscard]] static FilesOutboxDiagnostics& instance() noexcept;
    std::mutex mutex;
    std::string last_error_message;
    int last_status_code{0};
    uint32_t consecutive_failures{0};
    std::chrono::system_clock::time_point last_success_at{};
    std::chrono::system_clock::time_point last_failure_at{};
    std::chrono::system_clock::time_point last_purge_at{};

    [[nodiscard]] static std::string scrub_sensitive_data(std::string_view raw) noexcept;
    void log_event(FilesDiagnosticCategory category, std::string_view event, std::string_view correlation_id = {},
                   std::string_view detail = {}, uint64_t value = 0) noexcept;
    void set_output_stream(std::ostream* stream) noexcept;
    void reset_rate_limiters() noexcept;

  private:
    std::mutex log_mutex_;
    std::ostream* output_stream_{nullptr};
    std::chrono::steady_clock::time_point last_logged_[static_cast<size_t>(FilesDiagnosticCategory::Count)]{};
    double rate_tokens_[static_cast<size_t>(FilesDiagnosticCategory::Count)]{5, 5, 5, 5, 5, 5};
};

} // namespace securecloud::files::audit
