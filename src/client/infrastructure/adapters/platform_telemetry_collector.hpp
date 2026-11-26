#pragma once

#include <chrono>
#include <cstdint>
#include <mutex>

namespace securecloud::client::infrastructure::adapters {

struct ProcessResourceSample {
    uint64_t rss_bytes{0U};
    double rss_megabytes{0.0};
    double cpu_percent{0.0};
    int64_t sampled_at_ms{0};

    bool operator==(const ProcessResourceSample& other) const noexcept = default;
};

/// Cross-platform OS resource sampler (macOS Mach task_info + getrusage, Linux /proc/self/statm +
/// getrusage, Windows GetProcessMemoryInfo + GetProcessTimes). Thread-safe for periodic UI/benchmark sampling.
class PlatformTelemetryCollector {
  public:
    PlatformTelemetryCollector() = default;
    ~PlatformTelemetryCollector() = default;

    PlatformTelemetryCollector(const PlatformTelemetryCollector&) = delete;
    PlatformTelemetryCollector& operator=(const PlatformTelemetryCollector&) = delete;

    [[nodiscard]] ProcessResourceSample sample();

  private:
    mutable std::mutex mutex_;
    bool has_previous_{false};
    std::chrono::steady_clock::time_point prev_wall_time_{};
    uint64_t prev_cpu_us_{0U};
};

} // namespace securecloud::client::infrastructure::adapters
