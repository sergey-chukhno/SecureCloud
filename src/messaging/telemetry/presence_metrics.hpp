#pragma once

#include <atomic>
#include <cstdint>
#include <string>
#include <string_view>

namespace securecloud::messaging::telemetry {

enum class ConnectionChurnEvent { Connected, Disconnected, Evicted };

/**
 * @brief Thread-safe, lock-free Prometheus telemetry collector for presence & connection subsystems (MSG-010-T07).
 *
 * Invariant: Zero ScyllaDB/database amplification. Uses pure atomic variables.
 */
class PresenceMetrics {
  public:
    static PresenceMetrics& instance();

    /// Resets all metric counters and gauges to initial zero state (test isolation)
    void reset() noexcept;

    // 1. messaging_active_connections (Gauge)
    void set_active_connections(int64_t count) noexcept;
    void increment_active_connections() noexcept;
    void decrement_active_connections() noexcept;
    [[nodiscard]] int64_t active_connections() const noexcept;

    // 2. messaging_presence_status{status="online|away|busy|offline"} (Gauge)
    void set_presence_status_count(std::string_view status, int64_t count) noexcept;
    [[nodiscard]] int64_t presence_status_count(std::string_view status) const noexcept;

    // 3. messaging_connection_churn_total{event="connected|disconnected|evicted"} (Counter)
    void record_connection_churn(ConnectionChurnEvent event) noexcept;
    [[nodiscard]] uint64_t connection_churn(ConnectionChurnEvent event) const noexcept;

    // 4. messaging_fast_track_dispatches_total (Counter)
    void increment_fast_track_dispatches(uint64_t count = 1) noexcept;
    [[nodiscard]] uint64_t fast_track_dispatches_total() const noexcept;

    // 5. messaging_presence_update_latency_seconds (Histogram)
    void record_presence_update_latency(double seconds) noexcept;
    [[nodiscard]] uint64_t latency_sample_count() const noexcept;
    [[nodiscard]] double latency_sum() const noexcept;

    /// Formats all collected metrics into OpenMetrics / Prometheus exposition text format
    [[nodiscard]] std::string to_prometheus_text() const;

  private:
    PresenceMetrics() = default;
    ~PresenceMetrics() = default;

    PresenceMetrics(const PresenceMetrics&) = delete;
    PresenceMetrics& operator=(const PresenceMetrics&) = delete;

    std::atomic<int64_t> active_connections_{0};

    // Presence status gauges
    std::atomic<int64_t> presence_online_{0};
    std::atomic<int64_t> presence_away_{0};
    std::atomic<int64_t> presence_busy_{0};
    std::atomic<int64_t> presence_offline_{0};

    // Connection churn counters
    std::atomic<uint64_t> churn_connected_{0};
    std::atomic<uint64_t> churn_disconnected_{0};
    std::atomic<uint64_t> churn_evicted_{0};

    // Fast-track counter
    std::atomic<uint64_t> fast_track_dispatches_total_{0};

    // Latency histogram
    std::atomic<uint64_t> latency_count_{0};
    std::atomic<double> latency_sum_{0.0};
    std::atomic<uint64_t> bucket_1ms_{0};
    std::atomic<uint64_t> bucket_5ms_{0};
    std::atomic<uint64_t> bucket_10ms_{0};
    std::atomic<uint64_t> bucket_25ms_{0};
    std::atomic<uint64_t> bucket_50ms_{0};
    std::atomic<uint64_t> bucket_100ms_{0};
    std::atomic<uint64_t> bucket_250ms_{0};
};

} // namespace securecloud::messaging::telemetry
