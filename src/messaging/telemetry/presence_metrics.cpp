#include "telemetry/presence_metrics.hpp"

#include <sstream>

namespace securecloud::messaging::telemetry {

PresenceMetrics& PresenceMetrics::instance() {
    static PresenceMetrics s_instance;
    return s_instance;
}

void PresenceMetrics::reset() noexcept {
    active_connections_.store(0, std::memory_order_relaxed);
    presence_online_.store(0, std::memory_order_relaxed);
    presence_away_.store(0, std::memory_order_relaxed);
    presence_busy_.store(0, std::memory_order_relaxed);
    presence_offline_.store(0, std::memory_order_relaxed);
    churn_connected_.store(0, std::memory_order_relaxed);
    churn_disconnected_.store(0, std::memory_order_relaxed);
    churn_evicted_.store(0, std::memory_order_relaxed);
    fast_track_dispatches_total_.store(0, std::memory_order_relaxed);
    latency_count_.store(0, std::memory_order_relaxed);
    latency_sum_.store(0.0, std::memory_order_relaxed);
    bucket_1ms_.store(0, std::memory_order_relaxed);
    bucket_5ms_.store(0, std::memory_order_relaxed);
    bucket_10ms_.store(0, std::memory_order_relaxed);
    bucket_25ms_.store(0, std::memory_order_relaxed);
    bucket_50ms_.store(0, std::memory_order_relaxed);
    bucket_100ms_.store(0, std::memory_order_relaxed);
    bucket_250ms_.store(0, std::memory_order_relaxed);
}

void PresenceMetrics::set_active_connections(int64_t count) noexcept {
    active_connections_.store(count, std::memory_order_relaxed);
}

void PresenceMetrics::increment_active_connections() noexcept {
    active_connections_.fetch_add(1, std::memory_order_relaxed);
}

void PresenceMetrics::decrement_active_connections() noexcept {
    active_connections_.fetch_sub(1, std::memory_order_relaxed);
}

int64_t PresenceMetrics::active_connections() const noexcept {
    return active_connections_.load(std::memory_order_relaxed);
}

void PresenceMetrics::set_presence_status_count(std::string_view status, int64_t count) noexcept {
    if (status == "online") {
        presence_online_.store(count, std::memory_order_relaxed);
    } else if (status == "away") {
        presence_away_.store(count, std::memory_order_relaxed);
    } else if (status == "busy") {
        presence_busy_.store(count, std::memory_order_relaxed);
    } else if (status == "offline") {
        presence_offline_.store(count, std::memory_order_relaxed);
    }
}

int64_t PresenceMetrics::presence_status_count(std::string_view status) const noexcept {
    if (status == "online") {
        return presence_online_.load(std::memory_order_relaxed);
    }
    if (status == "away") {
        return presence_away_.load(std::memory_order_relaxed);
    }
    if (status == "busy") {
        return presence_busy_.load(std::memory_order_relaxed);
    }
    if (status == "offline") {
        return presence_offline_.load(std::memory_order_relaxed);
    }
    return 0;
}

void PresenceMetrics::record_connection_churn(ConnectionChurnEvent event) noexcept {
    switch (event) {
    case ConnectionChurnEvent::Connected:
        churn_connected_.fetch_add(1, std::memory_order_relaxed);
        break;
    case ConnectionChurnEvent::Disconnected:
        churn_disconnected_.fetch_add(1, std::memory_order_relaxed);
        break;
    case ConnectionChurnEvent::Evicted:
        churn_evicted_.fetch_add(1, std::memory_order_relaxed);
        break;
    }
}

uint64_t PresenceMetrics::connection_churn(ConnectionChurnEvent event) const noexcept {
    switch (event) {
    case ConnectionChurnEvent::Connected:
        return churn_connected_.load(std::memory_order_relaxed);
    case ConnectionChurnEvent::Disconnected:
        return churn_disconnected_.load(std::memory_order_relaxed);
    case ConnectionChurnEvent::Evicted:
        return churn_evicted_.load(std::memory_order_relaxed);
    }
    return 0;
}

void PresenceMetrics::increment_fast_track_dispatches(uint64_t count) noexcept {
    fast_track_dispatches_total_.fetch_add(count, std::memory_order_relaxed);
}

uint64_t PresenceMetrics::fast_track_dispatches_total() const noexcept {
    return fast_track_dispatches_total_.load(std::memory_order_relaxed);
}

void PresenceMetrics::record_presence_update_latency(double seconds) noexcept {
    latency_count_.fetch_add(1, std::memory_order_relaxed);

    double current = latency_sum_.load(std::memory_order_relaxed);
    while (!latency_sum_.compare_exchange_weak(current, current + seconds, std::memory_order_relaxed)) {
    }

    if (seconds <= 0.001) {
        bucket_1ms_.fetch_add(1, std::memory_order_relaxed);
    }
    if (seconds <= 0.005) {
        bucket_5ms_.fetch_add(1, std::memory_order_relaxed);
    }
    if (seconds <= 0.010) {
        bucket_10ms_.fetch_add(1, std::memory_order_relaxed);
    }
    if (seconds <= 0.025) {
        bucket_25ms_.fetch_add(1, std::memory_order_relaxed);
    }
    if (seconds <= 0.050) {
        bucket_50ms_.fetch_add(1, std::memory_order_relaxed);
    }
    if (seconds <= 0.100) {
        bucket_100ms_.fetch_add(1, std::memory_order_relaxed);
    }
    if (seconds <= 0.250) {
        bucket_250ms_.fetch_add(1, std::memory_order_relaxed);
    }
}

uint64_t PresenceMetrics::latency_sample_count() const noexcept {
    return latency_count_.load(std::memory_order_relaxed);
}

double PresenceMetrics::latency_sum() const noexcept {
    return latency_sum_.load(std::memory_order_relaxed);
}

std::string PresenceMetrics::to_prometheus_text() const {
    std::ostringstream ss;

    // 1. messaging_active_connections
    ss << "# HELP messaging_active_connections Current active device transport connections.\n";
    ss << "# TYPE messaging_active_connections gauge\n";
    ss << "messaging_active_connections " << active_connections_.load(std::memory_order_relaxed) << "\n";

    // 2. messaging_presence_status
    ss << "# HELP messaging_presence_status Current distribution of user presence statuses.\n";
    ss << "# TYPE messaging_presence_status gauge\n";
    ss << "messaging_presence_status{status=\"online\"} " << presence_online_.load(std::memory_order_relaxed) << "\n";
    ss << "messaging_presence_status{status=\"away\"} " << presence_away_.load(std::memory_order_relaxed) << "\n";
    ss << "messaging_presence_status{status=\"busy\"} " << presence_busy_.load(std::memory_order_relaxed) << "\n";
    ss << "messaging_presence_status{status=\"offline\"} " << presence_offline_.load(std::memory_order_relaxed) << "\n";

    // 3. messaging_connection_churn_total
    ss << "# HELP messaging_connection_churn_total Monotonic count of connection churn events.\n";
    ss << "# TYPE messaging_connection_churn_total counter\n";
    ss << "messaging_connection_churn_total{event=\"connected\"} " << churn_connected_.load(std::memory_order_relaxed)
       << "\n";
    ss << "messaging_connection_churn_total{event=\"disconnected\"} "
       << churn_disconnected_.load(std::memory_order_relaxed) << "\n";
    ss << "messaging_connection_churn_total{event=\"evicted\"} " << churn_evicted_.load(std::memory_order_relaxed)
       << "\n";

    // 4. messaging_fast_track_dispatches_total
    ss << "# HELP messaging_fast_track_dispatches_total Monotonic count of real-time reconnect fast-track "
          "dispatches.\n";
    ss << "# TYPE messaging_fast_track_dispatches_total counter\n";
    ss << "messaging_fast_track_dispatches_total " << fast_track_dispatches_total_.load(std::memory_order_relaxed)
       << "\n";

    // 5. messaging_presence_update_latency_seconds
    ss << "# HELP messaging_presence_update_latency_seconds Latency histogram for presence update operations.\n";
    ss << "# TYPE messaging_presence_update_latency_seconds histogram\n";
    ss << "messaging_presence_update_latency_seconds_bucket{le=\"0.001\"} "
       << bucket_1ms_.load(std::memory_order_relaxed) << "\n";
    ss << "messaging_presence_update_latency_seconds_bucket{le=\"0.005\"} "
       << bucket_5ms_.load(std::memory_order_relaxed) << "\n";
    ss << "messaging_presence_update_latency_seconds_bucket{le=\"0.01\"} "
       << bucket_10ms_.load(std::memory_order_relaxed) << "\n";
    ss << "messaging_presence_update_latency_seconds_bucket{le=\"0.025\"} "
       << bucket_25ms_.load(std::memory_order_relaxed) << "\n";
    ss << "messaging_presence_update_latency_seconds_bucket{le=\"0.05\"} "
       << bucket_50ms_.load(std::memory_order_relaxed) << "\n";
    ss << "messaging_presence_update_latency_seconds_bucket{le=\"0.1\"} "
       << bucket_100ms_.load(std::memory_order_relaxed) << "\n";
    ss << "messaging_presence_update_latency_seconds_bucket{le=\"0.25\"} "
       << bucket_250ms_.load(std::memory_order_relaxed) << "\n";
    ss << "messaging_presence_update_latency_seconds_bucket{le=\"+Inf\"} "
       << latency_count_.load(std::memory_order_relaxed) << "\n";
    ss << "messaging_presence_update_latency_seconds_sum " << latency_sum_.load(std::memory_order_relaxed) << "\n";
    ss << "messaging_presence_update_latency_seconds_count " << latency_count_.load(std::memory_order_relaxed) << "\n";

    return ss.str();
}

} // namespace securecloud::messaging::telemetry
