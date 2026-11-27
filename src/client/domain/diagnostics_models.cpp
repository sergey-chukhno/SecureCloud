#include "domain/diagnostics_models.hpp"

#include <nlohmann/json.hpp>

namespace securecloud::client::domain {

std::string TelemetrySnapshot::to_json() const {
    nlohmann::json root;
    root["rss_bytes"] = rss_bytes;
    root["rss_megabytes"] = rss_megabytes;
    root["cpu_percent"] = cpu_percent;
    root["active_ratchet_sessions"] = active_ratchet_sessions;
    root["pending_outbox_count"] = pending_outbox_count;
    root["pending_retry_count"] = pending_retry_count;
    root["active_file_transfers"] = active_file_transfers;
    root["connectivity_state"] = to_string(connectivity_state);
    root["live_gateway_transport"] = live_gateway_transport;
    root["last_gateway_rtt_ms"] = last_gateway_rtt_ms;
    root["avg_gateway_rtt_ms"] = avg_gateway_rtt_ms;
    root["gateway_requests_total"] = gateway_requests_total;
    root["gateway_requests_failed"] = gateway_requests_failed;
    root["sampled_at_ms"] = sampled_at_ms;
    return root.dump();
}

} // namespace securecloud::client::domain
