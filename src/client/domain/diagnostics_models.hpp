#pragma once

#include "domain/offline_sync_models.hpp"
#include "securecloud/configuration/secret_string.hpp"

#include <cstddef>
#include <cstdint>
#include <string>

namespace securecloud::client::domain {

struct GatewayTransportMetrics {
    int64_t last_rtt_ms{0};
    int64_t avg_rtt_ms{0};
    uint64_t requests_total{0U};
    uint64_t requests_failed{0U};

    bool operator==(const GatewayTransportMetrics& other) const noexcept = default;
};

struct TelemetrySnapshot {
    uint64_t rss_bytes{0U};
    double rss_megabytes{0.0};
    double cpu_percent{0.0};
    std::size_t active_ratchet_sessions{0U};
    std::size_t pending_outbox_count{0U};
    std::size_t pending_retry_count{0U};
    std::size_t active_file_transfers{0U};
    ConnectivityState connectivity_state{ConnectivityState::Online};
    bool live_gateway_transport{false};
    int64_t last_gateway_rtt_ms{0};
    int64_t avg_gateway_rtt_ms{0};
    uint64_t gateway_requests_total{0U};
    uint64_t gateway_requests_failed{0U};
    int64_t sampled_at_ms{0};

    [[nodiscard]] std::string to_json() const;

    bool operator==(const TelemetrySnapshot& other) const noexcept = default;
};

struct DiagnosticBundleExportResult {
    std::string output_path{};
    std::size_t plaintext_bytes{0U};
    std::size_t encrypted_bytes{0U};
    std::string bundle_sha256_hex{};
    bool used_passphrase{false};
    common::configuration::SecretString generated_export_key_hex{};

    bool operator==(const DiagnosticBundleExportResult& other) const noexcept = default;
};

} // namespace securecloud::client::domain
