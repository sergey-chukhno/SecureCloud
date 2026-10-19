#pragma once

#include "gateway_config.hpp"
#include "securecloud/security/mtls_config.hpp"

#include <chrono>
#include <cstddef>
#include <grpcpp/grpcpp.h>
#include <map>
#include <memory>
#include <mutex>
#include <string>

namespace securecloud::gateway::grpc {

class GrpcChannelManager {
  public:
    static constexpr const char* k_service_auth = "auth";
    static constexpr const char* k_service_messaging = "messaging";
    static constexpr const char* k_service_files = "files";
    static constexpr const char* k_service_audit = "audit";

    explicit GrpcChannelManager(const GatewayConfig& config);

    GrpcChannelManager(common::security::SecurityCredentialsConfig creds, std::string auth_ep, std::string messaging_ep,
                       std::string files_ep, std::string audit_ep);

    ~GrpcChannelManager();

    GrpcChannelManager(const GrpcChannelManager&) = delete;
    GrpcChannelManager& operator=(const GrpcChannelManager&) = delete;
    GrpcChannelManager(GrpcChannelManager&&) = delete;
    GrpcChannelManager& operator=(GrpcChannelManager&&) = delete;

    [[nodiscard]] std::shared_ptr<::grpc::Channel> get_channel(const std::string& service_name);

    [[nodiscard]] std::shared_ptr<::grpc::Channel> get_auth_channel();
    [[nodiscard]] std::shared_ptr<::grpc::Channel> get_messaging_channel();
    [[nodiscard]] std::shared_ptr<::grpc::Channel> get_files_channel();
    [[nodiscard]] std::shared_ptr<::grpc::Channel> get_audit_channel();

    [[nodiscard]] grpc_connectivity_state get_connection_state(const std::string& service_name,
                                                               bool try_to_connect = false) noexcept;

    [[nodiscard]] bool is_channel_ready(const std::string& service_name) noexcept;
    [[nodiscard]] bool is_channel_healthy(const std::string& service_name) noexcept;

    [[nodiscard]] bool wait_for_connected(const std::string& service_name,
                                          std::chrono::milliseconds timeout = std::chrono::milliseconds(2000)) noexcept;

    [[nodiscard]] bool check_connectivity(const std::string& service_name,
                                          std::chrono::milliseconds timeout = std::chrono::milliseconds(2000)) noexcept;

    bool reconnect(const std::string& service_name) noexcept;

    void reset() noexcept;

    [[nodiscard]] size_t cached_channel_count() const noexcept;

  private:
    [[nodiscard]] std::shared_ptr<::grpc::Channel> create_channel_for_service(const std::string& service_name);
    [[nodiscard]] static std::string get_expected_san(const std::string& service_name);

    common::security::SecurityCredentialsConfig credentials_config_;
    std::map<std::string, std::string> endpoints_;
    mutable std::mutex channels_mutex_;
    std::map<std::string, std::shared_ptr<::grpc::Channel>> channels_;
};

} // namespace securecloud::gateway::grpc
