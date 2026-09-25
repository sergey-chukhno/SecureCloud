#include "grpc/channel_manager.hpp"

#include <chrono>
#include <grpcpp/grpcpp.h>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <utility>

namespace securecloud::gateway::grpc {
namespace {

constexpr int k_keepalive_time_ms = 30000;
constexpr int k_keepalive_timeout_ms = 10000;
constexpr const char* k_user_agent_prefix = "securecloud-gateway/1.0";

} // namespace

GrpcChannelManager::GrpcChannelManager(const GatewayConfig& config)
    : GrpcChannelManager(config.common.tls_credentials, config.auth_endpoint, config.messaging_endpoint,
                         config.files_endpoint, config.audit_endpoint) {}

GrpcChannelManager::GrpcChannelManager(common::security::SecurityCredentialsConfig creds, std::string auth_ep,
                                       std::string messaging_ep, std::string files_ep, std::string audit_ep)
    : credentials_config_(std::move(creds)) {
    endpoints_[k_service_auth] = std::move(auth_ep);
    endpoints_[k_service_messaging] = std::move(messaging_ep);
    endpoints_[k_service_files] = std::move(files_ep);
    endpoints_[k_service_audit] = std::move(audit_ep);
}

GrpcChannelManager::~GrpcChannelManager() {
    reset();
}

std::string GrpcChannelManager::get_expected_san(const std::string& service_name) {
    if (service_name == k_service_auth) {
        return "auth";
    }
    if (service_name == k_service_messaging) {
        return "messaging";
    }
    if (service_name == k_service_files) {
        return "files";
    }
    if (service_name == k_service_audit) {
        return "audit";
    }
    return service_name;
}

std::shared_ptr<::grpc::Channel> GrpcChannelManager::create_channel_for_service(const std::string& service_name) {
    auto it = endpoints_.find(service_name);
    if (it == endpoints_.end() || it->second.empty()) {
        return nullptr;
    }

    const std::string& target_address = it->second;
    std::string expected_san = get_expected_san(service_name);

    auto creds = common::security::MtlsCredentialLoader::create_client_credentials(credentials_config_);
    if (!creds) {
        return nullptr;
    }

    ::grpc::ChannelArguments channel_args;
    channel_args.SetUserAgentPrefix(k_user_agent_prefix);
    channel_args.SetInt(GRPC_ARG_KEEPALIVE_TIME_MS, k_keepalive_time_ms);
    channel_args.SetInt(GRPC_ARG_KEEPALIVE_TIMEOUT_MS, k_keepalive_timeout_ms);
    channel_args.SetInt(GRPC_ARG_KEEPALIVE_PERMIT_WITHOUT_CALLS, 1);
    if (!expected_san.empty()) {
        channel_args.SetSslTargetNameOverride(expected_san);
    }

    return ::grpc::CreateCustomChannel(target_address, creds, channel_args);
}

std::shared_ptr<::grpc::Channel> GrpcChannelManager::get_channel(const std::string& service_name) {
    std::scoped_lock lock(channels_mutex_);
    auto it = channels_.find(service_name);
    if (it != channels_.end()) {
        return it->second;
    }

    auto channel = create_channel_for_service(service_name);
    if (channel) {
        channels_[service_name] = channel;
    }
    return channel;
}

std::shared_ptr<::grpc::Channel> GrpcChannelManager::get_auth_channel() {
    return get_channel(k_service_auth);
}

std::shared_ptr<::grpc::Channel> GrpcChannelManager::get_messaging_channel() {
    return get_channel(k_service_messaging);
}

std::shared_ptr<::grpc::Channel> GrpcChannelManager::get_files_channel() {
    return get_channel(k_service_files);
}

std::shared_ptr<::grpc::Channel> GrpcChannelManager::get_audit_channel() {
    return get_channel(k_service_audit);
}

bool GrpcChannelManager::check_connectivity(const std::string& service_name,
                                            std::chrono::milliseconds timeout) noexcept {
    try {
        auto channel = get_channel(service_name);
        if (!channel) {
            return false;
        }

        auto current_state = channel->GetState(true);
        if (current_state == GRPC_CHANNEL_READY) {
            return true;
        }

        auto deadline = std::chrono::system_clock::now() + timeout;
        return channel->WaitForConnected(deadline);
    } catch (...) {
        return false;
    }
}

void GrpcChannelManager::reset() noexcept {
    std::scoped_lock lock(channels_mutex_);
    channels_.clear();
}

size_t GrpcChannelManager::cached_channel_count() const noexcept {
    std::scoped_lock lock(channels_mutex_);
    return channels_.size();
}

} // namespace securecloud::gateway::grpc
