#include "securecloud/grpc/caller_context.hpp"

#include "securecloud/security/mtls_config.hpp"

#include <cctype>

namespace securecloud::common::rpc {

namespace {

constexpr size_t k_uuid_length = 36;
constexpr size_t k_uuid_hyphen_pos1 = 8;
constexpr size_t k_uuid_hyphen_pos2 = 13;
constexpr size_t k_uuid_hyphen_pos3 = 18;
constexpr size_t k_uuid_hyphen_pos4 = 23;

bool is_hex_char(char c) noexcept {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

} // namespace

bool is_valid_uuid(std::string_view id) noexcept {
    if (id.size() != k_uuid_length) {
        return false;
    }

    if (id[k_uuid_hyphen_pos1] != '-' || id[k_uuid_hyphen_pos2] != '-' || id[k_uuid_hyphen_pos3] != '-' ||
        id[k_uuid_hyphen_pos4] != '-') {
        return false;
    }

    for (size_t i = 0; i < k_uuid_length; ++i) {
        if (i == k_uuid_hyphen_pos1 || i == k_uuid_hyphen_pos2 || i == k_uuid_hyphen_pos3 || i == k_uuid_hyphen_pos4) {
            continue;
        }
        if (!is_hex_char(id[i])) {
            return false;
        }
    }

    return true;
}

std::string extract_peer_identity(const ::grpc::AuthContext* auth_context) {
    if (!auth_context || !auth_context->IsPeerAuthenticated()) {
        return "anonymous";
    }

    auto peer_opt = security::extract_peer_service_identity(*auth_context);
    return peer_opt.value_or("unknown_peer");
}

bool is_authorized_service_peer(std::string_view peer_identity) noexcept {
    return peer_identity == "gateway" || peer_identity == "auth" || peer_identity == "messaging" ||
           peer_identity == "files";
}

bool is_authorized_service_peer(const ::grpc::AuthContext* auth_context) {
    if (!auth_context || !auth_context->IsPeerAuthenticated()) {
        return false;
    }
    return is_authorized_service_peer(extract_peer_identity(auth_context));
}

bool is_authorized_service_peer(const ::grpc::ServerContext* context) {
    if (!context) {
        return false;
    }
    return is_authorized_service_peer(context->auth_context().get());
}

std::string_view get_metadata_value(const std::multimap<::grpc::string_ref, ::grpc::string_ref>& metadata,
                                    std::string_view key) noexcept {
    for (const auto& [k, v] : metadata) {
        if (std::string_view(k.data(), k.size()) == key) {
            return {v.data(), v.size()};
        }
    }
    return {};
}

CallerContext extract_caller_context(const ::grpc::ServerContext* context) {
    CallerContext result;
    if (!context) {
        return result;
    }

    const auto& metadata = context->client_metadata();

    // 1. Correlation ID (x-correlation-id with fallback to x-request-id)
    auto corr_id = get_metadata_value(metadata, k_header_correlation_id);
    if (!corr_id.empty()) {
        result.correlation_id.assign(corr_id);
    } else {
        auto req_id = get_metadata_value(metadata, k_header_request_id);
        if (!req_id.empty()) {
            result.correlation_id.assign(req_id);
        }
    }

    // 2. User ID
    auto user_id = get_metadata_value(metadata, k_header_user_id);
    if (!user_id.empty()) {
        result.user_id.assign(user_id);
    }

    // 3. Device ID
    auto device_id = get_metadata_value(metadata, k_header_device_id);
    if (!device_id.empty()) {
        result.device_id.assign(device_id);
    }

    // 4. Peer SAN identity
    result.peer_identity = extract_peer_identity(context->auth_context().get());

    return result;
}

} // namespace securecloud::common::rpc
