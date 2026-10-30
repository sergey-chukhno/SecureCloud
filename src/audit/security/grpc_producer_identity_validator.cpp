#include "security/grpc_producer_identity_validator.hpp"

#include "domain/enums.hpp"
#include "domain/producer_identity_validator.hpp"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <string_view>

namespace securecloud::audit::security {

namespace {

std::atomic<bool> g_bypass_peer_verification{false};

} // namespace

void GrpcProducerIdentityValidator::set_bypass_peer_verification_for_testing(bool bypass) noexcept {
    g_bypass_peer_verification.store(bypass, std::memory_order_relaxed);
}

domain::PeerIdentity GrpcProducerIdentityValidator::extract_peer_identity(const grpc::ServerContext& context) {
    domain::PeerIdentity identity{};
    auto auth_ctx = context.auth_context();
    if (!auth_ctx || !auth_ctx->IsPeerAuthenticated()) {
        identity.is_authenticated = false;
        return identity;
    }
    identity.is_authenticated = true;

    auto cns = auth_ctx->FindPropertyValues("x509_common_name");
    if (!cns.empty()) {
        identity.common_name = std::string(cns[0].data(), cns[0].size());
    }

    auto sans = auth_ctx->FindPropertyValues("x509_subject_alternative_name");
    for (const auto& san : sans) {
        std::string_view val(san.data(), san.size());
        if (val.starts_with("DNS:")) {
            identity.san_dns_names.emplace_back(val.substr(4));
        } else if (val.starts_with("URI:")) {
            identity.san_uri_names.emplace_back(val.substr(4));
        } else {
            identity.san_dns_names.emplace_back(val);
        }
    }
    return identity;
}

grpc::Status GrpcProducerIdentityValidator::validate_peer_context(const grpc::ServerContext& context,
                                                                  domain::ProducerService producer_service) {

    if (g_bypass_peer_verification.load(std::memory_order_relaxed)) {
        return grpc::Status::OK;
    }

    auto auth_ctx = context.auth_context();
    if (!auth_ctx || !auth_ctx->IsPeerAuthenticated()) {
        return grpc::Status(grpc::StatusCode::UNAUTHENTICATED,
                            "Authentication required: peer is not authenticated via mTLS");
    }

    auto identity = extract_peer_identity(context);
    auto val_res = domain::ProducerIdentityValidator::validate_producer_authorization(producer_service, identity);

    if (!val_res.is_valid()) {
        const auto& errors = val_res.errors();
        std::string msg =
            errors.empty() ? "mTLS peer identity does not match declared producer service" : errors.front().message;
        return grpc::Status(grpc::StatusCode::PERMISSION_DENIED, msg);
    }

    return grpc::Status::OK;
}

grpc::Status GrpcProducerIdentityValidator::validate_peer_context(const grpc::ServerContext& context,
                                                                  const std::string& declared_producer_service) {

    if (g_bypass_peer_verification.load(std::memory_order_relaxed)) {
        return grpc::Status::OK;
    }

    // Normalize producer service string (e.g., "PRODUCER_SERVICE_AUTH" -> "auth")
    std::string canonical_producer = declared_producer_service;
    if (canonical_producer.rfind("PRODUCER_SERVICE_", 0) == 0) {
        canonical_producer = canonical_producer.substr(17);
    }
    std::transform(canonical_producer.begin(), canonical_producer.end(), canonical_producer.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    auto prod_opt = domain::producer_from_string(canonical_producer);
    if (!prod_opt.has_value()) {
        return grpc::Status(grpc::StatusCode::INVALID_ARGUMENT,
                            "Invalid producer service: " + declared_producer_service);
    }

    return validate_peer_context(context, *prod_opt);
}

} // namespace securecloud::audit::security
