#include "security/producer_identity_validator.hpp"
#include "domain/enums.hpp"

#include <algorithm>
#include <cctype>

namespace securecloud::audit::security {

namespace {

std::string to_lower(std::string_view input) {
    std::string result(input);
    std::transform(result.begin(), result.end(), result.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return result;
}

} // namespace

std::optional<std::string> ProducerIdentityValidator::extract_peer_identity(
    const grpc::ServerContext& context) {

    auto auth_ctx = context.auth_context();
    if (!auth_ctx || !auth_ctx->IsPeerAuthenticated()) {
        return std::nullopt;
    }

    // Priority 1: SAN (Subject Alternative Name)
    auto san_properties = auth_ctx->FindPropertyValues("x509_subject_alternative_name");
    if (!san_properties.empty()) {
        const auto& san_ref = san_properties.front();
        return std::string(san_ref.data(), san_ref.size());
    }

    // Priority 2: CN (Common Name)
    auto cn_properties = auth_ctx->FindPropertyValues("x509_common_name");
    if (!cn_properties.empty()) {
        const auto& cn_ref = cn_properties.front();
        return std::string(cn_ref.data(), cn_ref.size());
    }

    return std::nullopt;
}

std::optional<std::string> ProducerIdentityValidator::map_san_to_producer_service(
    std::string_view san_identity) {

    std::string lower_san = to_lower(san_identity);

    if (lower_san == "gateway.securecloud.internal") return "gateway";
    if (lower_san == "auth.securecloud.internal") return "auth";
    if (lower_san == "messaging.securecloud.internal") return "messaging";
    if (lower_san == "files.securecloud.internal") return "files";
    if (lower_san == "audit.securecloud.internal") return "audit";

    return std::nullopt;
}

bool ProducerIdentityValidator::validate_producer_identity(
    const std::string& cert_identity,
    const std::string& declared_producer) {

    auto mapped_service_opt = map_san_to_producer_service(cert_identity);
    if (!mapped_service_opt.has_value()) {
        return false;
    }

    std::string lower_declared = to_lower(declared_producer);

    // Direct match between declared name and extracted service name
    if (*mapped_service_opt == lower_declared) {
        return true;
    }

    // Domain enum normalization to tolerate casing or formatting differences
    auto cert_prod = domain::producer_from_string(*mapped_service_opt);
    auto decl_prod = domain::producer_from_string(declared_producer);

    return cert_prod.has_value() && decl_prod.has_value() && (*cert_prod == *decl_prod);
}

grpc::Status ProducerIdentityValidator::validate_peer_context(
    const grpc::ServerContext& context,
    const std::string& declared_producer) {

    auto peer_identity_opt = extract_peer_identity(context);
    if (!peer_identity_opt.has_value()) {
        return grpc::Status(
            grpc::StatusCode::UNAUTHENTICATED,
            "Authentication required: missing or unverified mTLS peer certificate"
        );
    }

    if (!validate_producer_identity(*peer_identity_opt, declared_producer)) {
        return grpc::Status(
            grpc::StatusCode::PERMISSION_DENIED,
            "Producer identity mismatch: mTLS identity does not match declared producer_service"
        );
    }

    return grpc::Status::OK;
}

} // namespace securecloud::audit::security