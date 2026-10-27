#include "security/grpc_producer_identity_validator.hpp"

namespace securecloud::audit::security {

domain::PeerIdentity GrpcProducerIdentityValidator::extract_peer_identity(
    const grpc::ServerContext& context) {

    domain::PeerIdentity peer{};
    auto auth_ctx = context.auth_context();

    if (auth_ctx && auth_ctx->IsPeerAuthenticated()) {
        peer.is_authenticated = true;

        // Extract Common Name (CN)
        auto cn_props = auth_ctx->FindPropertyValues("x509_common_name");
        if (!cn_props.empty()) {
            peer.common_name = std::string(cn_props.front().data(), cn_props.front().size());
        }

        // Extract Subject Alternative Names (SAN)
        auto san_props = auth_ctx->FindPropertyValues("x509_subject_alternative_name");
        for (const auto& san : san_props) {
            peer.san_dns_names.emplace_back(san.data(), san.size());
        }
    }

    return peer;
}

grpc::Status GrpcProducerIdentityValidator::validate_peer_context(
    const grpc::ServerContext& context,
    domain::ProducerService declared_producer) {

    domain::PeerIdentity peer = extract_peer_identity(context);

    auto validation_res = domain::ProducerIdentityValidator::validate_producer_authorization(
        declared_producer, peer);

    if (validation_res.is_valid()) {
        return grpc::Status::OK;
    }

    if (!peer.is_authenticated) {
        return grpc::Status(
            grpc::StatusCode::UNAUTHENTICATED,
            "Authentication required: missing or unverified mTLS peer certificate"
        );
    }

    return grpc::Status(
        grpc::StatusCode::PERMISSION_DENIED,
        "Producer identity mismatch: mTLS identity does not match declared producer_service"
    );
}

grpc::Status GrpcProducerIdentityValidator::validate_peer_context(
    const grpc::ServerContext& context,
    const std::string& declared_producer) {

    auto prod_enum_opt = domain::producer_from_string(declared_producer);
    if (!prod_enum_opt.has_value()) {
        return grpc::Status(
            grpc::StatusCode::INVALID_ARGUMENT,
            "Invalid declared producer_service value"
        );
    }

    return validate_peer_context(context, *prod_enum_opt);
}

} // namespace securecloud::audit::security