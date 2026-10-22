#include "service/protocol_version_policy.hpp"

namespace securecloud::messaging::service {

bool ProtocolVersionPolicy::is_supported_protocol_version(int32_t version_raw) noexcept {
    auto version_opt = domain::e2e_protocol_version_from_int(version_raw);
    if (!version_opt.has_value()) {
        return false;
    }
    return is_supported_protocol_version(version_opt.value());
}

bool ProtocolVersionPolicy::is_supported_protocol_version(domain::E2EProtocolVersion version) noexcept {
    switch (version) {
    case domain::E2EProtocolVersion::V1_Signal_PQXDH_DoubleRatchet:
    case domain::E2EProtocolVersion::V2_Hybrid_PostQuantum:
        return true;
    case domain::E2EProtocolVersion::Unspecified:
    default:
        return false;
    }
}

bool ProtocolVersionPolicy::is_approved_algorithm(std::string_view algo_str) noexcept {
    auto algo_opt = domain::e2e_algorithm_from_string(algo_str);
    if (!algo_opt.has_value()) {
        return false;
    }
    return is_approved_algorithm(algo_opt.value());
}

bool ProtocolVersionPolicy::is_approved_algorithm(domain::E2EAlgorithm algo) noexcept {
    switch (algo) {
    case domain::E2EAlgorithm::XChaCha20_Poly1305:
    case domain::E2EAlgorithm::AES_256_GCM:
        return true;
    case domain::E2EAlgorithm::Unspecified:
    default:
        return false;
    }
}

size_t ProtocolVersionPolicy::get_minimum_iv_size(domain::E2EAlgorithm algo) noexcept {
    switch (algo) {
    case domain::E2EAlgorithm::XChaCha20_Poly1305:
        return k_min_xchacha20_iv_bytes;
    case domain::E2EAlgorithm::AES_256_GCM:
        return k_min_aes_gcm_iv_bytes;
    case domain::E2EAlgorithm::Unspecified:
    default:
        return 0;
    }
}

size_t ProtocolVersionPolicy::get_minimum_auth_tag_size(domain::E2EAlgorithm algo) noexcept {
    switch (algo) {
    case domain::E2EAlgorithm::XChaCha20_Poly1305:
    case domain::E2EAlgorithm::AES_256_GCM:
        return k_min_auth_tag_bytes;
    case domain::E2EAlgorithm::Unspecified:
    default:
        return 0;
    }
}

size_t ProtocolVersionPolicy::get_minimum_ephemeral_key_size(domain::E2EAlgorithm algo) noexcept {
    switch (algo) {
    case domain::E2EAlgorithm::XChaCha20_Poly1305:
    case domain::E2EAlgorithm::AES_256_GCM:
        return k_min_ephemeral_key_bytes;
    case domain::E2EAlgorithm::Unspecified:
    default:
        return 0;
    }
}

std::string_view ProtocolVersionPolicy::get_canonical_algorithm_name(domain::E2EAlgorithm algo) noexcept {
    switch (algo) {
    case domain::E2EAlgorithm::XChaCha20_Poly1305:
        return "XChaCha20-Poly1305";
    case domain::E2EAlgorithm::AES_256_GCM:
        return "AES-256-GCM";
    case domain::E2EAlgorithm::Unspecified:
    default:
        return "UNSPECIFIED";
    }
}

std::optional<std::string>
ProtocolVersionPolicy::validate_envelope_security(const domain::PerDeviceEnvelope& envelope) {
    if (!is_supported_protocol_version(envelope.protocol_version)) {
        return "Unsupported or deprecated E2E protocol version: " + to_string(envelope.protocol_version);
    }

    if (!is_approved_algorithm(envelope.algorithm)) {
        return "Unapproved cryptographic algorithm: " + to_string(envelope.algorithm);
    }

    if (envelope.ciphertext_blob.empty()) {
        return "Ciphertext blob cannot be empty";
    }

    if (envelope.ciphertext_blob.size() > k_max_ciphertext_bytes) {
        return "Ciphertext blob size (" + std::to_string(envelope.ciphertext_blob.size()) +
               " bytes) exceeds maximum permitted limit (" + std::to_string(k_max_ciphertext_bytes) + " bytes)";
    }

    const size_t min_iv = get_minimum_iv_size(envelope.algorithm);
    if (envelope.iv.size() < min_iv) {
        return "Initialization vector (IV) size (" + std::to_string(envelope.iv.size()) +
               " bytes) is smaller than required minimum (" + std::to_string(min_iv) + " bytes) for " +
               std::string(get_canonical_algorithm_name(envelope.algorithm));
    }

    const size_t min_tag = get_minimum_auth_tag_size(envelope.algorithm);
    if (envelope.auth_tag.size() < min_tag) {
        return "Authentication tag size (" + std::to_string(envelope.auth_tag.size()) +
               " bytes) is smaller than required minimum (" + std::to_string(min_tag) + " bytes)";
    }

    const size_t min_key = get_minimum_ephemeral_key_size(envelope.algorithm);
    if (envelope.ephemeral_public_key.size() < min_key) {
        return "Ephemeral public key size (" + std::to_string(envelope.ephemeral_public_key.size()) +
               " bytes) is smaller than required minimum (" + std::to_string(min_key) + " bytes)";
    }

    return std::nullopt;
}

} // namespace securecloud::messaging::service
