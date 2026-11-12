#include "application/managers/safety_number_engine.hpp"

#include <algorithm>
#include <sstream>

namespace securecloud::client::application::managers {

namespace {

std::string strip_whitespace(std::string_view str) {
    std::string out;
    out.reserve(str.size());
    for (char c : str) {
        if (!std::isspace(static_cast<unsigned char>(c))) {
            out.push_back(c);
        }
    }
    return out;
}

} // namespace

SafetyNumberEngine::SafetyNumberEngine(interfaces::ICryptoProvider& crypto_provider,
                                       interfaces::ISecureStorage& secure_storage)
    : crypto_provider_(crypto_provider), secure_storage_(secure_storage) {}

ClientResult<std::string> SafetyNumberEngine::compute_safety_number(const domain::UserId& local_user_id,
                                                                    std::span<const uint8_t> local_identity_key,
                                                                    const domain::UserId& peer_user_id,
                                                                    std::span<const uint8_t> peer_identity_key) {
    if (local_user_id.empty() || peer_user_id.empty()) {
        return ClientResult<std::string>::error(
            ClientError::validation("User IDs cannot be empty for safety number computation"));
    }
    if (local_identity_key.empty() || peer_identity_key.empty()) {
        return ClientResult<std::string>::error(
            ClientError::validation("Identity keys cannot be empty for safety number computation"));
    }

    auto comp_res =
        crypto_provider_.compute_safety_number(local_user_id, local_identity_key, peer_user_id, peer_identity_key);
    if (!comp_res.is_ok()) {
        return ClientResult<std::string>::error(comp_res.error());
    }

    return ClientResult<std::string>::ok(format_safety_number(comp_res.value()));
}

std::string SafetyNumberEngine::format_safety_number(std::string_view raw_digits) {
    std::string clean = strip_whitespace(raw_digits);
    if (clean.size() != 60) {
        return std::string(raw_digits);
    }

    std::ostringstream oss;
    for (std::size_t i = 0; i < 12; ++i) {
        if (i > 0) {
            oss << ' ';
        }
        oss << clean.substr(i * 5, 5);
    }
    return oss.str();
}

ClientResult<domain::KeyVerificationStatus>
SafetyNumberEngine::evaluate_key_verification_status(const domain::UserId& peer_user_id,
                                                     std::span<const uint8_t> peer_identity_key) {
    if (peer_user_id.empty()) {
        return ClientResult<domain::KeyVerificationStatus>::error(
            ClientError::validation("Peer user ID cannot be empty to evaluate verification status"));
    }
    if (peer_identity_key.empty()) {
        return ClientResult<domain::KeyVerificationStatus>::error(
            ClientError::validation("Peer identity key cannot be empty to evaluate verification status"));
    }

    auto fp_res = crypto_provider_.compute_identity_fingerprint(peer_identity_key);
    if (!fp_res.is_ok()) {
        return ClientResult<domain::KeyVerificationStatus>::error(fp_res.error());
    }
    const auto& current_fp = fp_res.value();

    std::string storage_key = std::string(kVerifiedKeyPrefix) + std::string(peer_user_id.str());
    auto stored_res = secure_storage_.get_secret(storage_key);

    if (!stored_res.is_ok()) {
        // No stored verification record exists
        return ClientResult<domain::KeyVerificationStatus>::ok(domain::KeyVerificationStatus::Unverified);
    }

    const auto stored_fp = stored_res.value().expose_unredacted_secret();
    if (stored_fp == current_fp) {
        return ClientResult<domain::KeyVerificationStatus>::ok(domain::KeyVerificationStatus::Verified);
    }

    // Key was previously verified, but active public key fingerprint differs: KeyChanged!
    return ClientResult<domain::KeyVerificationStatus>::ok(domain::KeyVerificationStatus::KeyChanged);
}

ClientResult<void> SafetyNumberEngine::set_verification_state(const domain::UserId& peer_user_id,
                                                              std::span<const uint8_t> peer_identity_key,
                                                              bool verified) {
    if (peer_user_id.empty()) {
        return ClientResult<void>::error(
            ClientError::validation("Peer user ID cannot be empty to set verification state"));
    }

    std::string storage_key = std::string(kVerifiedKeyPrefix) + std::string(peer_user_id.str());

    if (!verified) {
        secure_storage_.delete_secret(storage_key);
        return ClientResult<void>::ok();
    }

    if (peer_identity_key.empty()) {
        return ClientResult<void>::error(
            ClientError::validation("Peer identity key cannot be empty to mark as verified"));
    }

    auto fp_res = crypto_provider_.compute_identity_fingerprint(peer_identity_key);
    if (!fp_res.is_ok()) {
        return ClientResult<void>::error(fp_res.error());
    }

    auto store_res =
        secure_storage_.store_secret(storage_key, securecloud::common::configuration::SecretString(fp_res.value()));
    if (!store_res.is_ok()) {
        return ClientResult<void>::error(store_res.error());
    }

    return ClientResult<void>::ok();
}

ClientResult<std::optional<std::string>>
SafetyNumberEngine::get_verified_fingerprint(const domain::UserId& peer_user_id) const {
    if (peer_user_id.empty()) {
        return ClientResult<std::optional<std::string>>::error(ClientError::validation("Peer user ID cannot be empty"));
    }

    std::string storage_key = std::string(kVerifiedKeyPrefix) + std::string(peer_user_id.str());
    auto stored_res = secure_storage_.get_secret(storage_key);
    if (!stored_res.is_ok()) {
        return ClientResult<std::optional<std::string>>::ok(std::nullopt);
    }

    return ClientResult<std::optional<std::string>>::ok(stored_res.value().expose_unredacted_secret());
}

std::string SafetyNumberEngine::generate_verification_uri(const domain::UserId& local_user_id,
                                                          const domain::UserId& peer_user_id,
                                                          std::string_view formatted_safety_number) {
    std::string clean_sn = strip_whitespace(formatted_safety_number);
    return "securecloud://verify?v=1&u1=" + std::string(local_user_id.str()) +
           "&u2=" + std::string(peer_user_id.str()) + "&sn=" + clean_sn;
}

ClientResult<SafetyNumberEngine::ParsedVerificationUri>
SafetyNumberEngine::parse_verification_uri(std::string_view uri_str) {
    constexpr std::string_view kPrefix = "securecloud://verify?";
    if (!uri_str.starts_with(kPrefix)) {
        return ClientResult<ParsedVerificationUri>::error(
            ClientError::validation("Invalid verification URI scheme, expected prefix securecloud://verify?"));
    }

    std::string_view query = uri_str.substr(kPrefix.size());
    std::string u1;
    std::string u2;
    std::string sn;
    std::string v;

    std::size_t start = 0;
    while (start < query.size()) {
        auto amp = query.find('&', start);
        std::string_view param =
            (amp == std::string_view::npos) ? query.substr(start) : query.substr(start, amp - start);
        auto eq = param.find('=');
        if (eq != std::string_view::npos) {
            auto key = param.substr(0, eq);
            auto val = param.substr(eq + 1);
            if (key == "v") {
                v = std::string(val);
            } else if (key == "u1") {
                u1 = std::string(val);
            } else if (key == "u2") {
                u2 = std::string(val);
            } else if (key == "sn") {
                sn = std::string(val);
            }
        }
        if (amp == std::string_view::npos) {
            break;
        }
        start = amp + 1;
    }

    if (v != "1") {
        return ClientResult<ParsedVerificationUri>::error(
            ClientError::validation("Unsupported or missing verification URI version"));
    }
    if (u1.empty() || u2.empty() || sn.empty()) {
        return ClientResult<ParsedVerificationUri>::error(
            ClientError::validation("Verification URI missing mandatory parameters (u1, u2, sn)"));
    }

    ParsedVerificationUri result{
        .user1 = domain::UserId(std::move(u1)),
        .user2 = domain::UserId(std::move(u2)),
        .safety_number = format_safety_number(sn),
    };
    return ClientResult<ParsedVerificationUri>::ok(std::move(result));
}

} // namespace securecloud::client::application::managers
