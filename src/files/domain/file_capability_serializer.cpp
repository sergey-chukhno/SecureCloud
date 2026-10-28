#include "files/domain/file_capability_serializer.hpp"

#include <chrono>
#include <nlohmann/json.hpp>
#include <sstream>

namespace securecloud::files {

namespace {

using json = nlohmann::json;

void record_error(std::string* error_out, std::string msg) {
    if (error_out != nullptr) {
        *error_out = std::move(msg);
    }
}

} // namespace

std::string FileCapabilitySerializer::serialize(const FileAccessCapabilityClaims& claims,
                                                const auth::crypto::ITokenSigner& signer) {
    // 1. Header JSON
    json header_json = {{"alg", "EdDSA"}, {"typ", "sc-file-cap/v1"}, {"kid", signer.get_key_id()}};
    const std::string header_b64 = auth::crypto::Base64Url::encode(header_json.dump());

    // 2. Payload JSON
    const auto iat_sec = std::chrono::duration_cast<std::chrono::seconds>(claims.issued_at.time_since_epoch()).count();
    const auto exp_sec = std::chrono::duration_cast<std::chrono::seconds>(claims.expires_at.time_since_epoch()).count();

    json payload_json = {{"cap_id", claims.capability_id},
                         {"uid", claims.user_id},
                         {"did", claims.device_id},
                         {"fid", claims.file_id},
                         {"ver", claims.file_version},
                         {"op", std::string(to_string(claims.operation))},
                         {"iat", iat_sec},
                         {"exp", exp_sec},
                         {"iss", claims.issuer}};
    const std::string payload_b64 = auth::crypto::Base64Url::encode(payload_json.dump());

    // 3. Signing Input and Cryptographic Signature
    const std::string signing_input = header_b64 + "." + payload_b64;
    const std::string signature_b64 = signer.sign(signing_input);

    return signing_input + "." + signature_b64;
}

std::optional<FileAccessCapabilityClaims>
FileCapabilitySerializer::deserialize_and_verify(std::string_view token, const auth::crypto::ITokenVerifier& verifier,
                                                 std::string* error_out) {
    // 1. Structural validation: token must consist of exactly three dot-separated parts
    const auto first_dot = token.find('.');
    if (first_dot == std::string_view::npos) {
        record_error(error_out, "Malformed capability token: missing header/payload delimiter");
        return std::nullopt;
    }

    const auto second_dot = token.find('.', first_dot + 1);
    if (second_dot == std::string_view::npos) {
        record_error(error_out, "Malformed capability token: missing payload/signature delimiter");
        return std::nullopt;
    }

    if (token.find('.', second_dot + 1) != std::string_view::npos) {
        record_error(error_out, "Malformed capability token: unexpected extraneous segments");
        return std::nullopt;
    }

    const std::string_view header_b64 = token.substr(0, first_dot);
    const std::string_view payload_b64 = token.substr(first_dot + 1, second_dot - first_dot - 1);
    const std::string_view signature_b64 = token.substr(second_dot + 1);

    if (header_b64.empty() || payload_b64.empty() || signature_b64.empty()) {
        record_error(error_out, "Malformed capability token: contains empty segment");
        return std::nullopt;
    }

    // 2. Cryptographic signature verification over signing input
    const std::string_view signing_input = token.substr(0, second_dot);
    if (!verifier.verify(signing_input, signature_b64)) {
        record_error(error_out, "Invalid cryptographic signature: capability has been tampered with or key mismatch");
        return std::nullopt;
    }

    // 3. Decode and parse Header JSON
    auto header_decoded = auth::crypto::Base64Url::decode(header_b64);
    if (!header_decoded.has_value()) {
        record_error(error_out, "Malformed capability token: header is not valid Base64URL");
        return std::nullopt;
    }

    try {
        auto header_json = json::parse(*header_decoded);
        if (!header_json.contains("alg") || header_json["alg"] != "EdDSA") {
            record_error(error_out, "Unsupported or missing signature algorithm in capability header");
            return std::nullopt;
        }
    } catch (const std::exception& ex) {
        record_error(error_out, std::string("Malformed JSON in capability header: ") + ex.what());
        return std::nullopt;
    }

    // 4. Decode and parse Payload JSON
    auto payload_decoded = auth::crypto::Base64Url::decode(payload_b64);
    if (!payload_decoded.has_value()) {
        record_error(error_out, "Malformed capability token: payload is not valid Base64URL");
        return std::nullopt;
    }

    json payload_json;
    try {
        payload_json = json::parse(*payload_decoded);
    } catch (const std::exception& ex) {
        record_error(error_out, std::string("Malformed JSON in capability payload: ") + ex.what());
        return std::nullopt;
    }

    // 5. Validate required claims presence and types
    static const char* kRequiredFields[] = {"cap_id", "uid", "did", "fid", "op", "iat", "exp"};
    for (const char* field : kRequiredFields) {
        if (!payload_json.contains(field)) {
            record_error(error_out, std::string("Missing required claim in capability payload: ") + field);
            return std::nullopt;
        }
    }

    std::string op_str;
    try {
        op_str = payload_json["op"].get<std::string>();
    } catch (...) {
        record_error(error_out, "Invalid type for 'op' claim");
        return std::nullopt;
    }

    auto op_opt = file_capability_operation_from_string(op_str);
    if (!op_opt.has_value()) {
        record_error(error_out, "Unknown file capability operation: " + op_str);
        return std::nullopt;
    }

    FileAccessCapabilityClaims claims;
    try {
        claims.capability_id = payload_json["cap_id"].get<std::string>();
        claims.user_id = payload_json["uid"].get<std::string>();
        claims.device_id = payload_json["did"].get<std::string>();
        claims.file_id = payload_json["fid"].get<std::string>();
        claims.file_version = payload_json.value("ver", 0);
        claims.operation = *op_opt;

        int64_t iat_sec = payload_json["iat"].get<int64_t>();
        int64_t exp_sec = payload_json["exp"].get<int64_t>();
        claims.issued_at = std::chrono::system_clock::time_point(std::chrono::seconds(iat_sec));
        claims.expires_at = std::chrono::system_clock::time_point(std::chrono::seconds(exp_sec));

        claims.issuer = payload_json.value("iss", "securecloud-files");
    } catch (const std::exception& ex) {
        record_error(error_out, std::string("Error reading capability claims: ") + ex.what());
        return std::nullopt;
    }

    return claims;
}

} // namespace securecloud::files
