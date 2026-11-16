#include "domain/pairing_challenge_payload.hpp"

#include <cctype>
#include <charconv>
#include <iomanip>
#include <sstream>
#include <unordered_map>

namespace securecloud::client::domain {

namespace {

std::string bytes_to_hex(const std::vector<uint8_t>& bytes) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (uint8_t b : bytes) {
        oss << std::setw(2) << static_cast<unsigned int>(b);
    }
    return oss.str();
}

std::optional<std::vector<uint8_t>> hex_to_bytes(std::string_view hex) {
    if (hex.size() % 2 != 0) {
        return std::nullopt;
    }
    std::vector<uint8_t> bytes;
    bytes.reserve(hex.size() / 2);

    for (std::size_t i = 0; i < hex.size(); i += 2) {
        char high = hex[i];
        char low = hex[i + 1];
        if (!std::isxdigit(static_cast<unsigned char>(high)) || !std::isxdigit(static_cast<unsigned char>(low))) {
            return std::nullopt;
        }

        auto hex_val = [](char c) -> uint8_t {
            if (c >= '0' && c <= '9') {
                return static_cast<uint8_t>(c - '0');
            }
            if (c >= 'a' && c <= 'f') {
                return static_cast<uint8_t>(c - 'a' + 10);
            }
            if (c >= 'A' && c <= 'F') {
                return static_cast<uint8_t>(c - 'A' + 10);
            }
            return 0;
        };

        bytes.push_back(static_cast<uint8_t>((hex_val(high) << 4) | hex_val(low)));
    }
    return bytes;
}

std::string url_encode(std::string_view str) {
    std::ostringstream oss;
    for (char c : str) {
        if (std::isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '_' || c == '.' || c == '~') {
            oss << c;
        } else {
            oss << '%' << std::uppercase << std::hex << std::setw(2) << std::setfill('0')
                << static_cast<unsigned int>(static_cast<unsigned char>(c));
        }
    }
    return oss.str();
}

std::string url_decode(std::string_view str) {
    std::string result;
    result.reserve(str.size());
    for (std::size_t i = 0; i < str.size(); ++i) {
        if (str[i] == '%' && i + 2 < str.size()) {
            char high = str[i + 1];
            char low = str[i + 2];
            if (std::isxdigit(static_cast<unsigned char>(high)) && std::isxdigit(static_cast<unsigned char>(low))) {
                auto hex_val = [](char c) -> int {
                    if (c >= '0' && c <= '9') {
                        return c - '0';
                    }
                    if (c >= 'a' && c <= 'f') {
                        return c - 'a' + 10;
                    }
                    if (c >= 'A' && c <= 'F') {
                        return c - 'A' + 10;
                    }
                    return 0;
                };
                result.push_back(static_cast<char>((hex_val(high) << 4) | hex_val(low)));
                i += 2;
                continue;
            }
        } else if (str[i] == '+') {
            result.push_back(' ');
            continue;
        }
        result.push_back(str[i]);
    }
    return result;
}

} // namespace

PairingChallengePayload::PairingChallengePayload(UserId user_id, DeviceId device_id,
                                                 std::vector<uint8_t> ephemeral_public_key, std::string pairing_code,
                                                 std::chrono::system_clock::time_point expires_at,
                                                 std::string display_name, uint32_t version)
    : version_(version), user_id_(std::move(user_id)), device_id_(std::move(device_id)),
      ephemeral_public_key_(std::move(ephemeral_public_key)), pairing_code_(std::move(pairing_code)),
      expires_at_(expires_at), display_name_(std::move(display_name)) {}

bool PairingChallengePayload::is_expired(std::chrono::system_clock::time_point now) const noexcept {
    return now >= expires_at_;
}

std::string PairingChallengePayload::to_uri() const {
    std::ostringstream oss;
    oss << kUriScheme << "?v=" << version_ << "&uid=" << url_encode(user_id_.str())
        << "&did=" << url_encode(device_id_.str()) << "&code=" << url_encode(pairing_code_)
        << "&pk=" << bytes_to_hex(ephemeral_public_key_);

    auto epoch_sec = std::chrono::duration_cast<std::chrono::seconds>(expires_at_.time_since_epoch()).count();
    oss << "&exp=" << epoch_sec;

    if (!display_name_.empty()) {
        oss << "&name=" << url_encode(display_name_);
    }

    return oss.str();
}

application::ClientResult<PairingChallengePayload> PairingChallengePayload::from_uri(std::string_view uri_str) {
    if (!uri_str.starts_with(kUriScheme) || uri_str.size() <= kUriScheme.size() + 1 ||
        uri_str[kUriScheme.size()] != '?') {
        return application::ClientResult<PairingChallengePayload>::error(application::ClientError::validation(
            "URI does not start with expected scheme: " + std::string(kUriScheme)));
    }

    std::string_view query = uri_str.substr(kUriScheme.size() + 1);
    std::unordered_map<std::string, std::string> params;

    std::size_t start = 0;
    while (start < query.size()) {
        std::size_t amp = query.find('&', start);
        std::string_view pair =
            (amp == std::string_view::npos) ? query.substr(start) : query.substr(start, amp - start);

        std::size_t eq = pair.find('=');
        if (eq != std::string_view::npos) {
            std::string key = url_decode(pair.substr(0, eq));
            std::string val = url_decode(pair.substr(eq + 1));
            params[std::move(key)] = std::move(val);
        }

        if (amp == std::string_view::npos) {
            break;
        }
        start = amp + 1;
    }

    // Validate required fields
    if (!params.contains("v") || !params.contains("uid") || !params.contains("did") || !params.contains("code") ||
        !params.contains("pk") || !params.contains("exp")) {
        return application::ClientResult<PairingChallengePayload>::error(
            application::ClientError::validation("Missing mandatory query parameters in pairing URI"));
    }

    // Version check
    uint32_t version = 0;
    const auto& v_str = params["v"];
    auto [v_ptr, v_ec] = std::from_chars(v_str.data(), v_str.data() + v_str.size(), version);
    if (v_ec != std::errc{} || version == 0) {
        return application::ClientResult<PairingChallengePayload>::error(
            application::ClientError::validation("Invalid protocol version in pairing URI"));
    }

    // User ID & Device ID check
    UserId uid(params["uid"]);
    DeviceId did(params["did"]);
    if (uid.empty() || did.empty()) {
        return application::ClientResult<PairingChallengePayload>::error(
            application::ClientError::validation("User ID and Device ID must not be empty"));
    }

    // Pairing code check
    const std::string& code = params["code"];
    if (code.empty()) {
        return application::ClientResult<PairingChallengePayload>::error(
            application::ClientError::validation("Pairing code cannot be empty"));
    }

    // Public key hex decode
    auto pk_opt = hex_to_bytes(params["pk"]);
    if (!pk_opt.has_value() || pk_opt->size() != 32) {
        return application::ClientResult<PairingChallengePayload>::error(
            application::ClientError::validation("Ephemeral public key must be exactly 32 bytes (64 hex characters)"));
    }

    // Expiration timestamp check
    uint64_t exp_epoch = 0;
    const auto& exp_str = params["exp"];
    auto [exp_ptr, exp_ec] = std::from_chars(exp_str.data(), exp_str.data() + exp_str.size(), exp_epoch);
    if (exp_ec != std::errc{}) {
        return application::ClientResult<PairingChallengePayload>::error(
            application::ClientError::validation("Invalid expiration timestamp in pairing URI"));
    }
    auto expires_at = std::chrono::system_clock::time_point(std::chrono::seconds(exp_epoch));

    std::string display_name = params.contains("name") ? params["name"] : "";

    return application::ClientResult<PairingChallengePayload>::ok(PairingChallengePayload(
        std::move(uid), std::move(did), std::move(*pk_opt), code, expires_at, std::move(display_name), version));
}

bool PairingChallengePayload::operator==(const PairingChallengePayload& other) const noexcept {
    return version_ == other.version_ && user_id_ == other.user_id_ && device_id_ == other.device_id_ &&
           ephemeral_public_key_ == other.ephemeral_public_key_ && pairing_code_ == other.pairing_code_ &&
           expires_at_ == other.expires_at_ && display_name_ == other.display_name_;
}

} // namespace securecloud::client::domain
