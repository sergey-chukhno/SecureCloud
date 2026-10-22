#include "auth/domain/mappers.hpp"

#include <stdexcept>

namespace securecloud::auth::domain {

namespace {

template <typename Field> inline std::optional<time_point> parse_opt_timestamp(const Field& f) {
    if (f.is_null()) {
        return std::nullopt;
    }
    return from_iso8601_utc(f.template as<std::string>());
}

template <typename Field> inline time_point parse_timestamp(const Field& f) {
    auto opt = parse_opt_timestamp(f);
    if (!opt) {
        throw std::runtime_error("Required timestamp column is NULL or invalid: " + std::string(f.name()));
    }
    return *opt;
}

template <typename Field> inline std::optional<std::string> parse_opt_string(const Field& f) {
    if (f.is_null()) {
        return std::nullopt;
    }
    return f.template as<std::string>();
}

template <typename Field> inline std::optional<Uuid> parse_opt_uuid(const Field& f) {
    if (f.is_null()) {
        return std::nullopt;
    }
    return Uuid::from_string(f.template as<std::string>());
}

template <typename Field> inline Uuid parse_uuid(const Field& f) {
    auto opt = parse_opt_uuid(f);
    if (!opt) {
        throw std::runtime_error("Required UUID column is NULL or invalid: " + std::string(f.name()));
    }
    return *opt;
}

template <typename Field> inline std::vector<uint8_t> parse_bytea(const Field& f) {
    if (f.is_null()) {
        return {};
    }
    auto b = f.template as<pqxx::bytes>();
    const auto* data = reinterpret_cast<const uint8_t*>(b.data());
    return std::vector<uint8_t>(data, data + b.size());
}

} // namespace

UserEntity user_from_row(const pqxx::row& row) {
    UserEntity u;
    u.user_id = parse_uuid(row["user_id"]);
    u.credential_identifier = row["credential_identifier"].as<std::string>();
    u.password_verifier = row["password_verifier"].as<std::string>();
    u.password_algorithm = row["password_algorithm"].as<std::string>();
    u.password_updated_at = parse_timestamp(row["password_updated_at"]);

    auto opt_status = parse_enum<AccountStatus>(row["account_status"].as<std::string>());
    if (!opt_status) {
        throw std::runtime_error("Invalid account_status in row: " + row["account_status"].as<std::string>());
    }
    u.account_status = *opt_status;

    u.created_at = parse_timestamp(row["created_at"]);
    u.updated_at = parse_timestamp(row["updated_at"]);
    u.version = row["version"].as<uint64_t>();
    return u;
}

DeviceEntity device_from_row(const pqxx::row& row) {
    DeviceEntity d;
    d.device_id = parse_uuid(row["device_id"]);
    d.user_id = parse_uuid(row["user_id"]);

    auto opt_status = parse_enum<DeviceStatus>(row["device_status"].as<std::string>());
    if (!opt_status) {
        throw std::runtime_error("Invalid device_status in row: " + row["device_status"].as<std::string>());
    }
    d.device_status = *opt_status;

    d.registered_at = parse_timestamp(row["registered_at"]);
    d.revoked_at = parse_opt_timestamp(row["revoked_at"]);
    d.revocation_reason = parse_opt_string(row["revocation_reason"]);
    d.last_authenticated_at = parse_timestamp(row["last_authenticated_at"]);
    d.created_at = parse_timestamp(row["created_at"]);
    d.updated_at = parse_timestamp(row["updated_at"]);
    return d;
}

DevicePublicKeyEntity device_public_key_from_row(const pqxx::row& row) {
    DevicePublicKeyEntity k;
    k.key_id = parse_uuid(row["key_id"]);
    k.device_id = parse_uuid(row["device_id"]);

    auto opt_type = parse_enum<KeyType>(row["key_type"].as<std::string>());
    if (!opt_type) {
        throw std::runtime_error("Invalid key_type in row: " + row["key_type"].as<std::string>());
    }
    k.key_type = *opt_type;

    k.public_key = parse_bytea(row["public_key"]);

    auto opt_status = parse_enum<KeyStatus>(row["key_status"].as<std::string>());
    if (!opt_status) {
        throw std::runtime_error("Invalid key_status in row: " + row["key_status"].as<std::string>());
    }
    k.key_status = *opt_status;

    k.created_at = parse_timestamp(row["created_at"]);
    k.revoked_at = parse_opt_timestamp(row["revoked_at"]);
    k.replaced_by_key_id = parse_opt_uuid(row["replaced_by_key_id"]);
    try {
        if (!row["signature"].is_null()) {
            k.signature = parse_bytea(row["signature"]);
        }
    } catch (const pqxx::argument_error&) {
        // "signature" column not present in row projection
    }
    return k;
}

SessionEntity session_from_row(const pqxx::row& row) {
    SessionEntity s;
    s.session_id = parse_uuid(row["session_id"]);
    s.user_id = parse_uuid(row["user_id"]);
    s.device_id = parse_uuid(row["device_id"]);

    auto opt_status = parse_enum<SessionStatus>(row["session_status"].as<std::string>());
    if (!opt_status) {
        throw std::runtime_error("Invalid session_status in row: " + row["session_status"].as<std::string>());
    }
    s.session_status = *opt_status;

    auto opt_level = parse_enum<AuthenticationLevel>(row["authentication_level"].as<std::string>());
    if (!opt_level) {
        throw std::runtime_error("Invalid authentication_level in row: " +
                                 row["authentication_level"].as<std::string>());
    }
    s.authentication_level = *opt_level;

    s.created_at = parse_timestamp(row["created_at"]);
    s.expires_at = parse_timestamp(row["expires_at"]);
    s.revoked_at = parse_opt_timestamp(row["revoked_at"]);
    s.last_used_at = parse_timestamp(row["last_used_at"]);
    return s;
}

RefreshTokenEntity refresh_token_from_row(const pqxx::row& row) {
    RefreshTokenEntity t;
    t.refresh_token_id = parse_uuid(row["refresh_token_id"]);
    t.session_id = parse_uuid(row["session_id"]);
    t.device_id = parse_uuid(row["device_id"]);
    t.token_verifier = row["token_verifier"].as<std::string>();

    auto opt_status = parse_enum<TokenStatus>(row["token_status"].as<std::string>());
    if (!opt_status) {
        throw std::runtime_error("Invalid token_status in row: " + row["token_status"].as<std::string>());
    }
    t.token_status = *opt_status;

    t.issued_at = parse_timestamp(row["issued_at"]);
    t.expires_at = parse_timestamp(row["expires_at"]);
    t.revoked_at = parse_opt_timestamp(row["revoked_at"]);
    t.rotated_at = parse_opt_timestamp(row["rotated_at"]);
    t.replaced_by_token_id = parse_opt_uuid(row["replaced_by_token_id"]);
    return t;
}

MfaConfigurationEntity mfa_configuration_from_row(const pqxx::row& row) {
    MfaConfigurationEntity m;
    m.mfa_configuration_id = parse_uuid(row["mfa_configuration_id"]);
    m.user_id = parse_uuid(row["user_id"]);

    auto opt_factor = parse_enum<MfaFactorType>(row["factor_type"].as<std::string>());
    if (!opt_factor) {
        throw std::runtime_error("Invalid factor_type in row: " + row["factor_type"].as<std::string>());
    }
    m.factor_type = *opt_factor;

    m.encrypted_secret = parse_bytea(row["encrypted_secret"]);

    auto opt_status = parse_enum<MfaStatus>(row["status"].as<std::string>());
    if (!opt_status) {
        throw std::runtime_error("Invalid status in row: " + row["status"].as<std::string>());
    }
    m.status = *opt_status;

    m.created_at = parse_timestamp(row["created_at"]);
    m.enabled_at = parse_opt_timestamp(row["enabled_at"]);
    m.disabled_at = parse_opt_timestamp(row["disabled_at"]);
    m.version = row["version"].as<uint64_t>();
    return m;
}

MfaChallengeEntity mfa_challenge_from_row(const pqxx::row& row) {
    MfaChallengeEntity c;
    c.mfa_challenge_id = parse_uuid(row["mfa_challenge_id"]);
    c.user_id = parse_uuid(row["user_id"]);
    c.session_id = parse_uuid(row["session_id"]);

    auto opt_purpose = parse_enum<MfaChallengePurpose>(row["challenge_purpose"].as<std::string>());
    if (!opt_purpose) {
        throw std::runtime_error("Invalid challenge_purpose in row: " + row["challenge_purpose"].as<std::string>());
    }
    c.challenge_purpose = *opt_purpose;

    auto opt_status = parse_enum<MfaChallengeStatus>(row["challenge_status"].as<std::string>());
    if (!opt_status) {
        throw std::runtime_error("Invalid challenge_status in row: " + row["challenge_status"].as<std::string>());
    }
    c.challenge_status = *opt_status;

    c.created_at = parse_timestamp(row["created_at"]);
    c.expires_at = parse_timestamp(row["expires_at"]);
    c.completed_at = parse_opt_timestamp(row["completed_at"]);
    return c;
}

} // namespace securecloud::auth::domain
