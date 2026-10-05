#pragma once

#include "auth/domain/entities.hpp"

#include <pqxx/pqxx>

namespace securecloud::auth::domain {

/// Deserializes UserEntity from a PostgreSQL query row.
[[nodiscard]] UserEntity user_from_row(const pqxx::row& row);

/// Deserializes DeviceEntity from a PostgreSQL query row.
[[nodiscard]] DeviceEntity device_from_row(const pqxx::row& row);

/// Deserializes DevicePublicKeyEntity from a PostgreSQL query row.
[[nodiscard]] DevicePublicKeyEntity device_public_key_from_row(const pqxx::row& row);

/// Deserializes SessionEntity from a PostgreSQL query row.
[[nodiscard]] SessionEntity session_from_row(const pqxx::row& row);

/// Deserializes RefreshTokenEntity from a PostgreSQL query row.
[[nodiscard]] RefreshTokenEntity refresh_token_from_row(const pqxx::row& row);

/// Deserializes MfaConfigurationEntity from a PostgreSQL query row.
[[nodiscard]] MfaConfigurationEntity mfa_configuration_from_row(const pqxx::row& row);

/// Deserializes MfaChallengeEntity from a PostgreSQL query row.
[[nodiscard]] MfaChallengeEntity mfa_challenge_from_row(const pqxx::row& row);

} // namespace securecloud::auth::domain
