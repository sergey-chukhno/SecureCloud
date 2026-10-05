#pragma once

#include "auth/db/postgres_connection_pool.hpp"
#include "auth/domain/entities.hpp"
#include "auth/repository/exceptions.hpp"

#include <optional>
#include <pqxx/pqxx>
#include <string_view>
#include <vector>

namespace securecloud::auth::repository {

/// Result of an atomic single-use refresh token rotation.
struct TokenRotationResult {
    domain::RefreshTokenEntity old_token;
    domain::RefreshTokenEntity new_token;
};

/// Result of a detected token reuse compromise event.
struct TokenReuseDetectedResult {
    domain::Uuid session_id;
    domain::Uuid device_id;
    domain::time_point revoked_at;
};

/// Abstract interface contract for Refresh Token persistence operations.
class IRefreshTokenRepository {
  public:
    virtual ~IRefreshTokenRepository() = default;

    virtual void create_token(const domain::RefreshTokenEntity& token) = 0;
    virtual void create_token(const domain::RefreshTokenEntity& token, pqxx::transaction_base& tx) = 0;

    [[nodiscard]] virtual std::optional<domain::RefreshTokenEntity>
    find_by_id(const domain::Uuid& refresh_token_id) = 0;
    [[nodiscard]] virtual std::optional<domain::RefreshTokenEntity> find_by_id(const domain::Uuid& refresh_token_id,
                                                                               pqxx::transaction_base& tx) = 0;

    [[nodiscard]] virtual std::optional<domain::RefreshTokenEntity>
    find_by_verifier(std::string_view verifier_hash) = 0;
    [[nodiscard]] virtual std::optional<domain::RefreshTokenEntity> find_by_verifier(std::string_view verifier_hash,
                                                                                     pqxx::transaction_base& tx) = 0;

    virtual TokenRotationResult rotate_token_atomic(const domain::Uuid& old_token_id,
                                                    const domain::RefreshTokenEntity& new_token) = 0;
    virtual TokenRotationResult rotate_token_atomic(const domain::Uuid& old_token_id,
                                                    const domain::RefreshTokenEntity& new_token,
                                                    pqxx::transaction_base& tx) = 0;

    virtual TokenReuseDetectedResult handle_token_reuse(std::string_view verifier_hash) = 0;
    virtual TokenReuseDetectedResult handle_token_reuse(std::string_view verifier_hash, pqxx::transaction_base& tx) = 0;
};

/// PostgreSQL-backed implementation of IRefreshTokenRepository.
class PostgresRefreshTokenRepository : public IRefreshTokenRepository {
  public:
    explicit PostgresRefreshTokenRepository(db::PostgresConnectionPool& pool);

    void create_token(const domain::RefreshTokenEntity& token) override;
    void create_token(const domain::RefreshTokenEntity& token, pqxx::transaction_base& tx) override;

    [[nodiscard]] std::optional<domain::RefreshTokenEntity> find_by_id(const domain::Uuid& refresh_token_id) override;
    [[nodiscard]] std::optional<domain::RefreshTokenEntity> find_by_id(const domain::Uuid& refresh_token_id,
                                                                       pqxx::transaction_base& tx) override;

    [[nodiscard]] std::optional<domain::RefreshTokenEntity> find_by_verifier(std::string_view verifier_hash) override;
    [[nodiscard]] std::optional<domain::RefreshTokenEntity> find_by_verifier(std::string_view verifier_hash,
                                                                             pqxx::transaction_base& tx) override;

    TokenRotationResult rotate_token_atomic(const domain::Uuid& old_token_id,
                                            const domain::RefreshTokenEntity& new_token) override;
    TokenRotationResult rotate_token_atomic(const domain::Uuid& old_token_id,
                                            const domain::RefreshTokenEntity& new_token,
                                            pqxx::transaction_base& tx) override;

    TokenReuseDetectedResult handle_token_reuse(std::string_view verifier_hash) override;
    TokenReuseDetectedResult handle_token_reuse(std::string_view verifier_hash, pqxx::transaction_base& tx) override;

  private:
    db::PostgresConnectionPool& pool_;
};

} // namespace securecloud::auth::repository
