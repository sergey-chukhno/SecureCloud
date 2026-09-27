#pragma once

#include "grpc/auth_client_interface.hpp"
#include "http/auth/token_validator_interface.hpp"

#include <chrono>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

namespace securecloud::gateway::http {

struct TokenValidatorOptions {
    std::chrono::milliseconds rpc_timeout{500};
    std::chrono::seconds cache_ttl{10};
    size_t max_cache_entries{10000};
};

/**
 * @brief Token validator adapter delegating session validation to AuthService via internal mTLS.
 *
 * Implements perimeter authorization validation with:
 * - Strict RPC deadline enforcement via ClientCallContext.
 * - Thread-safe bounded in-memory cache to mitigate internal network RPC storm.
 * - Deterministic mapping of gRPC status codes to perimeter TokenValidationError.
 */
class AuthServiceTokenValidator : public ITokenValidator {
  public:
    explicit AuthServiceTokenValidator(std::shared_ptr<securecloud::gateway::grpc::IAuthClient> auth_client,
                                       TokenValidatorOptions options = {});

    ~AuthServiceTokenValidator() override = default;

    AuthenticatedResult validate(const std::string& token, const std::string& session_id = "",
                                 const std::string& request_id = "") override;

    void clear_cache();
    [[nodiscard]] size_t cache_size() const;

  private:
    struct CacheEntry {
        AuthenticatedContext context;
        std::chrono::system_clock::time_point valid_until;
    };

    std::shared_ptr<securecloud::gateway::grpc::IAuthClient> auth_client_;
    TokenValidatorOptions options_;

    mutable std::mutex cache_mutex_;
    std::unordered_map<std::string, CacheEntry> cache_;

    [[nodiscard]] std::string build_cache_key(const std::string& token, const std::string& session_id) const;
    void evict_expired_or_overflow_locked(std::chrono::system_clock::time_point now);
};

} // namespace securecloud::gateway::http
