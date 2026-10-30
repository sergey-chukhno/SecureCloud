#pragma once

#include "audit_config.hpp"

#include <chrono>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace securecloud::audit::repository {

/// Client HTTP bas niveau ClickHouse avec gestion du pool de connexions et keep-alive.
class ClickHouseClient {
  public:
    explicit ClickHouseClient(const ClickHouseConfig& config);
    ~ClickHouseClient();

    // Prevent copying to maintain connection state safety
    ClickHouseClient(const ClickHouseClient&) = delete;
    ClickHouseClient& operator=(const ClickHouseClient&) = delete;

    /// Exécute une requête SQL en lecture/commande (ex: SELECT, ALTER).
    [[nodiscard]] bool execute_query(const std::string& query, std::string* out_response = nullptr,
                                     std::chrono::milliseconds timeout = std::chrono::milliseconds(3000));

    /// Exécute une requête d'insertion avec données brutes en body (ex: JSONEachRow).
    [[nodiscard]] bool execute_insert(const std::string& query, const std::string& body_data,
                                      std::chrono::milliseconds timeout = std::chrono::milliseconds(3000));

    /// Healthcheck rapide (exécute `SELECT 1` avec timeout sub-seconde).
    [[nodiscard]] bool ping(std::chrono::milliseconds timeout = std::chrono::milliseconds(800));

  private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace securecloud::audit::repository