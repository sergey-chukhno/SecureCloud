#pragma once

#include <stdexcept>
#include <string>

namespace securecloud::audit::repository {

/// Base exception for all ClickHouse interactions
class ClickHouseException : public std::runtime_error {
    using std::runtime_error::runtime_error;
};

/// Thrown on socket errors, connection refused, or DNS resolution failures
class ClickHouseConnectionException : public ClickHouseException {
    using ClickHouseException::ClickHouseException;
};

/// Thrown when bounded request or connection deadlines are exceeded
class ClickHouseTimeoutException : public ClickHouseException {
    using ClickHouseException::ClickHouseException;
};

/// Thrown on HTTP 4xx or 5xx responses (syntax error, server error, missing table)
class ClickHouseQueryException : public ClickHouseException {
  public:
    ClickHouseQueryException(const std::string& message, int status_code)
        : ClickHouseException(message + " (HTTP " + std::to_string(status_code) + ")"), status_code_(status_code) {}

    [[nodiscard]] int status_code() const noexcept { return status_code_; }

  private:
    int status_code_;
};

} // namespace securecloud::audit::repository