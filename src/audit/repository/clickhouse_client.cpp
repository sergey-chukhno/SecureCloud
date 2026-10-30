#include "clickhouse_client.hpp"

#include "audit_repository_exceptions.hpp"

#include <httplib.h>
#include <queue>
#include <sstream>

namespace securecloud::audit::repository {

struct ClickHouseClient::Impl {
    ClickHouseConfig config;
    std::queue<std::unique_ptr<httplib::Client>> connection_pool;
    std::mutex pool_mutex;

    explicit Impl(const ClickHouseConfig& cfg) : config(cfg) {}

    std::unique_ptr<httplib::Client> acquire_connection(std::chrono::milliseconds timeout) {
        std::lock_guard<std::mutex> lock(pool_mutex);
        if (!connection_pool.empty()) {
            auto cli = std::move(connection_pool.front());
            connection_pool.pop();
            return cli;
        }

        auto cli = std::make_unique<httplib::Client>(config.host, config.port);

        // Timeout configuration
        auto sec = std::chrono::duration_cast<std::chrono::seconds>(timeout);
        auto usec = std::chrono::duration_cast<std::chrono::microseconds>(timeout - sec);
        cli->set_connection_timeout(sec.count(), usec.count());
        cli->set_read_timeout(sec.count(), usec.count());
        cli->set_write_timeout(sec.count(), usec.count());

        // Keep-alive settings
        cli->set_keep_alive(true);

        return cli;
    }

    void release_connection(std::unique_ptr<httplib::Client> cli) {
        if (!cli)
            return;
        std::lock_guard<std::mutex> lock(pool_mutex);
        if (connection_pool.size() < config.max_connections) {
            connection_pool.push(std::move(cli));
        }
    }

    httplib::Headers build_headers() const {
        return {{"X-ClickHouse-User", config.user},
                {"X-ClickHouse-Key", config.password.expose_unredacted_secret()},
                {"Accept-Encoding", "gzip, deflate"}};
    }
};

ClickHouseClient::ClickHouseClient(const ClickHouseConfig& config) : impl_(std::make_unique<Impl>(config)) {}

ClickHouseClient::~ClickHouseClient() = default;

bool ClickHouseClient::execute_query(const std::string& query, std::string* out_response,
                                     std::chrono::milliseconds timeout) {
    auto cli = impl_->acquire_connection(timeout);
    if (!cli) {
        throw ClickHouseConnectionException("Connection pool exhausted or timeout");
    }

    httplib::Params params;
    params.emplace("query", query);
    params.emplace("database", impl_->config.db_name);

    std::string path = "/?" + httplib::detail::params_to_query_str(params);
    auto res = cli->Get(path.c_str(), impl_->build_headers());

    // Release the connection back to the pool before potentially throwing
    impl_->release_connection(std::move(cli));

    if (!res) {
        if (res.error() == httplib::Error::Read || res.error() == httplib::Error::Write) {
            throw ClickHouseTimeoutException("ClickHouse request timed out");
        }
        throw ClickHouseConnectionException("Failed to reach ClickHouse: httplib error code " +
                                            std::to_string(static_cast<int>(res.error())));
    }

    if (res->status != 200) {
        // Strict Error Logging Taxonomy: Do NOT append raw query/payload to avoid leaking PII/secrets.
        throw ClickHouseQueryException("ClickHouse rejected the query", res->status);
    }

    if (out_response) {
        *out_response = res->body;
    }

    return true;
}

bool ClickHouseClient::execute_parameterized_query(
    const ParameterizedClickHouseQuery& query,
    std::string* out_response,
    std::chrono::milliseconds timeout,
    size_t max_bytes) {

    auto cli = impl_->acquire_connection(timeout);
    if (!cli) {
        throw ClickHouseConnectionException("Connection pool exhausted or timeout");
    }

    httplib::Params params;
    params.emplace("query", query.sql_template);
    params.emplace("database", impl_->config.db_name);
    params.emplace("readonly", "1");
    params.emplace("max_execution_time",
                   std::to_string(std::chrono::duration_cast<std::chrono::seconds>(timeout).count()));
    params.emplace("max_result_bytes", std::to_string(max_bytes));

    for (const auto& [param_name, param_val] : query.bind_params) {
        params.emplace("param_" + param_name, param_val);
    }

    std::string path = "/?" + httplib::detail::params_to_query_str(params);
    auto res = cli->Get(path.c_str(), impl_->build_headers());

    impl_->release_connection(std::move(cli));

    if (!res) {
        if (res.error() == httplib::Error::Read || res.error() == httplib::Error::Write) {
            throw ClickHouseTimeoutException("ClickHouse request timed out");
        }
        throw ClickHouseConnectionException("Failed to reach ClickHouse: httplib error code " +
                                            std::to_string(static_cast<int>(res.error())));
    }

    if (res->status != 200) {
        throw ClickHouseQueryException("ClickHouse rejected the parameterized query", res->status);
    }

    if (res->body.size() > max_bytes) {
        throw ClickHouseQueryException("ClickHouse query result exceeded max_result_bytes limit", 413);
    }

    if (out_response) {
        *out_response = res->body;
    }

    return true;
}

bool ClickHouseClient::execute_insert(const std::string& query, const std::string& body_data,
                                      std::chrono::milliseconds timeout) {
    auto cli = impl_->acquire_connection(timeout);
    if (!cli) {
        throw ClickHouseConnectionException("Connection pool exhausted or timeout");
    }

    httplib::Params params;
    params.emplace("query", query);
    params.emplace("database", impl_->config.db_name);

    std::string path = "/?" + httplib::detail::params_to_query_str(params);
    auto res = cli->Post(path.c_str(), impl_->build_headers(), body_data, "application/json");

    // Release the connection back to the pool before potentially throwing
    impl_->release_connection(std::move(cli));

    if (!res) {
        if (res.error() == httplib::Error::Read || res.error() == httplib::Error::Write) {
            throw ClickHouseTimeoutException("ClickHouse request timed out");
        }
        throw ClickHouseConnectionException("Failed to reach ClickHouse: httplib error code " +
                                            std::to_string(static_cast<int>(res.error())));
    }

    if (res->status != 200) {
        // Strict Error Logging Taxonomy: Do NOT append raw body_data to avoid leaking PII/secrets.
        throw ClickHouseQueryException("ClickHouse rejected the insertion", res->status);
    }

    return true;
}

bool ClickHouseClient::ping(std::chrono::milliseconds timeout) {
    try {
        std::string response;
        return execute_query("SELECT 1", &response, timeout) && !response.empty();
    } catch (const ClickHouseException&) {
        return false;
    }
}

} // namespace securecloud::audit::repository