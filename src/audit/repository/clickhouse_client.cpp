#include "clickhouse_client.hpp"

// Assuming standard httplib include available via CMake target
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
        if (!cli) return;
        std::lock_guard<std::mutex> lock(pool_mutex);
        if (connection_pool.size() < config.max_connections) {
            connection_pool.push(std::move(cli));
        }
    }

    httplib::Headers build_headers() const {
        return {
            {"X-ClickHouse-User", config.user},
            {"X-ClickHouse-Key", config.password.expose_unredacted_secret()},
            {"Accept-Encoding", "gzip, deflate"}
        };
    }
};

ClickHouseClient::ClickHouseClient(const ClickHouseConfig& config)
    : impl_(std::make_unique<Impl>(config)) {}

ClickHouseClient::~ClickHouseClient() = default;

bool ClickHouseClient::execute_query(const std::string& query,
                                      std::string* out_response,
                                      std::chrono::milliseconds timeout) {
    auto cli = impl_->acquire_connection(timeout);
    if (!cli) return false;

    httplib::Params params;
    params.emplace("query", query);
    params.emplace("database", impl_->config.db_name);

    std::string path = "/?" + httplib::detail::params_to_query_str(params);
    auto res = cli->Get(path.c_str(), impl_->build_headers());

    bool success = false;
    if (res && res->status == 200) {
        if (out_response) {
            *out_response = res->body;
        }
        success = true;
    }

    impl_->release_connection(std::move(cli));
    return success;
}

bool ClickHouseClient::execute_insert(const std::string& query,
                                       const std::string& body_data,
                                       std::chrono::milliseconds timeout) {
    auto cli = impl_->acquire_connection(timeout);
    if (!cli) return false;

    httplib::Params params;
    params.emplace("query", query);
    params.emplace("database", impl_->config.db_name);

    std::string path = "/?" + httplib::detail::params_to_query_str(params);
    auto res = cli->Post(path.c_str(), impl_->build_headers(), body_data, "application/json");

    bool success = (res && res->status == 200);

    impl_->release_connection(std::move(cli));
    return success;
}

bool ClickHouseClient::ping(std::chrono::milliseconds timeout) {
    std::string response;
    return execute_query("SELECT 1", &response, timeout) && !response.empty();
}

} // namespace securecloud::audit::repository