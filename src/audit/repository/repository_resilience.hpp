#pragma once

#include "audit_repository_exceptions.hpp"

#include <chrono>
#include <random>
#include <semaphore>
#include <thread>
#include <type_traits>

namespace securecloud::audit::repository {

class RepositoryResilience {
  public:
    /// Initializes the Bulkhead. max_concurrent_requests corresponds to config.clickhouse.max_connections (max 128).
    explicit RepositoryResilience(uint32_t max_concurrent_requests) : bulkhead_(max_concurrent_requests) {}

    /// Executes an operation with concurrency limits and a retry policy (exponential backoff + jitter).
    template <typename Func> auto execute(Func&& operation, uint32_t max_retries = 3) -> std::invoke_result_t<Func> {
        // Bulkhead: limits the number of concurrent requests to the database
        bulkhead_.acquire();
        struct BulkheadReleaser {
            std::counting_semaphore<128>& sem;
            ~BulkheadReleaser() { sem.release(); }
        } releaser{bulkhead_};

        uint32_t attempt = 0;
        std::chrono::milliseconds backoff{100};

        while (true) {
            try {
                return operation();
            } catch (const ClickHouseConnectionException&) {
                if (attempt >= max_retries)
                    throw;
            } catch (const ClickHouseTimeoutException&) {
                if (attempt >= max_retries)
                    throw;
            } catch (const ClickHouseQueryException& e) {
                // Fail-fast on 4xx errors (except 429 Too Many Requests), retry on 5xx
                if (e.status_code() >= 400 && e.status_code() < 500 && e.status_code() != 429) {
                    throw;
                }
                if (attempt >= max_retries)
                    throw;
            }

            std::this_thread::sleep_for(backoff + generate_jitter());
            backoff *= 2;
            attempt++;
        }
    }

  private:
    std::counting_semaphore<128> bulkhead_;

    [[nodiscard]] static std::chrono::milliseconds generate_jitter() {
        thread_local std::mt19937 generator(std::random_device{}());
        std::uniform_int_distribution<int> distribution(0, 50);
        return std::chrono::milliseconds(distribution(generator));
    }
};

} // namespace securecloud::audit::repository