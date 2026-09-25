#pragma once

#include "files/db/files_connection_pool.hpp"
#include "files/storage/s3_client.hpp"
#include "securecloud/health/health_status_manager.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <thread>

namespace securecloud::files::health {

using HealthProbeFn = std::function<bool()>;

/// Configuration parameters for FilesHealthEvaluator.
struct FilesHealthEvaluatorConfig {
    std::chrono::milliseconds check_interval{500};
    std::chrono::milliseconds probe_timeout{250};
    bool auto_start{true};
};

/// Dual-dependency health and readiness evaluator for SecureCloud Files service.
/// Coordinates health evaluations across PostgreSQL 17 (metadata) and MinIO S3 (ciphertext blobs).
/// Dynamically drives HealthStatusManager readiness state:
/// - SERVING if and only if BOTH PostgreSQL and MinIO are healthy.
/// - NOT_SERVING if either dependency degrades or fails.
/// - Non-blocking: maintains cached atomic states so incoming gRPC health checks are never blocked.
class FilesHealthEvaluator {
  public:
    /// Production constructor using real PostgreSQL pool and S3 client.
    FilesHealthEvaluator(common::health::HealthStatusManager& health_manager,
                         std::shared_ptr<db::FilesDbConnectionPool> db_pool,
                         std::shared_ptr<storage::S3Client> s3_client, FilesHealthEvaluatorConfig config = {});

    /// Flexible constructor accepting custom probe functions (used in unit testing).
    FilesHealthEvaluator(common::health::HealthStatusManager& health_manager, HealthProbeFn db_probe,
                         HealthProbeFn s3_probe, FilesHealthEvaluatorConfig config = {});

    ~FilesHealthEvaluator();

    FilesHealthEvaluator(const FilesHealthEvaluator&) = delete;
    FilesHealthEvaluator& operator=(const FilesHealthEvaluator&) = delete;
    FilesHealthEvaluator(FilesHealthEvaluator&&) = delete;
    FilesHealthEvaluator& operator=(FilesHealthEvaluator&&) = delete;

    /// Executes a single synchronous evaluation of both dependencies and updates states.
    /// Returns true if both dependencies are healthy.
    bool evaluate_once() noexcept;

    /// Starts the background evaluation thread if not already running.
    void start();

    /// Stops the background evaluation thread and joins it cleanly.
    void stop() noexcept;

    // State inspection
    [[nodiscard]] bool is_db_healthy() const noexcept;
    [[nodiscard]] bool is_s3_healthy() const noexcept;
    [[nodiscard]] bool is_ready() const noexcept;
    [[nodiscard]] bool is_running() const noexcept;

  private:
    void background_loop();
    void update_states(bool db_ok, bool s3_ok) noexcept;

    common::health::HealthStatusManager& health_manager_;
    HealthProbeFn db_probe_;
    HealthProbeFn s3_probe_;
    FilesHealthEvaluatorConfig config_;

    std::atomic<bool> db_healthy_{false};
    std::atomic<bool> s3_healthy_{false};
    std::atomic<bool> is_ready_{false};
    std::atomic<bool> is_running_{false};
    std::atomic<bool> stop_requested_{false};

    std::mutex loop_mutex_;
    std::condition_variable cv_loop_;
    std::thread background_thread_;
};

} // namespace securecloud::files::health
