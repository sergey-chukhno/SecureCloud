#include "files/health/files_health_evaluator.hpp"

#include <iostream>
#include <utility>

namespace securecloud::files::health {

FilesHealthEvaluator::FilesHealthEvaluator(common::health::HealthStatusManager& health_manager,
                                           std::shared_ptr<db::FilesDbConnectionPool> db_pool,
                                           std::shared_ptr<storage::S3Client> s3_client,
                                           FilesHealthEvaluatorConfig config)
    : FilesHealthEvaluator(
          health_manager,
          [pool = std::move(db_pool), timeout = config.probe_timeout]() -> bool {
              return pool ? pool->ping(timeout) : false;
          },
          [client = std::move(s3_client)]() -> bool { return client ? client->ping_bucket() : false; }, config) {}

FilesHealthEvaluator::FilesHealthEvaluator(common::health::HealthStatusManager& health_manager, HealthProbeFn db_probe,
                                           HealthProbeFn s3_probe, FilesHealthEvaluatorConfig config)
    : health_manager_(health_manager), db_probe_(std::move(db_probe)), s3_probe_(std::move(s3_probe)), config_(config) {
    // Hook non-blocking cached evaluator into common HealthStatusManager
    health_manager_.set_readiness_evaluator([this] { return this->is_ready(); });

    if (config_.auto_start) {
        start();
    }
}

FilesHealthEvaluator::~FilesHealthEvaluator() {
    stop();
}

bool FilesHealthEvaluator::evaluate_once() noexcept {
    bool db_ok = false;
    bool s3_ok = false;

    if (db_probe_) {
        try {
            db_ok = db_probe_();
        } catch (const std::exception& ex) {
            std::cerr << "[SecureCloud] [files] WARNING: Exception during PostgreSQL health probe: " << ex.what()
                      << "\n";
            db_ok = false;
        } catch (...) {
            std::cerr << "[SecureCloud] [files] WARNING: Unknown error during PostgreSQL health probe\n";
            db_ok = false;
        }
    }

    if (s3_probe_) {
        try {
            s3_ok = s3_probe_();
        } catch (const std::exception& ex) {
            std::cerr << "[SecureCloud] [files] WARNING: Exception during MinIO S3 health probe: " << ex.what() << "\n";
            s3_ok = false;
        } catch (...) {
            std::cerr << "[SecureCloud] [files] WARNING: Unknown error during MinIO S3 health probe\n";
            s3_ok = false;
        }
    }

    update_states(db_ok, s3_ok);
    return is_ready_.load(std::memory_order_acquire);
}

void FilesHealthEvaluator::update_states(bool db_ok, bool s3_ok) noexcept {
    bool prev_db = db_healthy_.exchange(db_ok, std::memory_order_acq_rel);
    bool prev_s3 = s3_healthy_.exchange(s3_ok, std::memory_order_acq_rel);

    // Compound rule: SERVING if and only if both PostgreSQL AND MinIO S3 are healthy
    bool compound_ready = db_ok && s3_ok;
    bool prev_ready = is_ready_.exchange(compound_ready, std::memory_order_acq_rel);

    health_manager_.set_ready(compound_ready);

    // Diagnostic operational logging
    if (prev_db && !db_ok) {
        std::cerr << "[SecureCloud] [files] WARNING: PostgreSQL dependency degraded (ping failed)\n";
    }
    if (prev_s3 && !s3_ok) {
        std::cerr << "[SecureCloud] [files] WARNING: MinIO S3 dependency degraded (ping_bucket failed)\n";
    }
    if (prev_ready && !compound_ready) {
        std::cerr << "[SecureCloud] [files] Files service readiness flipped to NOT_SERVING (db: "
                  << (db_ok ? "OK" : "DEGRADED") << ", s3: " << (s3_ok ? "OK" : "DEGRADED") << ")\n";
    }
    if (!prev_ready && compound_ready) {
        std::cout << "[SecureCloud] [files] INFO: All upstream dependencies healthy (db: OK, s3: OK). "
                  << "Files service readiness restored to SERVING\n";
    }
}

void FilesHealthEvaluator::start() {
    bool expected = false;
    if (!is_running_.compare_exchange_strong(expected, true)) {
        return; // Already running
    }

    stop_requested_.store(false, std::memory_order_release);
    background_thread_ = std::thread(&FilesHealthEvaluator::background_loop, this);
}

void FilesHealthEvaluator::stop() noexcept {
    if (!is_running_.exchange(false, std::memory_order_acq_rel)) {
        return; // Not running
    }

    stop_requested_.store(true, std::memory_order_release);
    cv_loop_.notify_all();

    if (background_thread_.joinable()) {
        background_thread_.join();
    }
}

void FilesHealthEvaluator::background_loop() {
    while (!stop_requested_.load(std::memory_order_acquire)) {
        evaluate_once();

        std::unique_lock<std::mutex> lock(loop_mutex_);
        cv_loop_.wait_for(lock, config_.check_interval,
                          [this] { return stop_requested_.load(std::memory_order_acquire); });
    }
}

bool FilesHealthEvaluator::is_db_healthy() const noexcept {
    return db_healthy_.load(std::memory_order_acquire);
}

bool FilesHealthEvaluator::is_s3_healthy() const noexcept {
    return s3_healthy_.load(std::memory_order_acquire);
}

bool FilesHealthEvaluator::is_ready() const noexcept {
    return is_ready_.load(std::memory_order_acquire);
}

bool FilesHealthEvaluator::is_running() const noexcept {
    return is_running_.load(std::memory_order_acquire);
}

} // namespace securecloud::files::health
