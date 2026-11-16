#pragma once

#include "auth/audit/auth_audit_client.hpp"
#include "auth/audit/auth_outbox_diagnostics.hpp"
#include "auth/audit/auth_outbox_metrics.hpp"
#include "auth/audit/auth_outbox_relay_config.hpp"
#include "auth/repository/auth_outbox_repository.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

namespace securecloud::auth::audit {

/// Background transactional outbox poller and gRPC relay worker for Auth Service.
class AuthOutboxRelay {
  public:
    AuthOutboxRelay(std::shared_ptr<repository::IAuthOutboxRepository> repository,
                    std::shared_ptr<IAuthAuditClient> audit_client, AuthOutboxRelayConfig config = {},
                    std::string producer_instance = "auth", AuthOutboxMetrics* metrics = nullptr,
                    AuthOutboxDiagnostics* diagnostics = nullptr);
    ~AuthOutboxRelay();

    AuthOutboxRelay(const AuthOutboxRelay&) = delete;
    AuthOutboxRelay& operator=(const AuthOutboxRelay&) = delete;
    AuthOutboxRelay(AuthOutboxRelay&&) = delete;
    AuthOutboxRelay& operator=(AuthOutboxRelay&&) = delete;

    void start();
    void stop();
    void notify();

    [[nodiscard]] bool is_running() const noexcept;

    size_t poll_and_dispatch();
    size_t purge_old_published_records();

    [[nodiscard]] std::chrono::milliseconds compute_backoff_delay(uint32_t failure_attempt) const noexcept;

  private:
    void run();
    void drain_on_shutdown();

    std::shared_ptr<repository::IAuthOutboxRepository> repository_;
    std::shared_ptr<IAuthAuditClient> audit_client_;
    AuthOutboxRelayConfig config_;
    std::string producer_instance_;
    AuthOutboxMetrics* metrics_;
    AuthOutboxDiagnostics* diagnostics_;

    std::atomic<bool> running_{false};
    std::atomic<bool> wake_requested_{false};
    uint32_t consecutive_failures_{0};

    std::thread worker_thread_;
    std::mutex cv_mutex_;
    std::condition_variable cv_;
};

} // namespace securecloud::auth::audit
