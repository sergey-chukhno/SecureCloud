#include "application/client_application.hpp"

#include "application/managers/local_audit_logger.hpp"
#include "infrastructure/client_logger.hpp"

#include <string>
#include <utility>

namespace securecloud::client::application {

std::string_view to_string(ApplicationLifecycleState state) noexcept {
    switch (state) {
    case ApplicationLifecycleState::Uninitialized:
        return "Uninitialized";
    case ApplicationLifecycleState::Initializing:
        return "Initializing";
    case ApplicationLifecycleState::Running:
        return "Running";
    case ApplicationLifecycleState::ShuttingDown:
        return "ShuttingDown";
    case ApplicationLifecycleState::Terminated:
        return "Terminated";
    }
    return "Unknown";
}

ClientApplication::ClientApplication(ClientConfig config)
    : bootstrap_(std::make_unique<ClientBootstrap>(std::move(config))) {}

ClientApplication::ClientApplication(std::unique_ptr<ClientBootstrap> bootstrap) : bootstrap_(std::move(bootstrap)) {}

ClientApplication::~ClientApplication() {
    if (state_ == ApplicationLifecycleState::Running || state_ == ApplicationLifecycleState::Initializing) {
        (void)shutdown();
    }
}

ClientApplication::ClientApplication(ClientApplication&&) noexcept = default;
ClientApplication& ClientApplication::operator=(ClientApplication&&) noexcept = default;

ClientResult<void> ClientApplication::initialize() {
    if (state_ != ApplicationLifecycleState::Uninitialized) {
        return ClientResult<void>::error(
            ClientError::internal_error("ClientApplication cannot be initialized from current state"));
    }

    state_ = ApplicationLifecycleState::Initializing;
    infrastructure::ClientLogger::info("ClientApp", "Initializing application subsystems...");

    if (!bootstrap_->config().is_valid()) {
        state_ = ApplicationLifecycleState::Terminated;
        return ClientResult<void>::error(ClientError::validation("Invalid client configuration during initialization"));
    }

    const auto open_res = bootstrap_->local_store().open(bootstrap_->config().database_path);
    if (open_res.is_error()) {
        state_ = ApplicationLifecycleState::Terminated;
        return open_res;
    }

    const auto self_test_report =
        domain::crypto::CryptoSelfTest::run_all(&bootstrap_->secure_storage(), bootstrap_->self_test_fault_injector());
    bootstrap_->set_last_self_test_report(self_test_report);

    if (!self_test_report.overall_passed) {
        const std::string failed_summary = self_test_report.failed_checks_summary();
        if (bootstrap_->local_audit_logger() != nullptr) {
            (void)bootstrap_->local_audit_logger()->record_event(
                domain::LocalAuditCategory::CryptoSelfTest, "crypto.selftest.failed",
                domain::LocalAuditOutcome::Failure, "", "", "Boot cryptographic self-test failed: " + failed_summary);
        }
        infrastructure::ClientLogger::error("ClientApp",
                                            "Boot cryptographic self-test failed (" + failed_summary + "); aborting");
        state_ = ApplicationLifecycleState::Terminated;
        return ClientResult<void>::error(ClientError::crypto("Boot cryptographic self-test failed: " + failed_summary));
    }

    if (bootstrap_->local_audit_logger() != nullptr) {
        (void)bootstrap_->local_audit_logger()->record_event(
            domain::LocalAuditCategory::CryptoSelfTest, "crypto.selftest.passed", domain::LocalAuditOutcome::Success,
            "", "",
            "Boot cryptographic self-test passed (" + std::to_string(self_test_report.checks.size()) + " checks, " +
                std::to_string(self_test_report.total_duration_us) + " us, " + self_test_report.crypto_backend + ")");
    }
    infrastructure::ClientLogger::info("ClientApp", "Boot cryptographic self-test passed (" +
                                                        std::to_string(self_test_report.checks.size()) + " checks in " +
                                                        std::to_string(self_test_report.total_duration_us) +
                                                        " us, backend: " + self_test_report.crypto_backend + ")");

    const auto probe_res = bootstrap_->gateway().probe_gateway("/health");
    if (probe_res.is_error()) {
        state_ = ApplicationLifecycleState::Terminated;
        return ClientResult<void>::error(probe_res.error());
    }

    infrastructure::ClientLogger::info("ClientApp", "Subsystems initialized successfully");
    return ClientResult<void>::ok();
}

ClientResult<void> ClientApplication::start() {
    if (state_ == ApplicationLifecycleState::Uninitialized) {
        const auto init_res = initialize();
        if (init_res.is_error()) {
            return init_res;
        }
    }

    if (state_ != ApplicationLifecycleState::Initializing) {
        return ClientResult<void>::error(
            ClientError::internal_error("ClientApplication must be in Initializing state to start"));
    }

    const auto sync_res = bootstrap_->sync_manager().start_sync();
    if (sync_res.is_error()) {
        return sync_res;
    }

    state_ = ApplicationLifecycleState::Running;
    infrastructure::ClientLogger::info("ClientApp", "Application entered RUNNING state");
    return ClientResult<void>::ok();
}

ClientResult<void> ClientApplication::shutdown(std::chrono::milliseconds /*timeout*/) {
    if (state_ == ApplicationLifecycleState::Terminated) {
        return ClientResult<void>::ok();
    }

    state_ = ApplicationLifecycleState::ShuttingDown;
    infrastructure::ClientLogger::info("ClientApp", "Initiating graceful shutdown...");

    // 1. Halt background synchronization
    (void)bootstrap_->sync_manager().stop_sync();

    // 2. Disconnect Gateway channel
    (void)bootstrap_->gateway().disconnect();

    // 3. Flush and close durable storage
    (void)bootstrap_->local_store().close();

    state_ = ApplicationLifecycleState::Terminated;
    infrastructure::ClientLogger::info("ClientApp", "Application terminated cleanly");
    return ClientResult<void>::ok();
}

} // namespace securecloud::client::application
