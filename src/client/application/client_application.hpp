#pragma once

#include "application/client_bootstrap.hpp"
#include "application/client_error.hpp"
#include "domain/crypto/crypto_self_test.hpp"

#include <chrono>
#include <memory>
#include <optional>
#include <string_view>

namespace securecloud::client::application {

enum class ApplicationLifecycleState { Uninitialized, Initializing, Running, ShuttingDown, Terminated };

[[nodiscard]] std::string_view to_string(ApplicationLifecycleState state) noexcept;

class ClientApplication {
  public:
    explicit ClientApplication(ClientConfig config);
    explicit ClientApplication(std::unique_ptr<ClientBootstrap> bootstrap);
    ~ClientApplication();

    ClientApplication(const ClientApplication&) = delete;
    ClientApplication& operator=(const ClientApplication&) = delete;
    ClientApplication(ClientApplication&&) noexcept;
    ClientApplication& operator=(ClientApplication&&) noexcept;

    ClientResult<void> initialize();
    ClientResult<void> start();
    ClientResult<void> shutdown(std::chrono::milliseconds timeout = std::chrono::milliseconds(2000));

    [[nodiscard]] ApplicationLifecycleState state() const noexcept { return state_; }
    [[nodiscard]] bool is_running() const noexcept { return state_ == ApplicationLifecycleState::Running; }

    [[nodiscard]] ClientBootstrap& bootstrap() noexcept { return *bootstrap_; }
    [[nodiscard]] const ClientBootstrap& bootstrap() const noexcept { return *bootstrap_; }
    [[nodiscard]] const std::optional<domain::crypto::CryptoSelfTestReport>& last_self_test_report() const noexcept {
        return bootstrap_->last_self_test_report();
    }

  private:
    std::unique_ptr<ClientBootstrap> bootstrap_;
    ApplicationLifecycleState state_{ApplicationLifecycleState::Uninitialized};
};

} // namespace securecloud::client::application
