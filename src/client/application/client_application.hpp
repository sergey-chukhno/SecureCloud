#pragma once

#include "application/client_bootstrap.hpp"
#include "application/client_error.hpp"

#include <chrono>
#include <memory>
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

  private:
    std::unique_ptr<ClientBootstrap> bootstrap_;
    ApplicationLifecycleState state_{ApplicationLifecycleState::Uninitialized};
};

} // namespace securecloud::client::application
