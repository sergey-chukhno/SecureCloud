#pragma once

#include "domain/session_state.hpp"
#include "infrastructure/gateway_adapter_stub.hpp"

#include <memory>
#include <string>

namespace securecloud::client::application {

class ClientAppService {
  public:
    ClientAppService();
    explicit ClientAppService(std::unique_ptr<infrastructure::GatewayAdapterStub> gateway);
    ~ClientAppService();

    ClientAppService(const ClientAppService&) = delete;
    ClientAppService& operator=(const ClientAppService&) = delete;
    ClientAppService(ClientAppService&&) noexcept;
    ClientAppService& operator=(ClientAppService&&) noexcept;

    [[nodiscard]] bool initialize();
    [[nodiscard]] const domain::SessionState& sessionState() const noexcept;
    [[nodiscard]] const infrastructure::GatewayAdapterStub& gateway() const noexcept;

    void updateSession(std::string userId, std::string deviceId);
    void logout();

  private:
    domain::SessionState sessionState_;
    std::unique_ptr<infrastructure::GatewayAdapterStub> gateway_;
};

} // namespace securecloud::client::application
