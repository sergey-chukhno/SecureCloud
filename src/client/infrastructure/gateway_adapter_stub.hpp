#pragma once

#include <string>
#include <string_view>

namespace securecloud::client::infrastructure {

class GatewayAdapterStub {
  public:
    GatewayAdapterStub() = default;
    explicit GatewayAdapterStub(std::string endpoint);

    [[nodiscard]] const std::string& endpoint() const noexcept;
    [[nodiscard]] bool isConnected() const noexcept;
    [[nodiscard]] bool probeGateway(std::string_view path);

  private:
    std::string endpoint_{"https://127.0.0.1:8443"};
    bool connected_{false};
};

} // namespace securecloud::client::infrastructure
