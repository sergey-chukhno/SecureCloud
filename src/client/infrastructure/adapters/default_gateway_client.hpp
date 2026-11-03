#pragma once

#include "application/client_config.hpp"
#include "application/interfaces/i_gateway_client.hpp"

#include <string>

namespace securecloud::client::infrastructure::adapters {

class DefaultGatewayClient final : public application::interfaces::IGatewayClient {
  public:
    explicit DefaultGatewayClient(const application::ClientConfig& config);
    ~DefaultGatewayClient() override = default;

    application::ClientResult<bool> probe_gateway(std::string_view path = "/health") override;
    application::ClientResult<std::string> send_message(const domain::ConversationId& conversation_id,
                                                        std::string_view encrypted_envelope) override;
    application::ClientResult<std::vector<std::string>> sync_messages(std::string_view cursor) override;
    application::ClientResult<bool> validate_token(std::string_view token) override;
    application::ClientResult<void> disconnect() override;

  private:
    std::string endpoint_;
    bool connected_{false};
};

} // namespace securecloud::client::infrastructure::adapters
