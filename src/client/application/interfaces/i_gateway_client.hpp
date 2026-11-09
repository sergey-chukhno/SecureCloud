#pragma once

#include "application/client_error.hpp"
#include "domain/conversation_id.hpp"
#include "domain/device_id.hpp"
#include "domain/user_id.hpp"

#include <string>
#include <string_view>
#include <vector>

namespace securecloud::client::application::interfaces {

class IGatewayClient {
  public:
    virtual ~IGatewayClient() = default;

    virtual ClientResult<bool> probe_gateway(std::string_view path = "/health") = 0;
    virtual ClientResult<std::string> send_message(const domain::ConversationId& conversation_id,
                                                   std::string_view encrypted_envelope) = 0;
    virtual ClientResult<std::vector<std::string>> sync_messages(std::string_view cursor) = 0;
    virtual ClientResult<bool> validate_token(std::string_view token) = 0;
    virtual ClientResult<void> disconnect() = 0;
};

} // namespace securecloud::client::application::interfaces
