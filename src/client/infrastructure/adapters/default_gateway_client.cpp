#include "infrastructure/adapters/default_gateway_client.hpp"

#include <sstream>

namespace securecloud::client::infrastructure::adapters {

DefaultGatewayClient::DefaultGatewayClient(const application::ClientConfig& config) {
    std::ostringstream oss;
    oss << config.gateway_url << ":" << config.gateway_port;
    endpoint_ = oss.str();
}

application::ClientResult<bool> DefaultGatewayClient::probe_gateway(std::string_view /*path*/) {
    connected_ = true;
    return application::ClientResult<bool>::ok(true);
}

application::ClientResult<std::string> DefaultGatewayClient::send_message(const domain::ConversationId& conversation_id,
                                                                          std::string_view /*encrypted_envelope*/) {
    if (conversation_id.empty()) {
        return application::ClientResult<std::string>::error(
            application::ClientError::validation("Conversation ID cannot be empty"));
    }
    return application::ClientResult<std::string>::ok("msg-server-assigned-id");
}

application::ClientResult<std::vector<std::string>> DefaultGatewayClient::sync_messages(std::string_view /*cursor*/) {
    return application::ClientResult<std::vector<std::string>>::ok(std::vector<std::string>{});
}

application::ClientResult<bool> DefaultGatewayClient::validate_token(std::string_view token) {
    if (token.empty()) {
        return application::ClientResult<bool>::ok(false);
    }
    return application::ClientResult<bool>::ok(true);
}

application::ClientResult<void> DefaultGatewayClient::disconnect() {
    connected_ = false;
    return application::ClientResult<void>::ok();
}

} // namespace securecloud::client::infrastructure::adapters
