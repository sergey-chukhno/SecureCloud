#include "application/client_app_service.hpp"

#include <utility>

namespace securecloud::client::application {

ClientAppService::ClientAppService() : gateway_(std::make_unique<infrastructure::GatewayAdapterStub>()) {}

ClientAppService::ClientAppService(std::unique_ptr<infrastructure::GatewayAdapterStub> gateway)
    : gateway_(std::move(gateway)) {
    if (!gateway_) {
        gateway_ = std::make_unique<infrastructure::GatewayAdapterStub>();
    }
}

ClientAppService::~ClientAppService() = default;

ClientAppService::ClientAppService(ClientAppService&&) noexcept = default;
ClientAppService& ClientAppService::operator=(ClientAppService&&) noexcept = default;

bool ClientAppService::initialize() {
    return gateway_->probeGateway("/health");
}

const domain::SessionState& ClientAppService::sessionState() const noexcept {
    return sessionState_;
}

const infrastructure::GatewayAdapterStub& ClientAppService::gateway() const noexcept {
    return *gateway_;
}

void ClientAppService::updateSession(std::string userId, std::string deviceId) {
    sessionState_ = domain::SessionState(std::move(userId), std::move(deviceId), domain::SessionStatus::Active);
}

void ClientAppService::logout() {
    sessionState_.reset();
}

} // namespace securecloud::client::application
