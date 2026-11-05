#include "infrastructure/gateway_adapter_stub.hpp"

#include <utility>

namespace securecloud::client::infrastructure {

GatewayAdapterStub::GatewayAdapterStub(std::string endpoint) : endpoint_(std::move(endpoint)) {}

const std::string& GatewayAdapterStub::endpoint() const noexcept {
    return endpoint_;
}

bool GatewayAdapterStub::isConnected() const noexcept {
    return connected_;
}

bool GatewayAdapterStub::probeGateway(std::string_view /*path*/) {
    // Stub probe implementation for CLIENT-001 foundation
    connected_ = true;
    return true;
}

} // namespace securecloud::client::infrastructure
