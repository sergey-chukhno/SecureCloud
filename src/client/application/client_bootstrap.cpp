#include "application/client_bootstrap.hpp"

#include "application/managers/device_pairing_coordinator.hpp"
#include "application/managers/ratchet_session_manager.hpp"
#include "application/managers/safety_number_engine.hpp"
#include "infrastructure/adapters/default_gateway_client.hpp"
#include "infrastructure/adapters/memory_local_store.hpp"
#include "infrastructure/adapters/memory_secure_storage.hpp"
#include "infrastructure/adapters/simulated_hardware_authenticator.hpp"
#include "infrastructure/adapters/stub_crypto_provider.hpp"

namespace securecloud::client::application {

ClientBootstrap::ClientBootstrap(ClientConfig config)
    : config_(std::move(config)), gateway_(std::make_unique<infrastructure::adapters::DefaultGatewayClient>(config_)),
      local_store_(std::make_unique<infrastructure::adapters::MemoryLocalStore>()),
      secure_storage_(std::make_unique<infrastructure::adapters::MemorySecureStorage>()),
      crypto_provider_(std::make_unique<infrastructure::adapters::StubCryptoProvider>()),
      hardware_authenticator_(std::make_unique<infrastructure::adapters::SimulatedHardwareAuthenticator>()) {
    wire_managers();
}

ClientBootstrap::~ClientBootstrap() = default;

ClientBootstrap::ClientBootstrap(ClientBootstrap&&) noexcept = default;
ClientBootstrap& ClientBootstrap::operator=(ClientBootstrap&&) noexcept = default;

std::unique_ptr<ClientBootstrap>
ClientBootstrap::create_with_adapters(ClientConfig config, std::unique_ptr<interfaces::IGatewayClient> gateway,
                                      std::unique_ptr<interfaces::ILocalStore> local_store,
                                      std::unique_ptr<interfaces::ISecureStorage> secure_storage,
                                      std::unique_ptr<interfaces::ICryptoProvider> crypto_provider) {
    auto bootstrap = std::unique_ptr<ClientBootstrap>(new ClientBootstrap(config));
    bootstrap->config_ = std::move(config);
    bootstrap->gateway_ = std::move(gateway);
    bootstrap->local_store_ = std::move(local_store);
    bootstrap->secure_storage_ = std::move(secure_storage);
    bootstrap->crypto_provider_ = std::move(crypto_provider);
    bootstrap->hardware_authenticator_ = std::make_unique<infrastructure::adapters::SimulatedHardwareAuthenticator>();
    bootstrap->wire_managers();
    return bootstrap;
}

void ClientBootstrap::wire_managers() {
    auth_manager_ = std::make_unique<managers::AuthManager>(*gateway_, *secure_storage_);
    messaging_manager_ = std::make_unique<managers::MessagingManager>(*gateway_, *local_store_, *crypto_provider_);
    contact_manager_ = std::make_unique<managers::ContactManager>(*local_store_);
    device_manager_ = std::make_unique<managers::DeviceManager>(*gateway_, *secure_storage_, *crypto_provider_);
    device_pairing_coordinator_ = std::make_unique<managers::DevicePairingCoordinator>(
        *gateway_, *secure_storage_, *crypto_provider_, *device_manager_);
    safety_number_engine_ = std::make_unique<managers::SafetyNumberEngine>(*crypto_provider_, *secure_storage_);
    file_manager_ = std::make_unique<managers::FileManager>(*gateway_, *crypto_provider_);
    emergency_manager_ = std::make_unique<managers::EmergencyManager>(*local_store_, *secure_storage_);
    sync_manager_ = std::make_unique<managers::SyncManager>(*gateway_, config_);
}

void ClientBootstrap::initialize_ratchet_session_manager(const domain::UserId& user_id,
                                                         const domain::DeviceId& device_id) {
    ratchet_session_manager_ = std::make_unique<managers::RatchetSessionManager>(*gateway_, *secure_storage_,
                                                                                 *crypto_provider_, user_id, device_id);
    if (messaging_manager_) {
        messaging_manager_->set_ratchet_session_manager(ratchet_session_manager_.get());
    }
    if (device_manager_) {
        device_manager_->set_ratchet_session_manager(ratchet_session_manager_.get());
    }
}

} // namespace securecloud::client::application
