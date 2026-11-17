#include "application/client_bootstrap.hpp"

#include "application/managers/device_pairing_coordinator.hpp"
#include "application/managers/ratchet_session_manager.hpp"
#include "application/managers/safety_number_engine.hpp"
#include "infrastructure/adapters/default_gateway_client.hpp"
#include "infrastructure/adapters/memory_local_store.hpp"
#include "infrastructure/adapters/memory_secure_storage.hpp"
#include "infrastructure/adapters/openssl_crypto_provider.hpp"
#include "infrastructure/adapters/simulated_hardware_authenticator.hpp"
#include "infrastructure/adapters/sqlcipher_local_store.hpp"
#include "infrastructure/adapters/stub_crypto_provider.hpp"

#include <stdexcept>

namespace securecloud::client::application {

ClientBootstrap::ClientBootstrap(ClientConfig config)
    : config_(std::move(config)), gateway_(std::make_unique<infrastructure::adapters::DefaultGatewayClient>(config_)),
      secure_storage_(std::make_unique<infrastructure::adapters::MemorySecureStorage>()),
      hardware_authenticator_(std::make_unique<infrastructure::adapters::SimulatedHardwareAuthenticator>()) {
    if (!config_.database_path.empty()) {
        crypto_provider_ = std::make_unique<infrastructure::adapters::OpenSslCryptoProvider>();
        auto sql_store =
            std::make_unique<infrastructure::adapters::SqlCipherLocalStore>(*secure_storage_, *crypto_provider_);
        const auto open_res = sql_store->open(config_.database_path);
        if (open_res.is_error()) {
            throw std::runtime_error("Failed to open encrypted SQLCipher store: " + open_res.error().user_message());
        }
        local_store_ = std::move(sql_store);
    } else {
        crypto_provider_ = std::make_unique<infrastructure::adapters::StubCryptoProvider>();
        local_store_ = std::make_unique<infrastructure::adapters::MemoryLocalStore>();
    }
    wire_managers();
}

ClientBootstrap::~ClientBootstrap() = default;

ClientBootstrap::ClientBootstrap(ClientBootstrap&&) noexcept = default;
ClientBootstrap& ClientBootstrap::operator=(ClientBootstrap&&) noexcept = default;

ClientBootstrap::ClientBootstrap(AdapterInitTag, ClientConfig config) : config_(std::move(config)) {}

std::unique_ptr<ClientBootstrap>
ClientBootstrap::create_with_adapters(ClientConfig config, std::unique_ptr<interfaces::IGatewayClient> gateway,
                                      std::unique_ptr<interfaces::ILocalStore> local_store,
                                      std::unique_ptr<interfaces::ISecureStorage> secure_storage,
                                      std::unique_ptr<interfaces::ICryptoProvider> crypto_provider) {
    auto bootstrap = std::unique_ptr<ClientBootstrap>(new ClientBootstrap(AdapterInitTag{}, std::move(config)));
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
    messaging_manager_ = std::make_unique<managers::MessagingManager>(*gateway_, *local_store_, *crypto_provider_,
                                                                      nullptr, secure_storage_.get());
    safety_number_engine_ = std::make_unique<managers::SafetyNumberEngine>(*crypto_provider_, *secure_storage_);
    contact_manager_ = std::make_unique<managers::ContactManager>(*local_store_, *gateway_, *safety_number_engine_);
    device_manager_ = std::make_unique<managers::DeviceManager>(*gateway_, *secure_storage_, *crypto_provider_);
    device_pairing_coordinator_ = std::make_unique<managers::DevicePairingCoordinator>(
        *gateway_, *secure_storage_, *crypto_provider_, *device_manager_);
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
    if (contact_manager_) {
        contact_manager_->set_ratchet_session_manager(ratchet_session_manager_.get());
    }
}

} // namespace securecloud::client::application
