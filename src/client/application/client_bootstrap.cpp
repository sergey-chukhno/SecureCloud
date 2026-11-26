#include "application/client_bootstrap.hpp"

#include "application/managers/device_pairing_coordinator.hpp"
#include "application/managers/diagnostics_manager.hpp"
#include "application/managers/local_audit_logger.hpp"
#include "application/managers/ratchet_session_manager.hpp"
#include "application/managers/safety_number_engine.hpp"
#include "infrastructure/adapters/default_gateway_client.hpp"
#include "infrastructure/adapters/memory_local_store.hpp"
#include "infrastructure/adapters/memory_secure_storage.hpp"
#include "infrastructure/adapters/openssl_crypto_provider.hpp"
#include "infrastructure/adapters/simulated_hardware_authenticator.hpp"
#include "infrastructure/adapters/sqlcipher_local_store.hpp"
#include "infrastructure/adapters/stub_crypto_provider.hpp"
#include "infrastructure/adapters/switchable_gateway_client.hpp"

#include <stdexcept>

namespace securecloud::client::application {

ClientBootstrap::ClientBootstrap(ClientConfig config)
    : config_(std::move(config)), secure_storage_(std::make_unique<infrastructure::adapters::MemorySecureStorage>()),
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

    auto switchable = std::make_unique<infrastructure::adapters::SwitchableGatewayClient>(
        config_, [storage = secure_storage_.get()]() -> std::optional<common::configuration::SecretString> {
            if (storage == nullptr) {
                return std::nullopt;
            }
            const auto res = storage->get_secret("session_auth_token");
            if (res.is_ok()) {
                return res.value();
            }
            return std::nullopt;
        });
    switchable_gateway_ = switchable.get();
    gateway_ = std::move(switchable);
    wire_managers();
}

interfaces::IGatewayClient& ClientBootstrap::gateway() noexcept {
    if (switchable_gateway_ != nullptr) {
        return switchable_gateway_->active_gateway();
    }
    return *gateway_;
}

bool ClientBootstrap::is_live_gateway_transport_active() const noexcept {
    if (switchable_gateway_ != nullptr) {
        return switchable_gateway_->is_live_transport_active();
    }
    return config_.use_live_gateway_transport;
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
    local_audit_logger_ = std::make_unique<managers::LocalAuditLogger>(*local_store_);
    auth_manager_ = std::make_unique<managers::AuthManager>(*gateway_, *secure_storage_);
    messaging_manager_ = std::make_unique<managers::MessagingManager>(*gateway_, *local_store_, *crypto_provider_,
                                                                      nullptr, secure_storage_.get());
    safety_number_engine_ = std::make_unique<managers::SafetyNumberEngine>(*crypto_provider_, *secure_storage_);
    safety_number_engine_->set_local_audit_logger(local_audit_logger_.get());
    contact_manager_ = std::make_unique<managers::ContactManager>(*local_store_, *gateway_, *safety_number_engine_);
    device_manager_ = std::make_unique<managers::DeviceManager>(*gateway_, *secure_storage_, *crypto_provider_);
    device_manager_->set_local_audit_logger(local_audit_logger_.get());
    device_pairing_coordinator_ = std::make_unique<managers::DevicePairingCoordinator>(
        *gateway_, *secure_storage_, *crypto_provider_, *device_manager_);
    device_pairing_coordinator_->set_local_audit_logger(local_audit_logger_.get());
    file_manager_ = std::make_unique<managers::FileManager>(*gateway_, *crypto_provider_, local_store_.get(),
                                                            secure_storage_.get(), messaging_manager_.get());
    emergency_manager_ = std::make_unique<managers::EmergencyManager>(*local_store_, *secure_storage_);
    settings_manager_ = std::make_unique<managers::SettingsManager>(*local_store_, *secure_storage_, *gateway_, config_,
                                                                    file_manager_.get(), messaging_manager_.get());
    settings_manager_->set_local_audit_logger(local_audit_logger_.get());
    sync_manager_ = std::make_unique<managers::SyncManager>(*gateway_, config_);
    sync_manager_->set_local_store(local_store_.get());
    sync_manager_->set_messaging_manager(messaging_manager_.get());
    sync_manager_->set_contact_manager(contact_manager_.get());
    sync_manager_->set_file_manager(file_manager_.get());
    emergency_manager_->set_gateway_client(gateway_.get());
    emergency_manager_->set_messaging_manager(messaging_manager_.get());
    emergency_manager_->set_file_manager(file_manager_.get());
    emergency_manager_->set_sync_manager(sync_manager_.get());
    emergency_manager_->set_auth_manager(auth_manager_.get());
    emergency_manager_->set_settings_manager(settings_manager_.get());
    emergency_manager_->set_local_audit_logger(local_audit_logger_.get());
    auth_manager_->set_emergency_manager(emergency_manager_.get());
    if (switchable_gateway_ != nullptr) {
        settings_manager_->set_network_config_reload_callback(
            [switchable = switchable_gateway_](const ClientConfig& updated_config) {
                switchable->reconfigure(updated_config);
            });
    }
    diagnostics_manager_ = std::make_unique<managers::DiagnosticsManager>(
        config_, local_audit_logger_.get(), messaging_manager_.get(), file_manager_.get(), sync_manager_.get(),
        settings_manager_.get(), ratchet_session_manager_.get(),
        [this]() -> std::optional<domain::crypto::CryptoSelfTestReport> { return last_self_test_report_; },
        [switchable = switchable_gateway_]() -> domain::GatewayTransportMetrics {
            if (switchable != nullptr) {
                return switchable->transport_metrics();
            }
            return {};
        },
        [switchable = switchable_gateway_, &cfg = config_]() -> bool {
            if (switchable != nullptr) {
                return switchable->is_live_transport_active();
            }
            return cfg.use_live_gateway_transport;
        });
}

void ClientBootstrap::initialize_ratchet_session_manager(const domain::UserId& user_id,
                                                         const domain::DeviceId& device_id) {
    ratchet_session_manager_ = std::make_unique<managers::RatchetSessionManager>(*gateway_, *secure_storage_,
                                                                                 *crypto_provider_, user_id, device_id);
    if (messaging_manager_) {
        messaging_manager_->set_ratchet_session_manager(ratchet_session_manager_.get());
        messaging_manager_->set_local_device_id(device_id);
    }
    if (device_manager_) {
        device_manager_->set_ratchet_session_manager(ratchet_session_manager_.get());
    }
    if (contact_manager_) {
        contact_manager_->set_ratchet_session_manager(ratchet_session_manager_.get());
        if (device_manager_) {
            const auto dev_res = device_manager_->get_local_device();
            if (dev_res.is_ok() && !dev_res.value().crypto_identity().identity_key_bytes().empty()) {
                contact_manager_->set_local_identity(user_id, dev_res.value().crypto_identity().identity_key_bytes());
            }
        }
    }
    if (file_manager_) {
        file_manager_->set_local_identity(user_id, device_id);
    }
    if (sync_manager_) {
        sync_manager_->set_local_identity(user_id, device_id);
    }
    if (emergency_manager_) {
        emergency_manager_->set_ratchet_session_manager(ratchet_session_manager_.get());
    }
    if (local_audit_logger_) {
        ratchet_session_manager_->set_local_audit_logger(local_audit_logger_.get());
    }
    if (diagnostics_manager_) {
        diagnostics_manager_->set_ratchet_session_manager(ratchet_session_manager_.get());
    }
}

void ClientBootstrap::set_last_self_test_report(domain::crypto::CryptoSelfTestReport report) {
    last_self_test_report_ = std::move(report);
}

void ClientBootstrap::set_self_test_fault_injector(domain::crypto::CryptoSelfTest::FaultInjector injector) {
    if (injector) {
        self_test_fault_injector_ =
            std::make_shared<domain::crypto::CryptoSelfTest::FaultInjector>(std::move(injector));
    } else {
        self_test_fault_injector_.reset();
    }
}

domain::crypto::CryptoSelfTest::FaultInjector ClientBootstrap::self_test_fault_injector() const {
    if (self_test_fault_injector_ != nullptr) {
        return *self_test_fault_injector_;
    }
    return {};
}

} // namespace securecloud::client::application
