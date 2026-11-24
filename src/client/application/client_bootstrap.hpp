#pragma once

#include "application/client_config.hpp"
#include "application/interfaces/i_crypto_provider.hpp"
#include "application/interfaces/i_gateway_client.hpp"
#include "application/interfaces/i_local_store.hpp"
#include "application/interfaces/i_secure_storage.hpp"
#include "application/managers/auth_manager.hpp"
#include "application/managers/contact_manager.hpp"
#include "application/managers/device_manager.hpp"
#include "application/managers/emergency_manager.hpp"
#include "application/managers/file_manager.hpp"
#include "application/managers/messaging_manager.hpp"
#include "application/managers/settings_manager.hpp"
#include "application/managers/sync_manager.hpp"
#include "domain/crypto/crypto_self_test.hpp"
#include "domain/device_id.hpp"
#include "domain/user_id.hpp"

#include <memory>
#include <optional>

namespace securecloud::client::application::interfaces {
class IHardwareAuthenticator;
} // namespace securecloud::client::application::interfaces

namespace securecloud::client::application::managers {
class RatchetSessionManager;
class DevicePairingCoordinator;
class DiagnosticsManager;
class LocalAuditLogger;
class SafetyNumberEngine;
} // namespace securecloud::client::application::managers

namespace securecloud::client::infrastructure::adapters {
class SwitchableGatewayClient;
} // namespace securecloud::client::infrastructure::adapters

namespace securecloud::client::application {

class ClientBootstrap {
  public:
    explicit ClientBootstrap(ClientConfig config);
    ~ClientBootstrap();

    ClientBootstrap(const ClientBootstrap&) = delete;
    ClientBootstrap& operator=(const ClientBootstrap&) = delete;
    ClientBootstrap(ClientBootstrap&&) noexcept;
    ClientBootstrap& operator=(ClientBootstrap&&) noexcept;

    static std::unique_ptr<ClientBootstrap>
    create_with_adapters(ClientConfig config, std::unique_ptr<interfaces::IGatewayClient> gateway,
                         std::unique_ptr<interfaces::ILocalStore> local_store,
                         std::unique_ptr<interfaces::ISecureStorage> secure_storage,
                         std::unique_ptr<interfaces::ICryptoProvider> crypto_provider);

    [[nodiscard]] const ClientConfig& config() const noexcept { return config_; }

    [[nodiscard]] interfaces::IGatewayClient& gateway() noexcept;
    [[nodiscard]] bool is_live_gateway_transport_active() const noexcept;
    [[nodiscard]] interfaces::ILocalStore& local_store() noexcept { return *local_store_; }
    [[nodiscard]] interfaces::ISecureStorage& secure_storage() noexcept { return *secure_storage_; }
    [[nodiscard]] interfaces::ICryptoProvider& crypto_provider() noexcept { return *crypto_provider_; }

    [[nodiscard]] managers::AuthManager& auth_manager() noexcept { return *auth_manager_; }
    [[nodiscard]] managers::MessagingManager& messaging_manager() noexcept { return *messaging_manager_; }
    [[nodiscard]] managers::ContactManager& contact_manager() noexcept { return *contact_manager_; }
    [[nodiscard]] managers::DeviceManager& device_manager() noexcept { return *device_manager_; }
    [[nodiscard]] managers::DevicePairingCoordinator& device_pairing_coordinator() noexcept {
        return *device_pairing_coordinator_;
    }
    [[nodiscard]] managers::SafetyNumberEngine& safety_number_engine() noexcept { return *safety_number_engine_; }
    [[nodiscard]] interfaces::IHardwareAuthenticator& hardware_authenticator() noexcept {
        return *hardware_authenticator_;
    }
    [[nodiscard]] managers::FileManager& file_manager() noexcept { return *file_manager_; }
    [[nodiscard]] managers::LocalAuditLogger* local_audit_logger() const noexcept { return local_audit_logger_.get(); }
    [[nodiscard]] const std::optional<domain::crypto::CryptoSelfTestReport>& last_self_test_report() const noexcept {
        return last_self_test_report_;
    }
    void set_last_self_test_report(domain::crypto::CryptoSelfTestReport report);
    void set_self_test_fault_injector(domain::crypto::CryptoSelfTest::FaultInjector injector);
    [[nodiscard]] domain::crypto::CryptoSelfTest::FaultInjector self_test_fault_injector() const;
    [[nodiscard]] managers::EmergencyManager& emergency_manager() noexcept { return *emergency_manager_; }
    [[nodiscard]] managers::SettingsManager& settings_manager() noexcept { return *settings_manager_; }
    [[nodiscard]] managers::SyncManager& sync_manager() noexcept { return *sync_manager_; }
    [[nodiscard]] managers::DiagnosticsManager& diagnostics_manager() noexcept { return *diagnostics_manager_; }
    [[nodiscard]] managers::RatchetSessionManager* ratchet_session_manager() noexcept {
        return ratchet_session_manager_.get();
    }

    void initialize_ratchet_session_manager(const domain::UserId& user_id, const domain::DeviceId& device_id);

  private:
    struct AdapterInitTag {};
    ClientBootstrap(AdapterInitTag, ClientConfig config);

    void wire_managers();

    ClientConfig config_;

    // Adapters (instantiated first; declared so secure_storage_ & crypto_provider_ outlive local_store_ & gateway_)
    std::unique_ptr<interfaces::ISecureStorage> secure_storage_;
    std::unique_ptr<interfaces::ICryptoProvider> crypto_provider_;
    std::unique_ptr<interfaces::IHardwareAuthenticator> hardware_authenticator_;
    std::unique_ptr<interfaces::ILocalStore> local_store_;
    std::unique_ptr<interfaces::IGatewayClient> gateway_;
    infrastructure::adapters::SwitchableGatewayClient* switchable_gateway_{nullptr};

    // Managers (instantiated second, destroyed first; local_audit_logger_ outlives sibling managers)
    std::unique_ptr<managers::LocalAuditLogger> local_audit_logger_;
    std::unique_ptr<managers::AuthManager> auth_manager_;
    std::unique_ptr<managers::MessagingManager> messaging_manager_;
    std::unique_ptr<managers::RatchetSessionManager> ratchet_session_manager_;
    std::unique_ptr<managers::ContactManager> contact_manager_;
    std::unique_ptr<managers::DeviceManager> device_manager_;
    std::unique_ptr<managers::DevicePairingCoordinator> device_pairing_coordinator_;
    std::unique_ptr<managers::SafetyNumberEngine> safety_number_engine_;
    std::unique_ptr<managers::FileManager> file_manager_;
    std::unique_ptr<managers::EmergencyManager> emergency_manager_;
    std::unique_ptr<managers::SettingsManager> settings_manager_;
    std::unique_ptr<managers::SyncManager> sync_manager_;
    std::unique_ptr<managers::DiagnosticsManager> diagnostics_manager_;

    std::optional<domain::crypto::CryptoSelfTestReport> last_self_test_report_;
    std::shared_ptr<domain::crypto::CryptoSelfTest::FaultInjector> self_test_fault_injector_;
};

} // namespace securecloud::client::application
