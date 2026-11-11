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
#include "application/managers/sync_manager.hpp"
#include "domain/device_id.hpp"
#include "domain/user_id.hpp"

#include <memory>

namespace securecloud::client::application::managers {
class RatchetSessionManager;
} // namespace securecloud::client::application::managers

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

    [[nodiscard]] interfaces::IGatewayClient& gateway() noexcept { return *gateway_; }
    [[nodiscard]] interfaces::ILocalStore& local_store() noexcept { return *local_store_; }
    [[nodiscard]] interfaces::ISecureStorage& secure_storage() noexcept { return *secure_storage_; }
    [[nodiscard]] interfaces::ICryptoProvider& crypto_provider() noexcept { return *crypto_provider_; }

    [[nodiscard]] managers::AuthManager& auth_manager() noexcept { return *auth_manager_; }
    [[nodiscard]] managers::MessagingManager& messaging_manager() noexcept { return *messaging_manager_; }
    [[nodiscard]] managers::ContactManager& contact_manager() noexcept { return *contact_manager_; }
    [[nodiscard]] managers::DeviceManager& device_manager() noexcept { return *device_manager_; }
    [[nodiscard]] managers::FileManager& file_manager() noexcept { return *file_manager_; }
    [[nodiscard]] managers::EmergencyManager& emergency_manager() noexcept { return *emergency_manager_; }
    [[nodiscard]] managers::SyncManager& sync_manager() noexcept { return *sync_manager_; }
    [[nodiscard]] managers::RatchetSessionManager* ratchet_session_manager() noexcept {
        return ratchet_session_manager_.get();
    }

    void initialize_ratchet_session_manager(const domain::UserId& user_id, const domain::DeviceId& device_id);

  private:
    void wire_managers();

    ClientConfig config_;

    // Adapters (instantiated first)
    std::unique_ptr<interfaces::IGatewayClient> gateway_;
    std::unique_ptr<interfaces::ILocalStore> local_store_;
    std::unique_ptr<interfaces::ISecureStorage> secure_storage_;
    std::unique_ptr<interfaces::ICryptoProvider> crypto_provider_;

    // Managers (instantiated second, destroyed first)
    std::unique_ptr<managers::AuthManager> auth_manager_;
    std::unique_ptr<managers::MessagingManager> messaging_manager_;
    std::unique_ptr<managers::RatchetSessionManager> ratchet_session_manager_;
    std::unique_ptr<managers::ContactManager> contact_manager_;
    std::unique_ptr<managers::DeviceManager> device_manager_;
    std::unique_ptr<managers::FileManager> file_manager_;
    std::unique_ptr<managers::EmergencyManager> emergency_manager_;
    std::unique_ptr<managers::SyncManager> sync_manager_;
};

} // namespace securecloud::client::application
