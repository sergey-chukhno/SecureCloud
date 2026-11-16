#pragma once

#include "application/client_error.hpp"
#include "application/interfaces/i_gateway_client.hpp"
#include "application/interfaces/i_local_store.hpp"
#include "domain/contact.hpp"
#include "domain/directory_user_entry.hpp"
#include "domain/user_id.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace securecloud::client::application::managers {

class SafetyNumberEngine;
class RatchetSessionManager;

class ContactManager {
  public:
    explicit ContactManager(interfaces::ILocalStore& local_store);
    ContactManager(interfaces::ILocalStore& local_store, interfaces::IGatewayClient& gateway_client,
                   SafetyNumberEngine& safety_number_engine);
    ~ContactManager() = default;

    ContactManager(const ContactManager&) = delete;
    ContactManager& operator=(const ContactManager&) = delete;

    // Optional dependency wiring
    void set_gateway_client(interfaces::IGatewayClient* gateway) noexcept { gateway_ = gateway; }
    void set_safety_number_engine(SafetyNumberEngine* safety_number_engine) noexcept {
        safety_number_engine_ = safety_number_engine;
    }
    void set_ratchet_session_manager(RatchetSessionManager* ratchet_session_manager) noexcept {
        ratchet_session_manager_ = ratchet_session_manager;
    }
    void set_local_identity(domain::UserId local_user_id, std::vector<uint8_t> local_identity_public_key);

    // Local Address Book CRUD
    ClientResult<void> add_or_update_contact(const domain::Contact& contact);
    ClientResult<domain::Contact> create_contact(const domain::UserId& user_id, const std::string& alias,
                                                 const std::string& safety_number, const std::string& role_note,
                                                 uint32_t authorized_device_count = 1);
    ClientResult<void> remove_contact(const domain::UserId& user_id);
    ClientResult<void> update_contact_alias(const domain::UserId& user_id, const std::string& new_alias,
                                            const std::string& new_role_note);
    ClientResult<std::vector<domain::Contact>> get_contacts();
    ClientResult<domain::Contact> get_contact(const domain::UserId& user_id);
    ClientResult<void> set_blocked(const domain::UserId& user_id, bool blocked);
    ClientResult<void> set_contact_blocked(const domain::UserId& user_id, bool blocked) {
        return set_blocked(user_id, blocked);
    }
    ClientResult<void> mark_contact_key_changed(const domain::UserId& user_id, const std::string& new_safety_number);
    ClientResult<void> verify_contact_key(const domain::UserId& user_id, bool verified);

    // Directory Discovery & Synchronization (CLIENT-008-T02)
    ClientResult<std::vector<domain::DirectoryUserEntry>> search_contacts(std::string_view query,
                                                                          std::size_t limit = 20);
    ClientResult<domain::Contact> add_contact_from_directory(const domain::DirectoryUserEntry& entry,
                                                             std::string_view local_alias = "",
                                                             std::string_view role_note = "");
    ClientResult<std::size_t> sync_contacts();
    ClientResult<domain::PresenceStatus> resolve_contact_presence(const domain::UserId& user_id,
                                                                  domain::PresenceStatus reported_presence);

  private:
    [[nodiscard]] bool has_mutual_conversation(const domain::UserId& peer_user_id) const;

    interfaces::ILocalStore& local_store_;
    interfaces::IGatewayClient* gateway_{nullptr};
    SafetyNumberEngine* safety_number_engine_{nullptr};
    RatchetSessionManager* ratchet_session_manager_{nullptr};

    domain::UserId local_user_id_;
    std::vector<uint8_t> local_identity_public_key_;
};

} // namespace securecloud::client::application::managers
