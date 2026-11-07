#pragma once

#include "application/client_error.hpp"
#include "application/interfaces/i_local_store.hpp"
#include "domain/contact.hpp"
#include "domain/user_id.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace securecloud::client::application::managers {

class ContactManager {
  public:
    explicit ContactManager(interfaces::ILocalStore& local_store);
    ~ContactManager() = default;

    ContactManager(const ContactManager&) = delete;
    ContactManager& operator=(const ContactManager&) = delete;

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

  private:
    interfaces::ILocalStore& local_store_;
};

} // namespace securecloud::client::application::managers
