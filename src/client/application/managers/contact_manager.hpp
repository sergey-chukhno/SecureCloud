#pragma once

#include "application/client_error.hpp"
#include "application/interfaces/i_local_store.hpp"
#include "domain/contact.hpp"
#include "domain/user_id.hpp"

#include <vector>

namespace securecloud::client::application::managers {

class ContactManager {
  public:
    explicit ContactManager(interfaces::ILocalStore& local_store);
    ~ContactManager() = default;

    ContactManager(const ContactManager&) = delete;
    ContactManager& operator=(const ContactManager&) = delete;

    ClientResult<void> add_or_update_contact(const domain::Contact& contact);
    ClientResult<std::vector<domain::Contact>> get_contacts();
    ClientResult<void> set_blocked(const domain::UserId& user_id, bool blocked);

  private:
    interfaces::ILocalStore& local_store_;
};

} // namespace securecloud::client::application::managers
