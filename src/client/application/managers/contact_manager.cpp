#include "application/managers/contact_manager.hpp"

namespace securecloud::client::application::managers {

ContactManager::ContactManager(interfaces::ILocalStore& local_store) : local_store_(local_store) {}

ClientResult<void> ContactManager::add_or_update_contact(const domain::Contact& contact) {
    if (contact.user_id().empty()) {
        return ClientResult<void>::error(ClientError::validation("Contact user_id cannot be empty"));
    }
    return local_store_.save_contact(contact);
}

ClientResult<std::vector<domain::Contact>> ContactManager::get_contacts() {
    return local_store_.list_contacts();
}

ClientResult<void> ContactManager::set_blocked(const domain::UserId& user_id, bool blocked) {
    const auto list_res = local_store_.list_contacts();
    if (list_res.is_error()) {
        return ClientResult<void>::error(list_res.error());
    }

    for (auto c : list_res.value()) {
        if (c.user_id() == user_id) {
            c.set_blocked(blocked);
            return local_store_.save_contact(c);
        }
    }
    return ClientResult<void>::error(ClientError::storage("Contact not found"));
}

} // namespace securecloud::client::application::managers
