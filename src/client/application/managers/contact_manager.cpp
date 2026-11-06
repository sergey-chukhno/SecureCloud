#include "application/managers/contact_manager.hpp"

#include <chrono>

namespace securecloud::client::application::managers {

ContactManager::ContactManager(interfaces::ILocalStore& local_store) : local_store_(local_store) {}

ClientResult<void> ContactManager::add_or_update_contact(const domain::Contact& contact) {
    if (contact.user_id().empty()) {
        return ClientResult<void>::error(ClientError::validation("Contact user_id cannot be empty"));
    }
    return local_store_.save_contact(contact);
}

ClientResult<domain::Contact> ContactManager::create_contact(const domain::UserId& user_id, const std::string& alias,
                                                             const std::string& safety_number,
                                                             const std::string& role_note,
                                                             uint32_t authorized_device_count) {
    if (user_id.empty()) {
        return ClientResult<domain::Contact>::error(ClientError::validation("Contact user_id cannot be empty"));
    }
    if (alias.empty()) {
        return ClientResult<domain::Contact>::error(ClientError::validation("Contact alias cannot be empty"));
    }

    domain::Contact contact(user_id, alias, domain::KeyVerificationStatus::Unverified, /*identity_fingerprint=*/"",
                            /*is_blocked=*/false, safety_number, role_note, domain::PresenceStatus::Offline,
                            authorized_device_count, std::chrono::system_clock::now());

    const auto save_res = local_store_.save_contact(contact);
    if (save_res.is_error()) {
        return ClientResult<domain::Contact>::error(save_res.error());
    }
    return ClientResult<domain::Contact>::ok(std::move(contact));
}

ClientResult<void> ContactManager::remove_contact(const domain::UserId& user_id) {
    if (user_id.empty()) {
        return ClientResult<void>::error(ClientError::validation("Contact user_id cannot be empty"));
    }
    return local_store_.delete_contact(user_id);
}

ClientResult<void> ContactManager::update_contact_alias(const domain::UserId& user_id, const std::string& new_alias,
                                                        const std::string& new_role_note) {
    if (user_id.empty()) {
        return ClientResult<void>::error(ClientError::validation("Contact user_id cannot be empty"));
    }
    if (new_alias.empty()) {
        return ClientResult<void>::error(ClientError::validation("Contact alias cannot be empty"));
    }

    auto contact_res = local_store_.get_contact(user_id);
    if (contact_res.is_error()) {
        return ClientResult<void>::error(contact_res.error());
    }

    auto contact = contact_res.value();
    contact.set_alias(new_alias);
    contact.set_role_note(new_role_note);
    contact.set_updated_at(std::chrono::system_clock::now());
    return local_store_.save_contact(contact);
}

ClientResult<std::vector<domain::Contact>> ContactManager::get_contacts() {
    return local_store_.list_contacts();
}

ClientResult<domain::Contact> ContactManager::get_contact(const domain::UserId& user_id) {
    if (user_id.empty()) {
        return ClientResult<domain::Contact>::error(ClientError::validation("Contact user_id cannot be empty"));
    }
    return local_store_.get_contact(user_id);
}

ClientResult<void> ContactManager::set_blocked(const domain::UserId& user_id, bool blocked) {
    auto contact_res = local_store_.get_contact(user_id);
    if (contact_res.is_error()) {
        return ClientResult<void>::error(contact_res.error());
    }
    auto contact = contact_res.value();
    contact.set_blocked(blocked);
    contact.set_updated_at(std::chrono::system_clock::now());
    return local_store_.save_contact(contact);
}

ClientResult<void> ContactManager::mark_contact_key_changed(const domain::UserId& user_id,
                                                            const std::string& new_safety_number) {
    auto contact_res = local_store_.get_contact(user_id);
    if (contact_res.is_error()) {
        return ClientResult<void>::error(contact_res.error());
    }
    auto contact = contact_res.value();
    contact.set_verification_status(domain::KeyVerificationStatus::KeyChanged);
    if (!new_safety_number.empty()) {
        contact.set_safety_number(new_safety_number);
    }
    contact.set_updated_at(std::chrono::system_clock::now());
    return local_store_.save_contact(contact);
}

ClientResult<void> ContactManager::verify_contact_key(const domain::UserId& user_id, bool verified) {
    auto contact_res = local_store_.get_contact(user_id);
    if (contact_res.is_error()) {
        return ClientResult<void>::error(contact_res.error());
    }
    auto contact = contact_res.value();
    contact.set_verification_status(verified ? domain::KeyVerificationStatus::Verified
                                             : domain::KeyVerificationStatus::Unverified);
    contact.set_updated_at(std::chrono::system_clock::now());
    return local_store_.save_contact(contact);
}

} // namespace securecloud::client::application::managers
