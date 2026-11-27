#include "application/managers/contact_manager.hpp"

#include "application/managers/ratchet_session_manager.hpp"
#include "application/managers/safety_number_engine.hpp"

#include <chrono>
#include <utility>

namespace securecloud::client::application::managers {

ContactManager::ContactManager(interfaces::ILocalStore& local_store) : local_store_(local_store) {}

ContactManager::ContactManager(interfaces::ILocalStore& local_store, interfaces::IGatewayClient& gateway_client,
                               SafetyNumberEngine& safety_number_engine)
    : local_store_(local_store), gateway_(&gateway_client), safety_number_engine_(&safety_number_engine) {}

void ContactManager::set_local_identity(domain::UserId local_user_id, std::vector<uint8_t> local_identity_public_key) {
    local_user_id_ = std::move(local_user_id);
    local_identity_public_key_ = std::move(local_identity_public_key);
}

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
    if (blocked) {
        contact.set_presence_status(domain::PresenceStatus::Offline);
    }
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
    const auto strict_res = set_contact_verified(user_id, verified);
    if (strict_res.is_ok()) {
        return strict_res;
    }

    // Preserve compatibility for locally seeded UI contacts (prior to directory wiring in T05)
    auto contact_res = local_store_.get_contact(user_id);
    if (contact_res.is_error()) {
        return strict_res;
    }

    auto contact = contact_res.value();
    contact.set_verification_status(verified ? domain::KeyVerificationStatus::Verified
                                             : domain::KeyVerificationStatus::Unverified);
    contact.set_updated_at(std::chrono::system_clock::now());
    return local_store_.save_contact(contact);
}

ClientResult<std::vector<domain::DirectoryUserEntry>> ContactManager::search_contacts(std::string_view query,
                                                                                      std::size_t limit) {
    if (gateway_ == nullptr) {
        return ClientResult<std::vector<domain::DirectoryUserEntry>>::error(
            ClientError::validation("Gateway client is not configured for directory search"));
    }
    return gateway_->search_directory_users(query, limit);
}

ClientResult<domain::Contact> ContactManager::add_contact_from_directory(const domain::DirectoryUserEntry& entry,
                                                                         std::string_view local_alias,
                                                                         std::string_view role_note) {
    if (entry.user_id().empty()) {
        return ClientResult<domain::Contact>::error(ClientError::validation("Directory user_id cannot be empty"));
    }

    std::string resolved_alias;
    if (!local_alias.empty()) {
        resolved_alias = std::string(local_alias);
    } else if (!entry.display_name().empty()) {
        resolved_alias = entry.display_name();
    } else {
        resolved_alias = entry.handle();
    }

    if (resolved_alias.empty()) {
        return ClientResult<domain::Contact>::error(
            ClientError::validation("Cannot onboard contact without an alias, display name, or handle"));
    }

    domain::KeyVerificationStatus verification_status = domain::KeyVerificationStatus::Unverified;
    std::string safety_number;

    if (safety_number_engine_ != nullptr && !entry.identity_public_key().empty()) {
        const auto eval_res =
            safety_number_engine_->evaluate_key_verification_status(entry.user_id(), entry.identity_public_key());
        if (eval_res.is_ok()) {
            verification_status = eval_res.value();
        }

        if (!local_user_id_.empty() && !local_identity_public_key_.empty()) {
            const auto sn_res = safety_number_engine_->compute_safety_number(
                local_user_id_, local_identity_public_key_, entry.user_id(), entry.identity_public_key());
            if (sn_res.is_ok()) {
                safety_number = sn_res.value();
            }
        }
    }

    domain::Contact contact(entry.user_id(), std::move(resolved_alias), verification_status,
                            entry.identity_fingerprint(), /*is_blocked=*/false, std::move(safety_number),
                            std::string(role_note), domain::PresenceStatus::Offline, entry.active_device_count(),
                            std::chrono::system_clock::now());

    const auto save_res = local_store_.save_contact(contact);
    if (save_res.is_error()) {
        return ClientResult<domain::Contact>::error(save_res.error());
    }

    return ClientResult<domain::Contact>::ok(std::move(contact));
}

ClientResult<std::size_t> ContactManager::sync_contacts() {
    if (gateway_ == nullptr) {
        return ClientResult<std::size_t>::error(
            ClientError::validation("Gateway client is not configured for contact synchronization"));
    }

    auto contacts_res = local_store_.list_contacts();
    if (contacts_res.is_error()) {
        return ClientResult<std::size_t>::error(contacts_res.error());
    }

    std::size_t synced_count = 0;
    const auto now = std::chrono::system_clock::now();

    for (auto contact : contacts_res.value()) {
        auto dir_res = gateway_->get_device_crypto_directory(contact.user_id());
        if (dir_res.is_error()) {
            return ClientResult<std::size_t>::error(dir_res.error());
        }

        std::vector<uint8_t> active_peer_key;
        std::string active_peer_fingerprint;

        const auto& directory = dir_res.value();
        if (!directory.empty()) {
            uint32_t authorized_count = 0;
            for (const auto& dev_entry : directory) {
                if (dev_entry.status == domain::DeviceAuthorizationStatus::Authorized) {
                    ++authorized_count;
                    if (active_peer_key.empty() && !dev_entry.identity_key.empty()) {
                        active_peer_key = dev_entry.identity_key;
                        active_peer_fingerprint = dev_entry.identity_key_fingerprint;
                    }
                    if (contact.identity_fingerprint().empty() && !dev_entry.identity_key_fingerprint.empty()) {
                        contact.set_identity_fingerprint(dev_entry.identity_key_fingerprint);
                    }
                } else if (dev_entry.status == domain::DeviceAuthorizationStatus::Revoked) {
                    if (ratchet_session_manager_ != nullptr) {
                        [[maybe_unused]] const auto term_res =
                            ratchet_session_manager_->terminate_session(contact.user_id(), dev_entry.device_id);
                    }
                }
            }
            contact.set_authorized_device_count(authorized_count);
        } else {
            const auto lookup_res = gateway_->lookup_user_identity(contact.user_id());
            if (lookup_res.is_ok()) {
                contact.set_authorized_device_count(lookup_res.value().active_device_count());
                active_peer_key = lookup_res.value().identity_public_key();
                active_peer_fingerprint = lookup_res.value().identity_fingerprint();
                if (contact.identity_fingerprint().empty() && !active_peer_fingerprint.empty()) {
                    contact.set_identity_fingerprint(active_peer_fingerprint);
                }
            }
        }

        // Automated Identity Key Change Detection during sync (ADR-008 §18, CLIENT-008-T04)
        bool key_changed_detected = false;
        if (safety_number_engine_ != nullptr && !active_peer_key.empty()) {
            const auto eval_res =
                safety_number_engine_->evaluate_key_verification_status(contact.user_id(), active_peer_key);
            const bool engine_flagged =
                eval_res.is_ok() && eval_res.value() == domain::KeyVerificationStatus::KeyChanged;
            const bool local_fp_mismatch = contact.verification_status() == domain::KeyVerificationStatus::Verified &&
                                           !contact.identity_fingerprint().empty() &&
                                           !active_peer_fingerprint.empty() &&
                                           contact.identity_fingerprint() != active_peer_fingerprint;

            if (engine_flagged || local_fp_mismatch) {
                contact.set_verification_status(domain::KeyVerificationStatus::KeyChanged);
                if (!active_peer_fingerprint.empty()) {
                    contact.set_identity_fingerprint(active_peer_fingerprint);
                }
                if (!local_user_id_.empty() && !local_identity_public_key_.empty()) {
                    const auto sn_res = safety_number_engine_->compute_safety_number(
                        local_user_id_, local_identity_public_key_, contact.user_id(), active_peer_key);
                    if (sn_res.is_ok()) {
                        contact.set_safety_number(sn_res.value());
                    }
                }
                key_changed_detected = true;
            } else if (contact.safety_number().empty() && !local_user_id_.empty() &&
                       !local_identity_public_key_.empty()) {
                const auto sn_res = safety_number_engine_->compute_safety_number(
                    local_user_id_, local_identity_public_key_, contact.user_id(), active_peer_key);
                if (sn_res.is_ok()) {
                    contact.set_safety_number(sn_res.value());
                }
            }
        }

        // Enforce Mutual-Conversation Privacy Shield on presence during sync (ADR-008 §24)
        if (contact.is_blocked() || contact.authorized_device_count() == 0 ||
            !has_mutual_conversation(contact.user_id())) {
            contact.set_presence_status(domain::PresenceStatus::Offline);
        }

        contact.set_updated_at(now);
        const auto save_res = local_store_.save_contact(contact);
        if (save_res.is_error()) {
            return ClientResult<std::size_t>::error(save_res.error());
        }

        if (key_changed_detected && key_change_alert_callback_) {
            key_change_alert_callback_(contact.user_id(), contact.safety_number());
        }

        ++synced_count;
    }

    return ClientResult<std::size_t>::ok(synced_count);
}

ClientResult<domain::PresenceStatus>
ContactManager::resolve_contact_presence(const domain::UserId& user_id, domain::PresenceStatus reported_presence) {
    if (user_id.empty()) {
        return ClientResult<domain::PresenceStatus>::error(ClientError::validation("Contact user_id cannot be empty"));
    }

    auto contact_res = local_store_.get_contact(user_id);
    if (contact_res.is_error()) {
        return ClientResult<domain::PresenceStatus>::error(contact_res.error());
    }

    auto contact = contact_res.value();
    const bool shielded =
        contact.is_blocked() || contact.authorized_device_count() == 0 || !has_mutual_conversation(user_id);

    const domain::PresenceStatus effective_presence = shielded ? domain::PresenceStatus::Offline : reported_presence;

    const auto now = std::chrono::system_clock::now();
    contact.set_presence_status(effective_presence);
    if (effective_presence == domain::PresenceStatus::Online || effective_presence == domain::PresenceStatus::Away) {
        contact.set_last_seen_at(now);
    }
    contact.set_updated_at(now);

    const auto save_res = local_store_.save_contact(contact);
    if (save_res.is_error()) {
        return ClientResult<domain::PresenceStatus>::error(save_res.error());
    }

    return ClientResult<domain::PresenceStatus>::ok(effective_presence);
}

ClientResult<std::string> ContactManager::get_or_compute_safety_number(const domain::UserId& peer_user_id) {
    if (peer_user_id.empty()) {
        return ClientResult<std::string>::error(
            ClientError::validation("Peer user_id cannot be empty for safety number computation"));
    }

    auto contact_res = local_store_.get_contact(peer_user_id);
    if (contact_res.is_error()) {
        return ClientResult<std::string>::error(contact_res.error());
    }

    auto contact = contact_res.value();
    if (!contact.safety_number().empty()) {
        return ClientResult<std::string>::ok(SafetyNumberEngine::format_safety_number(contact.safety_number()));
    }

    if (safety_number_engine_ == nullptr) {
        return ClientResult<std::string>::error(
            ClientError::validation("SafetyNumberEngine is not configured for safety number computation"));
    }
    if (local_user_id_.empty() || local_identity_public_key_.empty()) {
        return ClientResult<std::string>::error(
            ClientError::validation("Local user identity must be configured to compute safety numbers"));
    }

    const auto peer_key_res = resolve_peer_identity_key(peer_user_id);
    if (peer_key_res.is_error()) {
        return ClientResult<std::string>::error(peer_key_res.error());
    }

    const auto sn_res = safety_number_engine_->compute_safety_number(local_user_id_, local_identity_public_key_,
                                                                     peer_user_id, peer_key_res.value());
    if (sn_res.is_error()) {
        return ClientResult<std::string>::error(sn_res.error());
    }

    contact.set_safety_number(sn_res.value());
    contact.set_updated_at(std::chrono::system_clock::now());

    const auto save_res = local_store_.save_contact(contact);
    if (save_res.is_error()) {
        return ClientResult<std::string>::error(save_res.error());
    }

    return ClientResult<std::string>::ok(sn_res.value());
}

ClientResult<void> ContactManager::set_contact_verified(const domain::UserId& peer_user_id, bool verified) {
    if (peer_user_id.empty()) {
        return ClientResult<void>::error(
            ClientError::validation("Peer user_id cannot be empty for contact verification"));
    }

    auto contact_res = local_store_.get_contact(peer_user_id);
    if (contact_res.is_error()) {
        return ClientResult<void>::error(contact_res.error());
    }

    auto contact = contact_res.value();

    if (safety_number_engine_ != nullptr) {
        if (verified) {
            const auto peer_key_res = resolve_peer_identity_key(peer_user_id);
            if (peer_key_res.is_ok()) {
                const auto state_res =
                    safety_number_engine_->set_verification_state(peer_user_id, peer_key_res.value(), true);
                if (state_res.is_error()) {
                    return state_res;
                }
                const auto fp_res = safety_number_engine_->get_verified_fingerprint(peer_user_id);
                if (fp_res.is_ok() && fp_res.value().has_value()) {
                    contact.set_identity_fingerprint(*fp_res.value());
                }
            } else if (gateway_ != nullptr) {
                return ClientResult<void>::error(peer_key_res.error());
            }
        } else {
            const auto state_res = safety_number_engine_->set_verification_state(peer_user_id, {}, false);
            if (state_res.is_error()) {
                return state_res;
            }
        }
    }

    contact.set_verification_status(verified ? domain::KeyVerificationStatus::Verified
                                             : domain::KeyVerificationStatus::Unverified);
    contact.set_updated_at(std::chrono::system_clock::now());
    return local_store_.save_contact(contact);
}

ClientResult<domain::KeyVerificationStatus>
ContactManager::evaluate_contact_key_change(const domain::UserId& peer_user_id,
                                            std::span<const uint8_t> observed_identity_key) {
    if (peer_user_id.empty()) {
        return ClientResult<domain::KeyVerificationStatus>::error(
            ClientError::validation("Peer user_id cannot be empty for key change evaluation"));
    }
    if (observed_identity_key.empty()) {
        return ClientResult<domain::KeyVerificationStatus>::error(
            ClientError::validation("Observed peer identity key cannot be empty"));
    }
    if (safety_number_engine_ == nullptr) {
        return ClientResult<domain::KeyVerificationStatus>::error(
            ClientError::validation("SafetyNumberEngine is not configured for key change evaluation"));
    }

    auto contact_res = local_store_.get_contact(peer_user_id);
    if (contact_res.is_error()) {
        return ClientResult<domain::KeyVerificationStatus>::error(contact_res.error());
    }

    const auto eval_res = safety_number_engine_->evaluate_key_verification_status(peer_user_id, observed_identity_key);
    if (eval_res.is_error()) {
        return ClientResult<domain::KeyVerificationStatus>::error(eval_res.error());
    }

    if (eval_res.value() == domain::KeyVerificationStatus::KeyChanged) {
        auto contact = contact_res.value();
        contact.set_verification_status(domain::KeyVerificationStatus::KeyChanged);

        if (!local_user_id_.empty() && !local_identity_public_key_.empty()) {
            const auto sn_res = safety_number_engine_->compute_safety_number(local_user_id_, local_identity_public_key_,
                                                                             peer_user_id, observed_identity_key);
            if (sn_res.is_ok()) {
                contact.set_safety_number(sn_res.value());
            }
        }

        contact.set_updated_at(std::chrono::system_clock::now());
        const auto save_res = local_store_.save_contact(contact);
        if (save_res.is_error()) {
            return ClientResult<domain::KeyVerificationStatus>::error(save_res.error());
        }

        if (key_change_alert_callback_) {
            key_change_alert_callback_(peer_user_id, contact.safety_number());
        }
    } else if (!local_user_id_.empty() && !local_identity_public_key_.empty()) {
        const auto sn_res = safety_number_engine_->compute_safety_number(local_user_id_, local_identity_public_key_,
                                                                         peer_user_id, observed_identity_key);
        if (sn_res.is_ok()) {
            auto contact = contact_res.value();
            if (contact.safety_number() != sn_res.value()) {
                contact.set_safety_number(sn_res.value());
                contact.set_updated_at(std::chrono::system_clock::now());
                const auto save_res = local_store_.save_contact(contact);
                if (save_res.is_error()) {
                    return ClientResult<domain::KeyVerificationStatus>::error(save_res.error());
                }
            }
        }
    }

    return eval_res;
}

ClientResult<void> ContactManager::acknowledge_and_verify_key_change(const domain::UserId& peer_user_id) {
    if (peer_user_id.empty()) {
        return ClientResult<void>::error(
            ClientError::validation("Peer user_id cannot be empty to acknowledge key change"));
    }

    auto contact_res = local_store_.get_contact(peer_user_id);
    if (contact_res.is_error()) {
        return ClientResult<void>::error(contact_res.error());
    }

    auto contact = contact_res.value();
    contact.set_safety_number("");
    const auto clear_res = local_store_.save_contact(contact);
    if (clear_res.is_error()) {
        return clear_res;
    }

    const auto verify_res = set_contact_verified(peer_user_id, true);
    if (verify_res.is_error()) {
        return verify_res;
    }

    if (safety_number_engine_ != nullptr && !local_user_id_.empty() && !local_identity_public_key_.empty()) {
        [[maybe_unused]] const auto sn_res = get_or_compute_safety_number(peer_user_id);
    }

    return ClientResult<void>::ok();
}

bool ContactManager::has_mutual_conversation(const domain::UserId& peer_user_id) const {
    const auto convs_res = local_store_.list_conversations();
    if (!convs_res.is_ok()) {
        return false;
    }

    for (const auto& conv : convs_res.value()) {
        if (!conv.has_participant(peer_user_id)) {
            continue;
        }
        if (local_user_id_.empty() || conv.has_participant(local_user_id_)) {
            return true;
        }
    }

    return false;
}

ClientResult<std::vector<uint8_t>> ContactManager::resolve_peer_identity_key(const domain::UserId& peer_user_id) const {
    if (peer_user_id.empty()) {
        return ClientResult<std::vector<uint8_t>>::error(ClientError::validation("Peer user_id cannot be empty"));
    }

    if (gateway_ != nullptr) {
        const auto lookup_res = gateway_->lookup_user_identity(peer_user_id);
        if (lookup_res.is_ok() && !lookup_res.value().identity_public_key().empty()) {
            return ClientResult<std::vector<uint8_t>>::ok(lookup_res.value().identity_public_key());
        }

        const auto dir_res = gateway_->get_device_crypto_directory(peer_user_id);
        if (dir_res.is_ok()) {
            for (const auto& dev_entry : dir_res.value()) {
                if (dev_entry.status == domain::DeviceAuthorizationStatus::Authorized &&
                    !dev_entry.identity_key.empty()) {
                    return ClientResult<std::vector<uint8_t>>::ok(dev_entry.identity_key);
                }
            }
        }
    }

    return ClientResult<std::vector<uint8_t>>::error(
        ClientError::validation("Unable to resolve peer identity public key for user: " + peer_user_id.value()));
}

} // namespace securecloud::client::application::managers
