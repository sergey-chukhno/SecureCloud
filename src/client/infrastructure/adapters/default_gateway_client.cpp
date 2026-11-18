#include "infrastructure/adapters/default_gateway_client.hpp"

#include "domain/prekey_policy.hpp"

#include <algorithm>
#include <cctype>
#include <iomanip>
#include <sstream>

namespace securecloud::client::infrastructure::adapters {

DefaultGatewayClient::DefaultGatewayClient(const application::ClientConfig& config) {
    std::ostringstream oss;
    oss << config.gateway_url << ":" << config.gateway_port;
    endpoint_ = oss.str();
}

application::ClientResult<bool> DefaultGatewayClient::probe_gateway(std::string_view /*path*/) {
    if (simulate_failure_) {
        return application::ClientResult<bool>::error(application::ClientError::network(failure_message_));
    }
    connected_ = true;
    return application::ClientResult<bool>::ok(true);
}

application::ClientResult<std::string> DefaultGatewayClient::send_message(const domain::ConversationId& conversation_id,
                                                                          std::string_view /*encrypted_envelope*/) {
    if (simulate_failure_) {
        return application::ClientResult<std::string>::error(application::ClientError::network(failure_message_));
    }
    if (simulate_submission_failure_) {
        return application::ClientResult<std::string>::error(
            application::ClientError::network(submission_failure_message_));
    }
    if (conversation_id.empty()) {
        return application::ClientResult<std::string>::error(
            application::ClientError::validation("Conversation ID cannot be empty"));
    }
    return application::ClientResult<std::string>::ok("msg-server-assigned-id");
}

application::ClientResult<std::string>
DefaultGatewayClient::submit_encrypted_message(const application::interfaces::FanOutSubmissionRequest& request) {
    if (simulate_failure_) {
        return application::ClientResult<std::string>::error(application::ClientError::network(failure_message_));
    }
    if (simulate_submission_failure_) {
        return application::ClientResult<std::string>::error(
            application::ClientError::network(submission_failure_message_));
    }
    if (request.conversation_id.empty()) {
        return application::ClientResult<std::string>::error(
            application::ClientError::validation("Conversation ID cannot be empty"));
    }
    if (request.device_payloads.empty() && !request.group_envelope_bytes.has_value()) {
        return application::ClientResult<std::string>::error(
            application::ClientError::validation("Encrypted message submission requires ciphertext payloads"));
    }
    submitted_fanouts_.push_back(request);
    return application::ClientResult<std::string>::ok("msg-srv-" + std::to_string(message_submission_counter_++));
}

application::ClientResult<std::vector<std::string>> DefaultGatewayClient::sync_messages(std::string_view /*cursor*/) {
    if (simulate_failure_) {
        return application::ClientResult<std::vector<std::string>>::error(
            application::ClientError::network(failure_message_));
    }
    return application::ClientResult<std::vector<std::string>>::ok(std::vector<std::string>{});
}

application::ClientResult<bool> DefaultGatewayClient::validate_token(std::string_view token) {
    if (simulate_failure_) {
        return application::ClientResult<bool>::error(application::ClientError::network(failure_message_));
    }
    if (token.empty()) {
        return application::ClientResult<bool>::ok(false);
    }
    return application::ClientResult<bool>::ok(true);
}

application::ClientResult<void> DefaultGatewayClient::disconnect() {
    connected_ = false;
    return application::ClientResult<void>::ok();
}

application::ClientResult<application::interfaces::DeviceRegistrationResult>
DefaultGatewayClient::register_device(const domain::UserId& user_id, const domain::PrekeyBundle& bundle) {
    if (simulate_failure_) {
        return application::ClientResult<application::interfaces::DeviceRegistrationResult>::error(
            application::ClientError::network(failure_message_));
    }
    if (user_id.empty()) {
        return application::ClientResult<application::interfaces::DeviceRegistrationResult>::error(
            application::ClientError::validation("User ID cannot be empty for device registration"));
    }
    if (bundle.identity_key().size() != domain::PrekeyPolicy::kEd25519PublicKeySize) {
        return application::ClientResult<application::interfaces::DeviceRegistrationResult>::error(
            application::ClientError::validation("Invalid identity key size in prekey bundle"));
    }
    if (bundle.signed_prekey().size() != domain::PrekeyPolicy::kX25519PublicKeySize) {
        return application::ClientResult<application::interfaces::DeviceRegistrationResult>::error(
            application::ClientError::validation("Invalid signed prekey size in prekey bundle"));
    }
    if (bundle.signed_prekey_signature().size() != domain::PrekeyPolicy::kEd25519SignatureSize) {
        return application::ClientResult<application::interfaces::DeviceRegistrationResult>::error(
            application::ClientError::validation("Invalid signed prekey signature size in prekey bundle"));
    }

    std::ostringstream oss;
    oss << "dev-" << std::setfill('0') << std::setw(6) << device_registration_counter_++;
    const domain::DeviceId assigned_id(oss.str());

    const auto status = simulated_reg_status_.value_or(domain::DeviceAuthorizationStatus::Authorized);
    const auto now = std::chrono::system_clock::now();

    application::interfaces::DeviceRegistrationResult result{
        .device_id = assigned_id,
        .status = status,
        .registered_at = now,
        .pairing_code = simulated_pairing_code_,
        .pairing_code_expires_at = now + std::chrono::minutes(15),
    };

    return application::ClientResult<application::interfaces::DeviceRegistrationResult>::ok(std::move(result));
}

application::ClientResult<application::interfaces::PrekeyUpdateResult>
DefaultGatewayClient::update_crypto_prekeys(const domain::DeviceId& device_id,
                                            std::optional<std::vector<uint8_t>> signed_prekey,
                                            std::optional<std::vector<uint8_t>> signed_prekey_signature,
                                            std::vector<domain::OneTimePrekeyRecord> one_time_prekeys) {
    if (simulate_failure_) {
        return application::ClientResult<application::interfaces::PrekeyUpdateResult>::error(
            application::ClientError::network(failure_message_));
    }
    if (device_id.empty()) {
        return application::ClientResult<application::interfaces::PrekeyUpdateResult>::error(
            application::ClientError::validation("Device ID cannot be empty for prekey update"));
    }

    if (signed_prekey.has_value() && signed_prekey->size() != domain::PrekeyPolicy::kX25519PublicKeySize) {
        return application::ClientResult<application::interfaces::PrekeyUpdateResult>::error(
            application::ClientError::validation("Invalid signed prekey size"));
    }
    if (signed_prekey_signature.has_value() &&
        signed_prekey_signature->size() != domain::PrekeyPolicy::kEd25519SignatureSize) {
        return application::ClientResult<application::interfaces::PrekeyUpdateResult>::error(
            application::ClientError::validation("Invalid signed prekey signature size"));
    }

    application::interfaces::PrekeyUpdateResult result{
        .active_one_time_prekey_count = static_cast<int32_t>(one_time_prekeys.size()),
        .updated_at = std::chrono::system_clock::now(),
    };

    return application::ClientResult<application::interfaces::PrekeyUpdateResult>::ok(std::move(result));
}

application::ClientResult<domain::PrekeyInventoryStatus>
DefaultGatewayClient::get_prekey_inventory_status(const domain::DeviceId& device_id) {
    if (simulate_failure_) {
        return application::ClientResult<domain::PrekeyInventoryStatus>::error(
            application::ClientError::network(failure_message_));
    }
    if (device_id.empty()) {
        return application::ClientResult<domain::PrekeyInventoryStatus>::error(
            application::ClientError::validation("Device ID cannot be empty for inventory status query"));
    }

    if (simulated_inventory_.has_value()) {
        return application::ClientResult<domain::PrekeyInventoryStatus>::ok(*simulated_inventory_);
    }

    // Default healthy status
    domain::PrekeyInventoryStatus default_status(100, 0,
                                                 static_cast<int32_t>(domain::PrekeyPolicy::kLowPrekeyThreshold),
                                                 std::chrono::system_clock::now(), std::chrono::seconds(0), false);
    return application::ClientResult<domain::PrekeyInventoryStatus>::ok(default_status);
}

application::ClientResult<std::vector<application::interfaces::DeviceCryptoDirectoryEntry>>
DefaultGatewayClient::get_device_crypto_directory(const domain::UserId& user_id,
                                                  const std::vector<domain::DeviceId>& /*device_ids*/) {
    if (simulate_failure_) {
        return application::ClientResult<std::vector<application::interfaces::DeviceCryptoDirectoryEntry>>::error(
            application::ClientError::network(failure_message_));
    }
    if (user_id.empty()) {
        return application::ClientResult<std::vector<application::interfaces::DeviceCryptoDirectoryEntry>>::error(
            application::ClientError::validation("User ID cannot be empty for crypto directory query"));
    }

    auto user_it = simulated_user_directories_.find(user_id);
    if (user_it != simulated_user_directories_.end()) {
        return application::ClientResult<std::vector<application::interfaces::DeviceCryptoDirectoryEntry>>::ok(
            user_it->second);
    }

    return application::ClientResult<std::vector<application::interfaces::DeviceCryptoDirectoryEntry>>::ok(
        simulated_directory_);
}

void DefaultGatewayClient::set_simulated_inventory_status(domain::PrekeyInventoryStatus status) {
    simulated_inventory_ = status;
}

void DefaultGatewayClient::set_simulated_registration_status(domain::DeviceAuthorizationStatus status,
                                                             std::string pairing_code) {
    simulated_reg_status_ = status;
    simulated_pairing_code_ = std::move(pairing_code);
}

void DefaultGatewayClient::set_simulated_directory(
    std::vector<application::interfaces::DeviceCryptoDirectoryEntry> directory) {
    simulated_directory_ = std::move(directory);
}

void DefaultGatewayClient::set_simulated_user_directory(
    const domain::UserId& user_id, std::vector<application::interfaces::DeviceCryptoDirectoryEntry> directory) {
    simulated_user_directories_[user_id] = std::move(directory);
}

void DefaultGatewayClient::set_simulated_failure(bool fail, std::string error_message) {
    simulate_failure_ = fail;
    failure_message_ = std::move(error_message);
}

application::ClientResult<application::interfaces::PairingInitiationResult>
DefaultGatewayClient::initiate_device_pairing(const domain::DeviceId& device_id) {
    if (simulate_failure_) {
        return application::ClientResult<application::interfaces::PairingInitiationResult>::error(
            application::ClientError::network(failure_message_));
    }
    if (device_id.empty()) {
        return application::ClientResult<application::interfaces::PairingInitiationResult>::error(
            application::ClientError::validation("Device ID cannot be empty for pairing initiation"));
    }

    if (simulated_pairing_result_.has_value()) {
        return application::ClientResult<application::interfaces::PairingInitiationResult>::ok(
            *simulated_pairing_result_);
    }

    application::interfaces::PairingInitiationResult res;
    res.device_id = device_id;
    res.pairing_code = simulated_pairing_code_.empty() ? "948201" : simulated_pairing_code_;
    res.expires_at = std::chrono::system_clock::now() + std::chrono::minutes(10);
    return application::ClientResult<application::interfaces::PairingInitiationResult>::ok(std::move(res));
}

application::ClientResult<void> DefaultGatewayClient::authorize_device_pairing(const domain::DeviceId& device_id,
                                                                               std::string_view pairing_code,
                                                                               std::string_view mfa_token) {
    if (simulate_failure_) {
        return application::ClientResult<void>::error(application::ClientError::network(failure_message_));
    }
    if (device_id.empty()) {
        return application::ClientResult<void>::error(
            application::ClientError::validation("Device ID cannot be empty for pairing authorization"));
    }
    if (pairing_code.empty()) {
        return application::ClientResult<void>::error(
            application::ClientError::validation("Pairing code cannot be empty for pairing authorization"));
    }

    if (require_mfa_for_authorization_) {
        if (mfa_token.empty()) {
            return application::ClientResult<void>::error(application::ClientError(
                application::ClientErrorCode::AuthenticationRequired, application::ClientErrorCategory::Authentication,
                "MFA verification required to authorize device pairing"));
        }
        if (mfa_token == "invalid" || mfa_token == "bad_token") {
            return application::ClientResult<void>::error(application::ClientError(
                application::ClientErrorCode::InvalidCredentials, application::ClientErrorCategory::Authentication,
                "Invalid MFA verification token"));
        }
    }

    // Update status in simulated device lists if present
    for (auto& [uid, devices] : simulated_user_devices_) {
        for (auto& dev : devices) {
            if (dev.device_id() == device_id) {
                dev.set_status(domain::DeviceAuthorizationStatus::Authorized);
                dev.set_trust_level(domain::DeviceTrustLevel::VerifiedOutOfBand);
            }
        }
    }

    return application::ClientResult<void>::ok();
}

application::ClientResult<std::vector<domain::Device>>
DefaultGatewayClient::list_user_devices(const domain::UserId& user_id) {
    if (simulate_failure_) {
        return application::ClientResult<std::vector<domain::Device>>::error(
            application::ClientError::network(failure_message_));
    }
    if (user_id.empty()) {
        return application::ClientResult<std::vector<domain::Device>>::error(
            application::ClientError::validation("User ID cannot be empty to list devices"));
    }

    auto it = simulated_user_devices_.find(user_id);
    if (it != simulated_user_devices_.end()) {
        return application::ClientResult<std::vector<domain::Device>>::ok(it->second);
    }

    return application::ClientResult<std::vector<domain::Device>>::ok({});
}

application::ClientResult<void> DefaultGatewayClient::revoke_device(const domain::DeviceId& device_id,
                                                                    std::string_view mfa_token) {
    if (simulate_failure_) {
        return application::ClientResult<void>::error(application::ClientError::network(failure_message_));
    }
    if (device_id.empty()) {
        return application::ClientResult<void>::error(
            application::ClientError::validation("Device ID cannot be empty to revoke device"));
    }

    if (require_mfa_for_revocation_) {
        if (mfa_token.empty()) {
            return application::ClientResult<void>::error(application::ClientError(
                application::ClientErrorCode::AuthenticationRequired, application::ClientErrorCategory::Authentication,
                "MFA verification required to revoke device"));
        }
        if (mfa_token == "invalid" || mfa_token == "bad_token") {
            return application::ClientResult<void>::error(application::ClientError(
                application::ClientErrorCode::InvalidCredentials, application::ClientErrorCategory::Authentication,
                "Invalid MFA verification token"));
        }
    }

    // 1. Mark status in simulated_user_devices_
    for (auto& [uid, devices] : simulated_user_devices_) {
        for (auto& dev : devices) {
            if (dev.device_id() == device_id) {
                dev.set_status(domain::DeviceAuthorizationStatus::Revoked);
                dev.set_trust_level(domain::DeviceTrustLevel::Revoked);
            }
        }
    }

    // 2. Mark status in simulated_directory_
    for (auto& entry : simulated_directory_) {
        if (entry.device_id == device_id) {
            entry.status = domain::DeviceAuthorizationStatus::Revoked;
        }
    }

    // 3. Mark status in simulated_user_directories_
    for (auto& [uid, dir] : simulated_user_directories_) {
        for (auto& entry : dir) {
            if (entry.device_id == device_id) {
                entry.status = domain::DeviceAuthorizationStatus::Revoked;
            }
        }
    }

    return application::ClientResult<void>::ok();
}

void DefaultGatewayClient::set_simulated_pairing_result(application::interfaces::PairingInitiationResult result) {
    simulated_pairing_result_ = std::move(result);
}

void DefaultGatewayClient::set_simulated_user_devices(const domain::UserId& user_id,
                                                      std::vector<domain::Device> devices) {
    simulated_user_devices_[user_id] = std::move(devices);
}

void DefaultGatewayClient::set_simulated_authorization_mfa_requirement(bool require_mfa) {
    require_mfa_for_authorization_ = require_mfa;
}

void DefaultGatewayClient::set_simulated_revocation_mfa_requirement(bool require_mfa) {
    require_mfa_for_revocation_ = require_mfa;
}

application::ClientResult<std::vector<domain::DirectoryUserEntry>>
DefaultGatewayClient::search_directory_users(std::string_view query, std::size_t limit) {
    if (simulate_failure_) {
        return application::ClientResult<std::vector<domain::DirectoryUserEntry>>::error(
            application::ClientError::network(failure_message_));
    }

    std::vector<domain::DirectoryUserEntry> results;
    results.reserve(std::min(simulated_directory_users_.size(), limit));

    auto to_lower = [](std::string_view sv) {
        std::string s;
        s.reserve(sv.size());
        for (const char c : sv) {
            s.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
        }
        return s;
    };

    const std::string lower_query = to_lower(query);

    for (const auto& entry : simulated_directory_users_) {
        if (results.size() >= limit) {
            break;
        }

        if (lower_query.empty()) {
            results.push_back(entry);
            continue;
        }

        const std::string lower_handle = to_lower(entry.handle());
        const std::string lower_display = to_lower(entry.display_name());
        const std::string lower_uid = to_lower(entry.user_id().value());

        if (lower_handle.find(lower_query) != std::string::npos ||
            lower_display.find(lower_query) != std::string::npos || lower_uid.find(lower_query) != std::string::npos) {
            results.push_back(entry);
        }
    }

    return application::ClientResult<std::vector<domain::DirectoryUserEntry>>::ok(std::move(results));
}

application::ClientResult<domain::DirectoryUserEntry>
DefaultGatewayClient::lookup_user_identity(const domain::UserId& user_id) {
    if (simulate_failure_) {
        return application::ClientResult<domain::DirectoryUserEntry>::error(
            application::ClientError::network(failure_message_));
    }

    if (user_id.empty()) {
        return application::ClientResult<domain::DirectoryUserEntry>::error(
            application::ClientError::validation("User ID cannot be empty"));
    }

    for (const auto& entry : simulated_directory_users_) {
        if (entry.user_id() == user_id) {
            return application::ClientResult<domain::DirectoryUserEntry>::ok(entry);
        }
    }

    return application::ClientResult<domain::DirectoryUserEntry>::error(
        application::ClientError::validation("User identity not found in directory: " + user_id.value()));
}

void DefaultGatewayClient::set_simulated_submission_failure(bool fail, std::string error_message) {
    simulate_submission_failure_ = fail;
    submission_failure_message_ = std::move(error_message);
}

void DefaultGatewayClient::set_simulated_directory_users(std::vector<domain::DirectoryUserEntry> users) {
    simulated_directory_users_ = std::move(users);
}

application::ClientResult<domain::DeliveryState>
DefaultGatewayClient::acknowledge_delivery(const domain::MessageId& message_id,
                                           const domain::DeviceId& recipient_device_id, int64_t delivered_at_ms) {
    if (simulate_failure_) {
        return application::ClientResult<domain::DeliveryState>::error(
            application::ClientError::network(failure_message_));
    }
    if (message_id.empty() || recipient_device_id.empty()) {
        return application::ClientResult<domain::DeliveryState>::error(
            application::ClientError::validation("Message ID and recipient device ID are required for delivery ack"));
    }

    sent_delivery_acks_.push_back(domain::DeliveryAckRecord{
        .message_id = message_id,
        .recipient_device_id = recipient_device_id,
        .delivered_at_ms = delivered_at_ms,
    });
    return application::ClientResult<domain::DeliveryState>::ok(domain::DeliveryState::Delivered);
}

application::ClientResult<domain::DeliveryState>
DefaultGatewayClient::send_read_receipt(const domain::ConversationId& conversation_id,
                                        const domain::MessageId& message_id, const domain::DeviceId& reader_device_id,
                                        int64_t read_at_ms) {
    if (simulate_failure_) {
        return application::ClientResult<domain::DeliveryState>::error(
            application::ClientError::network(failure_message_));
    }
    if (conversation_id.empty() || message_id.empty() || reader_device_id.empty()) {
        return application::ClientResult<domain::DeliveryState>::error(application::ClientError::validation(
            "Conversation ID, message ID, and reader device ID are required for read receipt"));
    }

    sent_read_receipts_.push_back(domain::ReadReceiptRecord{
        .conversation_id = conversation_id,
        .message_id = message_id,
        .reader_device_id = reader_device_id,
        .read_at_ms = read_at_ms,
    });
    return application::ClientResult<domain::DeliveryState>::ok(domain::DeliveryState::Read);
}

application::ClientResult<domain::MessageDeliveryStatusInfo>
DefaultGatewayClient::get_message_delivery_status(const domain::ConversationId& conversation_id,
                                                  const domain::MessageId& message_id) {
    if (simulate_failure_) {
        return application::ClientResult<domain::MessageDeliveryStatusInfo>::error(
            application::ClientError::network(failure_message_));
    }
    if (conversation_id.empty() || message_id.empty()) {
        return application::ClientResult<domain::MessageDeliveryStatusInfo>::error(
            application::ClientError::validation("Conversation ID and message ID are required"));
    }

    const auto it = simulated_delivery_statuses_.find(message_id);
    if (it != simulated_delivery_statuses_.end()) {
        return application::ClientResult<domain::MessageDeliveryStatusInfo>::ok(it->second);
    }

    return application::ClientResult<domain::MessageDeliveryStatusInfo>::ok(domain::MessageDeliveryStatusInfo{
        .message_id = message_id,
        .delivery_state = domain::DeliveryState::Accepted,
        .server_sequence_number = 0,
        .updated_at_ms = 0,
    });
}

application::ClientResult<domain::ConversationMessagesPage>
DefaultGatewayClient::fetch_conversation_messages(const domain::ConversationId& conversation_id,
                                                  const domain::DeviceId& recipient_device_id, uint64_t since_sequence,
                                                  std::size_t max_results) {
    if (simulate_failure_) {
        return application::ClientResult<domain::ConversationMessagesPage>::error(
            application::ClientError::network(failure_message_));
    }
    if (conversation_id.empty() || recipient_device_id.empty()) {
        return application::ClientResult<domain::ConversationMessagesPage>::error(
            application::ClientError::validation("Conversation ID and recipient device ID are required"));
    }

    domain::ConversationMessagesPage page;
    page.latest_sequence = since_sequence;

    const auto it = simulated_conversation_messages_.find(conversation_id);
    if (it == simulated_conversation_messages_.end()) {
        return application::ClientResult<domain::ConversationMessagesPage>::ok(std::move(page));
    }

    const std::size_t limit = max_results == 0 ? 50 : max_results;
    for (const auto& ev : it->second) {
        if (ev.server_sequence_number > since_sequence) {
            if (page.events.size() < limit) {
                page.events.push_back(ev);
                if (ev.server_sequence_number > page.latest_sequence) {
                    page.latest_sequence = ev.server_sequence_number;
                }
            } else {
                page.has_more = true;
                break;
            }
        }
    }

    return application::ClientResult<domain::ConversationMessagesPage>::ok(std::move(page));
}

uint64_t DefaultGatewayClient::subscribe_realtime_events(RealtimeEventHandler handler) {
    std::lock_guard<std::mutex> lock(event_mutex_);
    const uint64_t id = next_subscription_id_++;
    if (handler) {
        event_subscribers_.emplace(id, std::move(handler));
    }
    return id;
}

void DefaultGatewayClient::unsubscribe_realtime_events(uint64_t subscription_id) {
    std::lock_guard<std::mutex> lock(event_mutex_);
    event_subscribers_.erase(subscription_id);
}

void DefaultGatewayClient::emit_realtime_event(const domain::RealtimeEvent& event) {
    std::vector<RealtimeEventHandler> handlers;
    {
        std::lock_guard<std::mutex> lock(event_mutex_);
        handlers.reserve(event_subscribers_.size());
        for (const auto& [_, handler] : event_subscribers_) {
            handlers.push_back(handler);
        }
    }
    for (const auto& handler : handlers) {
        if (handler) {
            handler(event);
        }
    }
}

void DefaultGatewayClient::set_simulated_delivery_status(const domain::MessageId& message_id,
                                                         domain::MessageDeliveryStatusInfo status) {
    simulated_delivery_statuses_[message_id] = std::move(status);
}

void DefaultGatewayClient::set_simulated_conversation_messages(const domain::ConversationId& conversation_id,
                                                               std::vector<domain::RealtimeEvent> events) {
    simulated_conversation_messages_[conversation_id] = std::move(events);
}

} // namespace securecloud::client::infrastructure::adapters
