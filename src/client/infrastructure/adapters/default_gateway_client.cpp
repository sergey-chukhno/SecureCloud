#include "infrastructure/adapters/default_gateway_client.hpp"

#include "domain/crypto/file_crypto_engine.hpp"
#include "domain/prekey_policy.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <iomanip>
#include <span>
#include <sstream>

namespace securecloud::client::infrastructure::adapters {
namespace {

std::string to_lower_ascii(std::string_view sv) {
    std::string out;
    out.reserve(sv.size());
    for (const char ch : sv) {
        out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
    }
    return out;
}

int64_t current_unix_ms() noexcept {
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
        .count();
}

} // namespace

DefaultGatewayClient::DefaultGatewayClient(const application::ClientConfig& config)
    : pinned_tls_spki_sha256_(domain::normalize_hex_lower(config.pinned_tls_spki_sha256)) {
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
    page.next_sequence = since_sequence;
    page.latest_sequence = since_sequence;

    const auto it = simulated_conversation_messages_.find(conversation_id);
    if (it == simulated_conversation_messages_.end()) {
        const std::string cursor_key = recipient_device_id.value() + "|" + conversation_id.value();
        const auto cur_it = simulated_sync_cursors_.find(cursor_key);
        if (cur_it != simulated_sync_cursors_.end()) {
            page.cursor = cur_it->second;
        }
        return application::ClientResult<domain::ConversationMessagesPage>::ok(std::move(page));
    }

    std::vector<domain::RealtimeEvent> matching;
    matching.reserve(it->second.size());
    for (const auto& ev : it->second) {
        if (ev.server_sequence_number > since_sequence) {
            matching.push_back(ev);
        }
    }
    std::sort(matching.begin(), matching.end(), [](const domain::RealtimeEvent& a, const domain::RealtimeEvent& b) {
        return a.server_sequence_number < b.server_sequence_number;
    });

    const std::size_t limit = max_results == 0 ? 50 : max_results;
    const std::size_t take_count = std::min(matching.size(), limit);
    page.events.reserve(take_count);
    for (std::size_t i = 0; i < take_count; ++i) {
        page.events.push_back(matching[i]);
        if (matching[i].server_sequence_number > page.latest_sequence) {
            page.latest_sequence = matching[i].server_sequence_number;
        }
    }
    page.has_more = (matching.size() > take_count);
    page.next_sequence = page.events.empty() ? since_sequence : page.events.back().server_sequence_number;

    const std::string cursor_key = recipient_device_id.value() + "|" + conversation_id.value();
    const auto cur_it = simulated_sync_cursors_.find(cursor_key);
    if (cur_it != simulated_sync_cursors_.end()) {
        page.cursor = cur_it->second;
    } else if (!page.events.empty()) {
        page.cursor = domain::SyncCursorRecord{
            .device_id = recipient_device_id,
            .conversation_id = conversation_id,
            .last_delivered_sequence = page.next_sequence,
            .last_sync_timestamp_ms = current_unix_ms(),
            .sync_version = 1,
        };
    }

    return application::ClientResult<domain::ConversationMessagesPage>::ok(std::move(page));
}

application::ClientResult<domain::SyncCursorRecord>
DefaultGatewayClient::get_sync_cursor(const domain::DeviceId& device_id,
                                      const domain::ConversationId& conversation_id) {
    if (simulate_failure_) {
        return application::ClientResult<domain::SyncCursorRecord>::error(
            application::ClientError::network(failure_message_));
    }
    if (device_id.empty()) {
        return application::ClientResult<domain::SyncCursorRecord>::error(
            application::ClientError::validation("Device ID is required for get_sync_cursor"));
    }

    const std::string cursor_key = device_id.value() + "|" + conversation_id.value();
    const auto it = simulated_sync_cursors_.find(cursor_key);
    if (it != simulated_sync_cursors_.end()) {
        return application::ClientResult<domain::SyncCursorRecord>::ok(it->second);
    }

    return application::ClientResult<domain::SyncCursorRecord>::ok(domain::SyncCursorRecord{
        .device_id = device_id,
        .conversation_id = conversation_id,
        .last_delivered_sequence = 0,
        .last_sync_timestamp_ms = 0,
        .sync_version = 1,
    });
}

application::ClientResult<domain::SyncCursorRecord>
DefaultGatewayClient::update_sync_cursor(const domain::SyncCursorRecord& cursor) {
    if (simulate_failure_) {
        return application::ClientResult<domain::SyncCursorRecord>::error(
            application::ClientError::network(failure_message_));
    }
    if (cursor.device_id.empty()) {
        return application::ClientResult<domain::SyncCursorRecord>::error(
            application::ClientError::validation("Device ID is required for update_sync_cursor"));
    }

    const std::string cursor_key = cursor.device_id.value() + "|" + cursor.conversation_id.value();
    auto it = simulated_sync_cursors_.find(cursor_key);
    if (it == simulated_sync_cursors_.end()) {
        domain::SyncCursorRecord stored = cursor;
        if (stored.last_sync_timestamp_ms <= 0) {
            stored.last_sync_timestamp_ms = current_unix_ms();
        }
        simulated_sync_cursors_[cursor_key] = stored;
        return application::ClientResult<domain::SyncCursorRecord>::ok(std::move(stored));
    }

    const int64_t ts_ms = cursor.last_sync_timestamp_ms > 0 ? cursor.last_sync_timestamp_ms : current_unix_ms();
    (void)it->second.advance_monotonically(cursor.last_delivered_sequence, ts_ms);
    if (cursor.sync_version > it->second.sync_version) {
        it->second.sync_version = cursor.sync_version;
    }
    return application::ClientResult<domain::SyncCursorRecord>::ok(it->second);
}

application::ClientResult<std::vector<domain::RemoteConversationSummary>>
DefaultGatewayClient::list_remote_conversations(const domain::UserId& user_id, std::size_t max_results) {
    if (simulate_failure_) {
        return application::ClientResult<std::vector<domain::RemoteConversationSummary>>::error(
            application::ClientError::network(failure_message_));
    }
    if (user_id.empty()) {
        return application::ClientResult<std::vector<domain::RemoteConversationSummary>>::error(
            application::ClientError::validation("User ID is required for list_remote_conversations"));
    }

    const std::size_t limit = max_results == 0 ? 100U : max_results;
    std::vector<domain::RemoteConversationSummary> out;
    out.reserve(std::min(limit, simulated_remote_conversations_.size()));
    for (const auto& conv : simulated_remote_conversations_) {
        if (out.size() >= limit) {
            break;
        }
        const bool is_creator = (conv.creator_user_id == user_id);
        const bool is_participant = std::find(conv.participant_user_ids.begin(), conv.participant_user_ids.end(),
                                              user_id) != conv.participant_user_ids.end();
        if (is_creator || is_participant || conv.participant_user_ids.empty()) {
            out.push_back(conv);
        }
    }
    return application::ClientResult<std::vector<domain::RemoteConversationSummary>>::ok(std::move(out));
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

void DefaultGatewayClient::set_simulated_sync_cursor(const domain::SyncCursorRecord& cursor) {
    const std::string cursor_key = cursor.device_id.value() + "|" + cursor.conversation_id.value();
    simulated_sync_cursors_[cursor_key] = cursor;
}

void DefaultGatewayClient::set_simulated_remote_conversations(
    std::vector<domain::RemoteConversationSummary> conversations) {
    simulated_remote_conversations_ = std::move(conversations);
}

std::optional<application::ClientError> DefaultGatewayClient::check_file_network_failure_locked() const {
    if (simulate_failure_) {
        return application::ClientError::network(failure_message_);
    }
    if (simulate_file_transfer_failure_) {
        return application::ClientError::network(file_transfer_failure_message_);
    }
    return std::nullopt;
}

application::ClientResult<application::interfaces::FileUploadInitResult>
DefaultGatewayClient::init_file_upload(const application::interfaces::FileUploadInitRequest& request) {
    std::lock_guard<std::mutex> lock(file_store_mutex_);
    if (const auto err = check_file_network_failure_locked(); err.has_value()) {
        return application::ClientResult<application::interfaces::FileUploadInitResult>::error(*err);
    }

    if (request.file_id.empty() || request.owner_user_id.empty() || request.owner_device_id.empty() ||
        request.conversation_id.empty()) {
        return application::ClientResult<application::interfaces::FileUploadInitResult>::error(
            application::ClientError::validation(
                "File ID, owner user ID, owner device ID, and conversation ID are required"));
    }
    if (request.encrypted_size_bytes == 0ULL || request.encrypted_size_bytes > domain::kMaxEncryptedFileSizeBytes) {
        return application::ClientResult<application::interfaces::FileUploadInitResult>::error(
            application::ClientError::validation("Encrypted file size is outside allowed bounds (1 B .. 5 GiB)"));
    }
    if (request.expected_chunk_count == 0U) {
        return application::ClientResult<application::interfaces::FileUploadInitResult>::error(
            application::ClientError::validation("Expected chunk count must be positive"));
    }

    const int64_t now_ms = current_unix_ms();
    const std::string upload_id = "upload-srv-" + std::to_string(file_upload_counter_++);

    SimulatedUploadSession session;
    session.upload_id = upload_id;
    session.file_id = request.file_id;
    session.owner_user_id = request.owner_user_id;
    session.conversation_id = request.conversation_id;
    session.encrypted_size_bytes = request.encrypted_size_bytes;
    session.expected_chunk_count = request.expected_chunk_count;
    session.encryption_version = request.encryption_version.empty() ? "v1" : request.encryption_version;
    session.created_at_unix_ms = now_ms;
    simulated_upload_sessions_[upload_id] = std::move(session);

    return application::ClientResult<application::interfaces::FileUploadInitResult>::ok(
        application::interfaces::FileUploadInitResult{
            .upload_id = upload_id,
            .file_id = request.file_id,
            .status = "TRANSFER_STATUS_PENDING",
            .expires_at_unix_ms = now_ms + 3600000LL,
        });
}

application::ClientResult<application::interfaces::FileChunkUploadResult>
DefaultGatewayClient::upload_file_chunk(const application::interfaces::FileChunkUploadRequest& request) {
    std::lock_guard<std::mutex> lock(file_store_mutex_);
    if (const auto err = check_file_network_failure_locked(); err.has_value()) {
        return application::ClientResult<application::interfaces::FileChunkUploadResult>::error(*err);
    }
    if (simulated_failed_chunk_index_.has_value() && *simulated_failed_chunk_index_ == request.chunk_index) {
        return application::ClientResult<application::interfaces::FileChunkUploadResult>::error(
            application::ClientError::network(chunk_failure_message_));
    }

    if (request.upload_id.empty()) {
        return application::ClientResult<application::interfaces::FileChunkUploadResult>::error(
            application::ClientError::validation("Upload ID is required for chunk upload"));
    }

    const auto session_it = simulated_upload_sessions_.find(request.upload_id);
    if (session_it == simulated_upload_sessions_.end()) {
        return application::ClientResult<application::interfaces::FileChunkUploadResult>::error(
            application::ClientError::validation("Upload session not found: " + request.upload_id));
    }

    SimulatedUploadSession& session = session_it->second;
    if (session.cancelled) {
        return application::ClientResult<application::interfaces::FileChunkUploadResult>::error(
            application::ClientError::validation("Upload session has been cancelled"));
    }
    if (session.finalized) {
        return application::ClientResult<application::interfaces::FileChunkUploadResult>::error(
            application::ClientError::validation("Upload session is already finalized"));
    }
    if (request.chunk_index >= session.expected_chunk_count) {
        return application::ClientResult<application::interfaces::FileChunkUploadResult>::error(
            application::ClientError::validation("Chunk index out of expected range"));
    }
    if (request.encrypted_data.empty() ||
        request.encrypted_data.size() > static_cast<std::size_t>(domain::kMaxFileWireChunkSize)) {
        return application::ClientResult<application::interfaces::FileChunkUploadResult>::error(
            application::ClientError::validation("Encrypted chunk size is outside allowed bounds (1 B .. 8 MiB)"));
    }

    const auto digest_res = domain::crypto::StreamingSha256::digest_hex(request.encrypted_data);
    if (digest_res.is_error()) {
        return application::ClientResult<application::interfaces::FileChunkUploadResult>::error(digest_res.error());
    }
    const std::string& digest_hex = digest_res.value();
    if (!request.ciphertext_sha256.empty() && to_lower_ascii(request.ciphertext_sha256) != digest_hex) {
        return application::ClientResult<application::interfaces::FileChunkUploadResult>::error(
            application::ClientError::validation("Chunk ciphertext SHA-256 mismatch at chunk index " +
                                                 std::to_string(request.chunk_index)));
    }

    session.chunks[request.chunk_index] = SimulatedStagedChunk{
        .bytes = request.encrypted_data,
        .sha256_hex = digest_hex,
    };
    uploaded_chunk_call_counts_[session.file_id] += 1U;

    return application::ClientResult<application::interfaces::FileChunkUploadResult>::ok(
        application::interfaces::FileChunkUploadResult{
            .upload_id = request.upload_id,
            .chunk_index = request.chunk_index,
            .accepted = true,
            .received_sha256 = digest_hex,
        });
}

application::ClientResult<application::interfaces::FileUploadFinalizeResult>
DefaultGatewayClient::finalize_file_upload(const application::interfaces::FileUploadFinalizeRequest& request) {
    std::lock_guard<std::mutex> lock(file_store_mutex_);
    if (const auto err = check_file_network_failure_locked(); err.has_value()) {
        return application::ClientResult<application::interfaces::FileUploadFinalizeResult>::error(*err);
    }

    if (request.upload_id.empty() || request.file_id.empty()) {
        return application::ClientResult<application::interfaces::FileUploadFinalizeResult>::error(
            application::ClientError::validation("Upload ID and file ID are required to finalize upload"));
    }

    const auto session_it = simulated_upload_sessions_.find(request.upload_id);
    if (session_it == simulated_upload_sessions_.end()) {
        return application::ClientResult<application::interfaces::FileUploadFinalizeResult>::error(
            application::ClientError::validation("Upload session not found: " + request.upload_id));
    }

    SimulatedUploadSession& session = session_it->second;
    if (session.file_id != request.file_id) {
        return application::ClientResult<application::interfaces::FileUploadFinalizeResult>::error(
            application::ClientError::validation("Upload session file ID mismatch"));
    }
    if (session.cancelled) {
        return application::ClientResult<application::interfaces::FileUploadFinalizeResult>::error(
            application::ClientError::validation("Cannot finalize cancelled upload session"));
    }
    if (session.finalized) {
        return application::ClientResult<application::interfaces::FileUploadFinalizeResult>::error(
            application::ClientError::validation("Upload session is already finalized"));
    }

    SimulatedStoredFile stored;
    stored.chunks.reserve(session.expected_chunk_count);
    stored.chunk_sha256s.reserve(session.expected_chunk_count);
    domain::crypto::StreamingSha256 total_hasher;
    uint64_t total_size_bytes = 0ULL;

    for (uint32_t idx = 0; idx < session.expected_chunk_count; ++idx) {
        const auto chunk_it = session.chunks.find(idx);
        if (chunk_it == session.chunks.end()) {
            return application::ClientResult<application::interfaces::FileUploadFinalizeResult>::error(
                application::ClientError::validation("Missing chunk index " + std::to_string(idx) +
                                                     " during finalize"));
        }
        if (const auto upd = total_hasher.update(chunk_it->second.bytes); upd.is_error()) {
            return application::ClientResult<application::interfaces::FileUploadFinalizeResult>::error(upd.error());
        }
        total_size_bytes += static_cast<uint64_t>(chunk_it->second.bytes.size());
        stored.chunks.push_back(chunk_it->second.bytes);
        stored.chunk_sha256s.push_back(chunk_it->second.sha256_hex);
    }

    const auto finalized_sha256 = total_hasher.finalize_hex();
    if (finalized_sha256.is_error()) {
        return application::ClientResult<application::interfaces::FileUploadFinalizeResult>::error(
            finalized_sha256.error());
    }
    if (!request.expected_ciphertext_sha256.empty() &&
        to_lower_ascii(request.expected_ciphertext_sha256) != finalized_sha256.value()) {
        return application::ClientResult<application::interfaces::FileUploadFinalizeResult>::error(
            application::ClientError::validation("Finalized ciphertext SHA-256 mismatch"));
    }

    const int64_t available_at_ms = current_unix_ms();
    stored.metadata = application::interfaces::RemoteFileMetadata{
        .file_id = session.file_id,
        .owner_user_id = session.owner_user_id,
        .conversation_id = session.conversation_id,
        .lifecycle_state = "FILE_LIFECYCLE_STATE_AVAILABLE",
        .encrypted_size_bytes = total_size_bytes,
        .chunk_count = session.expected_chunk_count,
        .encryption_version = session.encryption_version,
        .ciphertext_integrity_hash = finalized_sha256.value(),
        .created_at_unix_ms = session.created_at_unix_ms,
        .available_at_unix_ms = available_at_ms,
    };

    simulated_stored_files_[session.file_id] = std::move(stored);
    session.finalized = true;
    session.chunks.clear();

    return application::ClientResult<application::interfaces::FileUploadFinalizeResult>::ok(
        application::interfaces::FileUploadFinalizeResult{
            .file_id = request.file_id,
            .lifecycle_state = "FILE_LIFECYCLE_STATE_AVAILABLE",
            .available_at_unix_ms = available_at_ms,
        });
}

application::ClientResult<void> DefaultGatewayClient::cancel_file_upload(std::string_view upload_id,
                                                                         std::string_view /*reason*/) {
    std::lock_guard<std::mutex> lock(file_store_mutex_);
    if (const auto err = check_file_network_failure_locked(); err.has_value()) {
        return application::ClientResult<void>::error(*err);
    }
    if (upload_id.empty()) {
        return application::ClientResult<void>::error(
            application::ClientError::validation("Upload ID is required to cancel upload"));
    }

    const auto session_it = simulated_upload_sessions_.find(std::string(upload_id));
    if (session_it == simulated_upload_sessions_.end()) {
        return application::ClientResult<void>::error(
            application::ClientError::validation("Upload session not found: " + std::string(upload_id)));
    }
    if (session_it->second.finalized) {
        return application::ClientResult<void>::error(
            application::ClientError::validation("Cannot cancel finalized upload session"));
    }

    session_it->second.cancelled = true;
    session_it->second.chunks.clear();
    return application::ClientResult<void>::ok();
}

application::ClientResult<application::interfaces::RemoteFileMetadata>
DefaultGatewayClient::get_file_metadata(std::string_view file_id) {
    std::lock_guard<std::mutex> lock(file_store_mutex_);
    if (const auto err = check_file_network_failure_locked(); err.has_value()) {
        return application::ClientResult<application::interfaces::RemoteFileMetadata>::error(*err);
    }
    if (file_id.empty()) {
        return application::ClientResult<application::interfaces::RemoteFileMetadata>::error(
            application::ClientError::validation("File ID is required for metadata lookup"));
    }

    const auto it = simulated_stored_files_.find(std::string(file_id));
    if (it == simulated_stored_files_.end() || it->second.deleted) {
        return application::ClientResult<application::interfaces::RemoteFileMetadata>::error(
            application::ClientError::validation("File not found or deleted: " + std::string(file_id)));
    }
    return application::ClientResult<application::interfaces::RemoteFileMetadata>::ok(it->second.metadata);
}

application::ClientResult<application::interfaces::FileChunkDownloadResult>
DefaultGatewayClient::download_file_chunk(std::string_view file_id, uint32_t chunk_index) {
    std::lock_guard<std::mutex> lock(file_store_mutex_);
    if (const auto err = check_file_network_failure_locked(); err.has_value()) {
        return application::ClientResult<application::interfaces::FileChunkDownloadResult>::error(*err);
    }
    if (simulated_failed_chunk_index_.has_value() && *simulated_failed_chunk_index_ == chunk_index) {
        return application::ClientResult<application::interfaces::FileChunkDownloadResult>::error(
            application::ClientError::network(chunk_failure_message_));
    }
    if (file_id.empty()) {
        return application::ClientResult<application::interfaces::FileChunkDownloadResult>::error(
            application::ClientError::validation("File ID is required for chunk download"));
    }

    const auto it = simulated_stored_files_.find(std::string(file_id));
    if (it == simulated_stored_files_.end() || it->second.deleted) {
        return application::ClientResult<application::interfaces::FileChunkDownloadResult>::error(
            application::ClientError::validation("File not found or deleted: " + std::string(file_id)));
    }
    if (chunk_index >= it->second.chunks.size()) {
        return application::ClientResult<application::interfaces::FileChunkDownloadResult>::error(
            application::ClientError::validation("Requested chunk index out of range"));
    }

    return application::ClientResult<application::interfaces::FileChunkDownloadResult>::ok(
        application::interfaces::FileChunkDownloadResult{
            .file_id = std::string(file_id),
            .chunk_index = chunk_index,
            .encrypted_data = it->second.chunks[chunk_index],
            .ciphertext_sha256 = it->second.chunk_sha256s[chunk_index],
        });
}

application::ClientResult<void> DefaultGatewayClient::delete_file(std::string_view file_id) {
    std::lock_guard<std::mutex> lock(file_store_mutex_);
    if (const auto err = check_file_network_failure_locked(); err.has_value()) {
        return application::ClientResult<void>::error(*err);
    }
    if (file_id.empty()) {
        return application::ClientResult<void>::error(
            application::ClientError::validation("File ID is required for deletion"));
    }

    const auto it = simulated_stored_files_.find(std::string(file_id));
    if (it == simulated_stored_files_.end() || it->second.deleted) {
        return application::ClientResult<void>::error(
            application::ClientError::validation("File not found or already deleted: " + std::string(file_id)));
    }

    it->second.deleted = true;
    it->second.metadata.lifecycle_state = "FILE_LIFECYCLE_STATE_DELETED";
    it->second.chunks.clear();
    it->second.chunk_sha256s.clear();
    return application::ClientResult<void>::ok();
}

void DefaultGatewayClient::set_simulated_file_transfer_failure(bool fail, std::string error_message) {
    std::lock_guard<std::mutex> lock(file_store_mutex_);
    simulate_file_transfer_failure_ = fail;
    file_transfer_failure_message_ = std::move(error_message);
}

void DefaultGatewayClient::set_simulated_chunk_failure(std::optional<uint32_t> chunk_index, std::string error_message) {
    std::lock_guard<std::mutex> lock(file_store_mutex_);
    simulated_failed_chunk_index_ = chunk_index;
    chunk_failure_message_ = std::move(error_message);
}

bool DefaultGatewayClient::mutate_stored_file_chunk_for_test(std::string_view file_id, uint32_t chunk_index,
                                                             std::vector<uint8_t> tampered_bytes,
                                                             bool recompute_server_sha256) {
    std::lock_guard<std::mutex> lock(file_store_mutex_);
    const auto it = simulated_stored_files_.find(std::string(file_id));
    if (it == simulated_stored_files_.end() || it->second.deleted || chunk_index >= it->second.chunks.size()) {
        return false;
    }

    it->second.chunks[chunk_index] = std::move(tampered_bytes);
    uint64_t new_total = 0ULL;
    for (const auto& chunk : it->second.chunks) {
        new_total += static_cast<uint64_t>(chunk.size());
    }
    it->second.metadata.encrypted_size_bytes = new_total;

    if (recompute_server_sha256) {
        const auto chunk_sha = domain::crypto::StreamingSha256::digest_hex(it->second.chunks[chunk_index]);
        if (chunk_sha.is_error()) {
            return false;
        }
        it->second.chunk_sha256s[chunk_index] = chunk_sha.value();

        domain::crypto::StreamingSha256 total_hasher;
        for (const auto& chunk : it->second.chunks) {
            if (total_hasher.update(chunk).is_error()) {
                return false;
            }
        }
        const auto total_sha = total_hasher.finalize_hex();
        if (total_sha.is_error()) {
            return false;
        }
        it->second.metadata.ciphertext_integrity_hash = total_sha.value();
    }

    return true;
}

std::size_t DefaultGatewayClient::uploaded_chunk_call_count(std::string_view file_id) const {
    std::lock_guard<std::mutex> lock(file_store_mutex_);
    const auto it = uploaded_chunk_call_counts_.find(std::string(file_id));
    return it == uploaded_chunk_call_counts_.end() ? 0U : it->second;
}

bool DefaultGatewayClient::has_stored_file(std::string_view file_id) const {
    std::lock_guard<std::mutex> lock(file_store_mutex_);
    const auto it = simulated_stored_files_.find(std::string(file_id));
    return it != simulated_stored_files_.end() && !it->second.deleted;
}

std::vector<uint8_t> DefaultGatewayClient::stored_file_raw_bytes(std::string_view file_id) const {
    std::lock_guard<std::mutex> lock(file_store_mutex_);
    const auto it = simulated_stored_files_.find(std::string(file_id));
    if (it == simulated_stored_files_.end() || it->second.deleted) {
        return {};
    }

    std::size_t total_size = 0U;
    for (const auto& chunk : it->second.chunks) {
        total_size += chunk.size();
    }
    std::vector<uint8_t> combined;
    combined.reserve(total_size);
    for (const auto& chunk : it->second.chunks) {
        combined.insert(combined.end(), chunk.begin(), chunk.end());
    }
    return combined;
}

application::ClientResult<domain::UserProfile> DefaultGatewayClient::get_user_profile(const domain::UserId& user_id) {
    if (simulate_failure_) {
        return application::ClientResult<domain::UserProfile>::error(
            application::ClientError::network(failure_message_));
    }
    if (user_id.empty()) {
        return application::ClientResult<domain::UserProfile>::error(
            application::ClientError::validation("User ID cannot be empty"));
    }

    std::lock_guard<std::mutex> lock(profile_tls_mutex_);
    if (const auto it = simulated_user_profiles_.find(user_id); it != simulated_user_profiles_.end()) {
        return application::ClientResult<domain::UserProfile>::ok(it->second);
    }

    domain::UserProfile profile;
    profile.user_id = user_id;
    profile.display_name = "SecureCloud User";
    profile.allow_handle_discovery = true;
    profile.updated_at_ms = current_unix_ms();
    return application::ClientResult<domain::UserProfile>::ok(std::move(profile));
}

application::ClientResult<application::interfaces::UserProfileSyncResult>
DefaultGatewayClient::update_user_profile(const domain::UserProfile& public_profile) {
    if (simulate_failure_) {
        return application::ClientResult<application::interfaces::UserProfileSyncResult>::error(
            application::ClientError::network(failure_message_));
    }
    const auto errors = public_profile.validate();
    if (!errors.empty()) {
        return application::ClientResult<application::interfaces::UserProfileSyncResult>::error(
            application::ClientError::validation(errors.front()));
    }

    if (!public_profile.allow_handle_discovery) {
        application::interfaces::UserProfileSyncResult res;
        res.profile = public_profile;
        res.sync_status = application::interfaces::ProfileSyncStatus::SyncDisabledByPrivacyPolicy;
        return application::ClientResult<application::interfaces::UserProfileSyncResult>::ok(std::move(res));
    }

    std::lock_guard<std::mutex> lock(profile_tls_mutex_);
    ++profile_update_call_count_;

    if (simulate_profile_sync_unsupported_) {
        application::interfaces::UserProfileSyncResult res;
        res.profile = public_profile;
        res.sync_status = application::interfaces::ProfileSyncStatus::LocalOnlyServerUnsupported;
        return application::ClientResult<application::interfaces::UserProfileSyncResult>::ok(std::move(res));
    }

    domain::UserProfile stored = public_profile;
    stored.avatar_sha256 = domain::normalize_hex_lower(stored.avatar_sha256);
    if (stored.updated_at_ms == 0) {
        stored.updated_at_ms = current_unix_ms();
    }
    simulated_user_profiles_[stored.user_id] = stored;

    application::interfaces::UserProfileSyncResult res;
    res.profile = std::move(stored);
    res.sync_status = application::interfaces::ProfileSyncStatus::Synced;
    return application::ClientResult<application::interfaces::UserProfileSyncResult>::ok(std::move(res));
}

application::ClientResult<application::interfaces::TlsCertificateInfo>
DefaultGatewayClient::inspect_tls_certificate(std::string_view host, uint16_t port) {
    if (simulate_failure_) {
        return application::ClientResult<application::interfaces::TlsCertificateInfo>::error(
            application::ClientError::network(failure_message_));
    }
    if (host.empty()) {
        return application::ClientResult<application::interfaces::TlsCertificateInfo>::error(
            application::ClientError::validation("TLS inspection host cannot be empty"));
    }
    if (port == 0U) {
        return application::ClientResult<application::interfaces::TlsCertificateInfo>::error(
            application::ClientError::validation("TLS inspection port must be non-zero"));
    }

    std::lock_guard<std::mutex> lock(profile_tls_mutex_);
    application::interfaces::TlsCertificateInfo info;
    if (simulated_tls_cert_.has_value()) {
        info = *simulated_tls_cert_;
        if (info.host.empty()) {
            info.host = std::string(host);
        }
        if (info.port == 0U) {
            info.port = port;
        }
    } else {
        const int64_t now_ms = current_unix_ms();
        info.host = std::string(host);
        info.port = port;
        info.subject_cn = std::string(host);
        info.issuer_cn = "SecureCloud Local Dev CA";
        info.spki_sha256_hex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        info.valid_from_ms = now_ms - 86400000LL;
        info.valid_until_ms = now_ms + 31536000000LL;
    }

    info.spki_sha256_hex = domain::normalize_hex_lower(info.spki_sha256_hex);
    info.has_pinned_key = !pinned_tls_spki_sha256_.empty();
    info.matches_pinned_key = !info.has_pinned_key || (info.spki_sha256_hex == pinned_tls_spki_sha256_);
    return application::ClientResult<application::interfaces::TlsCertificateInfo>::ok(std::move(info));
}

void DefaultGatewayClient::set_simulated_user_profile(domain::UserProfile profile) {
    std::lock_guard<std::mutex> lock(profile_tls_mutex_);
    const domain::UserId uid = profile.user_id;
    simulated_user_profiles_[uid] = std::move(profile);
}

void DefaultGatewayClient::set_simulated_profile_sync_unsupported(bool unsupported) {
    std::lock_guard<std::mutex> lock(profile_tls_mutex_);
    simulate_profile_sync_unsupported_ = unsupported;
}

void DefaultGatewayClient::set_simulated_tls_certificate(application::interfaces::TlsCertificateInfo cert_info) {
    std::lock_guard<std::mutex> lock(profile_tls_mutex_);
    simulated_tls_cert_ = std::move(cert_info);
}

void DefaultGatewayClient::set_pinned_tls_spki_sha256(std::string spki_sha256_hex) {
    std::lock_guard<std::mutex> lock(profile_tls_mutex_);
    pinned_tls_spki_sha256_ = domain::normalize_hex_lower(spki_sha256_hex);
}

std::size_t DefaultGatewayClient::profile_update_call_count() const {
    std::lock_guard<std::mutex> lock(profile_tls_mutex_);
    return profile_update_call_count_;
}

} // namespace securecloud::client::infrastructure::adapters
