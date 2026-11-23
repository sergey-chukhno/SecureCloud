#include "domain/offline_sync_models.hpp"

#include <algorithm>
#include <cctype>
#include <limits>
#include <nlohmann/json.hpp>
#include <span>

namespace securecloud::client::domain {
namespace {

std::string bytes_to_hex(std::span<const uint8_t> bytes) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2U);
    for (const uint8_t b : bytes) {
        out.push_back(kHex[(b >> 4) & 0x0FU]);
        out.push_back(kHex[b & 0x0FU]);
    }
    return out;
}

std::string string_bytes_to_hex(std::string_view s) {
    return bytes_to_hex(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(s.data()), s.size()));
}

std::optional<std::vector<uint8_t>> hex_to_bytes(std::string_view hex) {
    if (hex.size() % 2U != 0U) {
        return std::nullopt;
    }
    auto nibble = [](char ch) noexcept -> int {
        if (ch >= '0' && ch <= '9') {
            return ch - '0';
        }
        if (ch >= 'a' && ch <= 'f') {
            return 10 + (ch - 'a');
        }
        if (ch >= 'A' && ch <= 'F') {
            return 10 + (ch - 'A');
        }
        return -1;
    };

    std::vector<uint8_t> out;
    out.reserve(hex.size() / 2U);
    for (std::size_t i = 0; i < hex.size(); i += 2U) {
        const int hi = nibble(hex[i]);
        const int lo = nibble(hex[i + 1U]);
        if (hi < 0 || lo < 0) {
            return std::nullopt;
        }
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return out;
}

std::optional<std::string> hex_to_string_bytes(std::string_view hex) {
    const auto bytes = hex_to_bytes(hex);
    if (!bytes.has_value()) {
        return std::nullopt;
    }
    return std::string(reinterpret_cast<const char*>(bytes->data()), bytes->size());
}

bool extract_required_nonempty_string(const nlohmann::json& j, const char* key, std::string& out) {
    const auto it = j.find(key);
    if (it == j.end() || !it->is_string()) {
        return false;
    }
    out = it->get<std::string>();
    return !out.empty();
}

bool extract_optional_string(const nlohmann::json& j, const char* key, std::string& out) {
    const auto it = j.find(key);
    if (it == j.end()) {
        return true;
    }
    if (!it->is_string()) {
        return false;
    }
    out = it->get<std::string>();
    return true;
}

bool extract_optional_i32(const nlohmann::json& j, const char* key, int32_t& out) {
    const auto it = j.find(key);
    if (it == j.end()) {
        return true;
    }
    if (!it->is_number_integer()) {
        return false;
    }
    const auto raw = it->get<int64_t>();
    if (raw < static_cast<int64_t>(std::numeric_limits<int32_t>::min()) ||
        raw > static_cast<int64_t>(std::numeric_limits<int32_t>::max())) {
        return false;
    }
    out = static_cast<int32_t>(raw);
    return true;
}

bool extract_optional_u32(const nlohmann::json& j, const char* key, uint32_t& out) {
    const auto it = j.find(key);
    if (it == j.end()) {
        return true;
    }
    if (!it->is_number_unsigned()) {
        return false;
    }
    const auto raw = it->get<uint64_t>();
    if (raw > static_cast<uint64_t>(std::numeric_limits<uint32_t>::max())) {
        return false;
    }
    out = static_cast<uint32_t>(raw);
    return true;
}

bool extract_optional_i64(const nlohmann::json& j, const char* key, int64_t& out) {
    const auto it = j.find(key);
    if (it == j.end()) {
        return true;
    }
    if (!it->is_number_integer()) {
        return false;
    }
    out = it->get<int64_t>();
    return true;
}

bool extract_optional_u64(const nlohmann::json& j, const char* key, uint64_t& out) {
    const auto it = j.find(key);
    if (it == j.end()) {
        return true;
    }
    if (!it->is_number_unsigned()) {
        return false;
    }
    out = it->get<uint64_t>();
    return true;
}

} // namespace

std::string_view to_string(ConnectivityState state) noexcept {
    switch (state) {
    case ConnectivityState::Online:
        return "Online";
    case ConnectivityState::Offline:
        return "Offline";
    case ConnectivityState::Syncing:
        return "Syncing";
    }
    return "Unknown";
}

std::optional<ConnectivityState> connectivity_state_from_string(std::string_view str) noexcept {
    if (str == "Online") {
        return ConnectivityState::Online;
    }
    if (str == "Offline") {
        return ConnectivityState::Offline;
    }
    if (str == "Syncing") {
        return ConnectivityState::Syncing;
    }
    return std::nullopt;
}

bool can_transition_connectivity_state(ConnectivityState current, ConnectivityState next) noexcept {
    if (current == next) {
        return true;
    }
    switch (current) {
    case ConnectivityState::Online:
        return next == ConnectivityState::Offline || next == ConnectivityState::Syncing;
    case ConnectivityState::Offline:
        return next == ConnectivityState::Syncing;
    case ConnectivityState::Syncing:
        return next == ConnectivityState::Online || next == ConnectivityState::Offline;
    }
    return false;
}

std::string_view to_string(OfflineOutboxOperationType type) noexcept {
    switch (type) {
    case OfflineOutboxOperationType::EncryptedMessageSubmission:
        return "EncryptedMessageSubmission";
    case OfflineOutboxOperationType::DeliveryAck:
        return "DeliveryAck";
    case OfflineOutboxOperationType::ReadReceipt:
        return "ReadReceipt";
    case OfflineOutboxOperationType::FileKeyEnvelopeSubmission:
        return "FileKeyEnvelopeSubmission";
    }
    return "Unknown";
}

std::optional<OfflineOutboxOperationType> offline_outbox_operation_type_from_string(std::string_view str) noexcept {
    if (str == "EncryptedMessageSubmission") {
        return OfflineOutboxOperationType::EncryptedMessageSubmission;
    }
    if (str == "DeliveryAck") {
        return OfflineOutboxOperationType::DeliveryAck;
    }
    if (str == "ReadReceipt") {
        return OfflineOutboxOperationType::ReadReceipt;
    }
    if (str == "FileKeyEnvelopeSubmission") {
        return OfflineOutboxOperationType::FileKeyEnvelopeSubmission;
    }
    return std::nullopt;
}

std::string OfflineOutboxFanOutPayload::to_json() const {
    nlohmann::json j;
    j["conversation_id"] = conversation_id.value();
    j["idempotency_key"] = idempotency_key;
    j["priority"] = priority;

    nlohmann::json payloads_json = nlohmann::json::array();
    for (const auto& dp : device_payloads) {
        nlohmann::json item;
        item["recipient_user_id"] = dp.recipient_user_id.value();
        item["recipient_device_id"] = dp.recipient_device_id.value();
        item["ciphertext_blob_hex"] = string_bytes_to_hex(dp.ciphertext_blob);
        item["ephemeral_public_key_hex"] = bytes_to_hex(dp.ephemeral_public_key);
        item["iv_hex"] = bytes_to_hex(dp.iv);
        item["auth_tag_hex"] = bytes_to_hex(dp.auth_tag);
        item["algorithm"] = dp.algorithm;
        payloads_json.push_back(std::move(item));
    }
    j["device_payloads"] = std::move(payloads_json);

    if (group_envelope_bytes.has_value()) {
        j["group_envelope_hex"] = bytes_to_hex(*group_envelope_bytes);
    }

    return j.dump();
}

std::optional<OfflineOutboxFanOutPayload> OfflineOutboxFanOutPayload::from_json(std::string_view json_str) {
    try {
        const auto j = nlohmann::json::parse(json_str);
        if (!j.is_object()) {
            return std::nullopt;
        }

        OfflineOutboxFanOutPayload payload;
        std::string conv_id_str;
        if (!extract_required_nonempty_string(j, "conversation_id", conv_id_str) ||
            !extract_required_nonempty_string(j, "idempotency_key", payload.idempotency_key) ||
            !extract_optional_i32(j, "priority", payload.priority)) {
            return std::nullopt;
        }
        payload.conversation_id = ConversationId(std::move(conv_id_str));

        const auto dp_it = j.find("device_payloads");
        if (dp_it != j.end()) {
            if (!dp_it->is_array()) {
                return std::nullopt;
            }
            for (const auto& item : *dp_it) {
                if (!item.is_object()) {
                    return std::nullopt;
                }
                std::string uid_str;
                std::string did_str;
                std::string ct_hex;
                std::string epk_hex;
                std::string iv_hex;
                std::string tag_hex;
                std::string algo = "AES-256-GCM";
                if (!extract_required_nonempty_string(item, "recipient_user_id", uid_str) ||
                    !extract_required_nonempty_string(item, "recipient_device_id", did_str) ||
                    !extract_optional_string(item, "ciphertext_blob_hex", ct_hex) ||
                    !extract_optional_string(item, "ephemeral_public_key_hex", epk_hex) ||
                    !extract_optional_string(item, "iv_hex", iv_hex) ||
                    !extract_optional_string(item, "auth_tag_hex", tag_hex) ||
                    !extract_optional_string(item, "algorithm", algo)) {
                    return std::nullopt;
                }

                const auto ct_opt = hex_to_string_bytes(ct_hex);
                const auto epk_opt = hex_to_bytes(epk_hex);
                const auto iv_opt = hex_to_bytes(iv_hex);
                const auto tag_opt = hex_to_bytes(tag_hex);
                if (!ct_opt.has_value() || !epk_opt.has_value() || !iv_opt.has_value() || !tag_opt.has_value()) {
                    return std::nullopt;
                }

                payload.device_payloads.push_back(crypto::PerDeviceDeliveryPayload{
                    .recipient_user_id = UserId(std::move(uid_str)),
                    .recipient_device_id = DeviceId(std::move(did_str)),
                    .ciphertext_blob = *ct_opt,
                    .ephemeral_public_key = *epk_opt,
                    .iv = *iv_opt,
                    .auth_tag = *tag_opt,
                    .algorithm = std::move(algo),
                });
            }
        }

        const auto grp_it = j.find("group_envelope_hex");
        if (grp_it != j.end()) {
            if (!grp_it->is_string()) {
                return std::nullopt;
            }
            const auto grp_bytes = hex_to_bytes(grp_it->get<std::string>());
            if (!grp_bytes.has_value()) {
                return std::nullopt;
            }
            payload.group_envelope_bytes = *grp_bytes;
        }

        if (payload.device_payloads.empty() && !payload.group_envelope_bytes.has_value()) {
            return std::nullopt;
        }

        return payload;
    } catch (...) {
        return std::nullopt;
    }
}

std::string OfflineOutboxDeliveryAckPayload::to_json() const {
    nlohmann::json j;
    j["message_id"] = message_id.value();
    j["recipient_device_id"] = recipient_device_id.value();
    j["delivered_at_ms"] = delivered_at_ms;
    return j.dump();
}

std::optional<OfflineOutboxDeliveryAckPayload> OfflineOutboxDeliveryAckPayload::from_json(std::string_view json_str) {
    try {
        const auto j = nlohmann::json::parse(json_str);
        if (!j.is_object()) {
            return std::nullopt;
        }
        std::string mid_str;
        std::string did_str;
        int64_t ts_ms{0};
        if (!extract_required_nonempty_string(j, "message_id", mid_str) ||
            !extract_required_nonempty_string(j, "recipient_device_id", did_str) ||
            !extract_optional_i64(j, "delivered_at_ms", ts_ms)) {
            return std::nullopt;
        }
        return OfflineOutboxDeliveryAckPayload{
            .message_id = MessageId(std::move(mid_str)),
            .recipient_device_id = DeviceId(std::move(did_str)),
            .delivered_at_ms = ts_ms,
        };
    } catch (...) {
        return std::nullopt;
    }
}

std::string OfflineOutboxReadReceiptPayload::to_json() const {
    nlohmann::json j;
    j["conversation_id"] = conversation_id.value();
    j["message_id"] = message_id.value();
    j["reader_device_id"] = reader_device_id.value();
    j["read_at_ms"] = read_at_ms;
    return j.dump();
}

std::optional<OfflineOutboxReadReceiptPayload> OfflineOutboxReadReceiptPayload::from_json(std::string_view json_str) {
    try {
        const auto j = nlohmann::json::parse(json_str);
        if (!j.is_object()) {
            return std::nullopt;
        }
        std::string cid_str;
        std::string mid_str;
        std::string did_str;
        int64_t ts_ms{0};
        if (!extract_required_nonempty_string(j, "conversation_id", cid_str) ||
            !extract_required_nonempty_string(j, "message_id", mid_str) ||
            !extract_required_nonempty_string(j, "reader_device_id", did_str) ||
            !extract_optional_i64(j, "read_at_ms", ts_ms)) {
            return std::nullopt;
        }
        return OfflineOutboxReadReceiptPayload{
            .conversation_id = ConversationId(std::move(cid_str)),
            .message_id = MessageId(std::move(mid_str)),
            .reader_device_id = DeviceId(std::move(did_str)),
            .read_at_ms = ts_ms,
        };
    } catch (...) {
        return std::nullopt;
    }
}

std::string OfflineOutboxRecord::to_json() const {
    nlohmann::json j;
    j["outbox_id"] = outbox_id;
    j["operation_type"] = std::string(to_string(operation_type));
    j["conversation_id"] = conversation_id.value();
    j["message_id"] = message_id.value();
    j["transfer_id"] = transfer_id;
    j["idempotency_key"] = idempotency_key;
    j["priority"] = priority;
    j["payload_json"] = payload_json;
    j["attempt_count"] = attempt_count;
    j["created_at_ms"] = created_at_ms;
    j["next_retry_at_ms"] = next_retry_at_ms;
    j["expires_at_ms"] = expires_at_ms;
    j["last_error"] = last_error;
    return j.dump();
}

std::optional<OfflineOutboxRecord> OfflineOutboxRecord::from_json(std::string_view json_str) {
    try {
        const auto j = nlohmann::json::parse(json_str);
        if (!j.is_object()) {
            return std::nullopt;
        }

        OfflineOutboxRecord record;
        std::string op_str;
        std::string conv_str;
        std::string msg_str;

        if (!extract_required_nonempty_string(j, "outbox_id", record.outbox_id) ||
            !extract_required_nonempty_string(j, "operation_type", op_str)) {
            return std::nullopt;
        }

        const auto op_opt = offline_outbox_operation_type_from_string(op_str);
        if (!op_opt.has_value()) {
            return std::nullopt;
        }
        record.operation_type = *op_opt;

        if (!extract_optional_string(j, "conversation_id", conv_str) ||
            !extract_optional_string(j, "message_id", msg_str) ||
            !extract_optional_string(j, "transfer_id", record.transfer_id) ||
            !extract_optional_string(j, "idempotency_key", record.idempotency_key) ||
            !extract_optional_i32(j, "priority", record.priority) ||
            !extract_optional_string(j, "payload_json", record.payload_json) ||
            !extract_optional_u32(j, "attempt_count", record.attempt_count) ||
            !extract_optional_i64(j, "created_at_ms", record.created_at_ms) ||
            !extract_optional_i64(j, "next_retry_at_ms", record.next_retry_at_ms) ||
            !extract_optional_i64(j, "expires_at_ms", record.expires_at_ms) ||
            !extract_optional_string(j, "last_error", record.last_error)) {
            return std::nullopt;
        }

        if (!conv_str.empty()) {
            record.conversation_id = ConversationId(std::move(conv_str));
        }
        if (!msg_str.empty()) {
            record.message_id = MessageId(std::move(msg_str));
        }

        return record;
    } catch (...) {
        return std::nullopt;
    }
}

bool SyncCursorRecord::advance_monotonically(uint64_t new_sequence, int64_t timestamp_ms) noexcept {
    if (new_sequence <= last_delivered_sequence) {
        return false;
    }
    last_delivered_sequence = new_sequence;
    if (timestamp_ms > last_sync_timestamp_ms) {
        last_sync_timestamp_ms = timestamp_ms;
    }
    return true;
}

std::string SyncCursorRecord::to_json() const {
    nlohmann::json j;
    j["device_id"] = device_id.value();
    j["conversation_id"] = conversation_id.value();
    j["last_delivered_sequence"] = last_delivered_sequence;
    j["last_sync_timestamp_ms"] = last_sync_timestamp_ms;
    j["sync_version"] = sync_version;
    return j.dump();
}

std::optional<SyncCursorRecord> SyncCursorRecord::from_json(std::string_view json_str) {
    try {
        const auto j = nlohmann::json::parse(json_str);
        if (!j.is_object()) {
            return std::nullopt;
        }

        SyncCursorRecord record;
        std::string dev_str;
        std::string conv_str;
        if (!extract_required_nonempty_string(j, "device_id", dev_str) ||
            !extract_optional_string(j, "conversation_id", conv_str) ||
            !extract_optional_u64(j, "last_delivered_sequence", record.last_delivered_sequence) ||
            !extract_optional_i64(j, "last_sync_timestamp_ms", record.last_sync_timestamp_ms) ||
            !extract_optional_i32(j, "sync_version", record.sync_version)) {
            return std::nullopt;
        }

        record.device_id = DeviceId(std::move(dev_str));
        if (!conv_str.empty()) {
            record.conversation_id = ConversationId(std::move(conv_str));
        }
        return record;
    } catch (...) {
        return std::nullopt;
    }
}

} // namespace securecloud::client::domain
