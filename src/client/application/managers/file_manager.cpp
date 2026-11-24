#include "application/managers/file_manager.hpp"

#include "application/managers/messaging_manager.hpp"
#include "domain/crypto/file_crypto_engine.hpp"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <nlohmann/json.hpp>
#include <span>

namespace securecloud::client::application::managers {
namespace {

int64_t current_unix_ms() noexcept {
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
        .count();
}

std::string make_unique_id(std::string_view prefix) {
    static std::atomic<uint64_t> sequence{1ULL};
    const uint64_t seq = sequence.fetch_add(1ULL, std::memory_order_relaxed);
    const auto now_ns =
        std::chrono::duration_cast<std::chrono::nanoseconds>(std::chrono::system_clock::now().time_since_epoch())
            .count();
    return std::string(prefix) + "-" + std::to_string(now_ns) + "-" + std::to_string(seq);
}

std::string to_lower_ascii(std::string_view sv) {
    std::string out;
    out.reserve(sv.size());
    for (const char ch : sv) {
        out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
    }
    return out;
}

std::filesystem::path part_file_path_for(std::string_view destination_path) {
    return std::filesystem::path(std::string(destination_path) + ".part");
}

void remove_file_quietly(const std::filesystem::path& path) noexcept {
    std::error_code ec;
    std::filesystem::remove(path, ec);
}

ClientResult<void> read_exact_slice(std::ifstream& stream, std::size_t expected_len, std::vector<uint8_t>& buffer) {
    buffer.resize(expected_len);
    if (expected_len == 0U) {
        return ClientResult<void>::ok();
    }
    stream.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(expected_len));
    const std::streamsize bytes_read = stream.gcount();
    if (bytes_read < 0 || static_cast<std::size_t>(bytes_read) != expected_len || stream.bad()) {
        return ClientResult<void>::error(ClientError::storage("Failed to read expected chunk slice from disk"));
    }
    return ClientResult<void>::ok();
}

} // namespace

FileManager::ActiveTransferGuard::ActiveTransferGuard(FileManager& owner, std::string transfer_id)
    : owner_(owner), transfer_id_(std::move(transfer_id)) {
    std::lock_guard<std::mutex> lock(owner_.control_mutex_);
    owner_.active_transfers_.insert(transfer_id_);
    owner_.pause_requested_transfers_.erase(transfer_id_);
    owner_.cancel_requested_transfers_.erase(transfer_id_);
}

FileManager::ActiveTransferGuard::~ActiveTransferGuard() {
    std::lock_guard<std::mutex> lock(owner_.control_mutex_);
    owner_.active_transfers_.erase(transfer_id_);
    owner_.pause_requested_transfers_.erase(transfer_id_);
    owner_.cancel_requested_transfers_.erase(transfer_id_);
}

FileManager::FileManager(interfaces::IGatewayClient& gateway, interfaces::ICryptoProvider& crypto_provider,
                         interfaces::ILocalStore* local_store, interfaces::ISecureStorage* secure_storage,
                         MessagingManager* messaging_manager)
    : gateway_(gateway), crypto_provider_(crypto_provider), local_store_(local_store), secure_storage_(secure_storage),
      messaging_manager_(messaging_manager) {}

void FileManager::set_local_store(interfaces::ILocalStore* local_store) noexcept {
    local_store_ = local_store;
}

void FileManager::set_secure_storage(interfaces::ISecureStorage* secure_storage) noexcept {
    secure_storage_ = secure_storage;
}

void FileManager::set_messaging_manager(MessagingManager* messaging_manager) noexcept {
    messaging_manager_ = messaging_manager;
}

void FileManager::set_local_identity(const domain::UserId& user_id, const domain::DeviceId& device_id) {
    std::lock_guard<std::mutex> lock(control_mutex_);
    local_user_id_ = user_id;
    local_device_id_ = device_id;
}

ClientResult<void> FileManager::set_wire_chunk_size(uint32_t wire_chunk_size) {
    const auto validate_res = domain::crypto::FileCryptoEngine::create(wire_chunk_size);
    if (validate_res.is_error()) {
        return ClientResult<void>::error(validate_res.error());
    }
    std::lock_guard<std::mutex> lock(control_mutex_);
    wire_chunk_size_ = wire_chunk_size;
    return ClientResult<void>::ok();
}

uint32_t FileManager::wire_chunk_size() const noexcept {
    std::lock_guard<std::mutex> lock(control_mutex_);
    return wire_chunk_size_;
}

void FileManager::set_progress_callback(ProgressCallback callback) {
    std::lock_guard<std::mutex> lock(control_mutex_);
    progress_callback_ = std::move(callback);
}

std::string FileManager::file_key_storage_id(std::string_view file_id) {
    return "file_transfer.key." + std::string(file_id);
}

ClientResult<void> FileManager::ensure_stateful_storage() const {
    if (local_store_ == nullptr || secure_storage_ == nullptr) {
        return ClientResult<void>::error(
            ClientError::storage("ILocalStore and ISecureStorage are required for file transfers"));
    }
    return ClientResult<void>::ok();
}

void FileManager::notify_progress(const domain::FileTransferRecord& record) const {
    ProgressCallback cb;
    {
        std::lock_guard<std::mutex> lock(control_mutex_);
        cb = progress_callback_;
    }
    if (cb) {
        cb(record);
    }
}

ClientResult<void> FileManager::persist_and_notify(domain::FileTransferRecord& record) const {
    record.updated_at_ms = current_unix_ms();
    const auto save_res = local_store_->save_file_transfer(record);
    if (save_res.is_error()) {
        return save_res;
    }
    notify_progress(record);
    return ClientResult<void>::ok();
}

FileManager::ControlAction FileManager::poll_control_action(std::string_view transfer_id) const {
    std::lock_guard<std::mutex> lock(control_mutex_);
    const std::string key(transfer_id);
    if (cancel_requested_transfers_.contains(key)) {
        return ControlAction::Cancel;
    }
    if (pause_requested_transfers_.contains(key)) {
        return ControlAction::Pause;
    }
    return ControlAction::None;
}

ClientResult<void> FileManager::abort_and_mark_cancelled(domain::FileTransferRecord& record) {
    if (record.direction == domain::FileTransferDirection::Outbound && !record.upload_id.empty() &&
        record.status != domain::FileTransferStatus::Completed) {
        (void)gateway_.cancel_file_upload(record.upload_id, "Cancelled by user");
    }
    if (record.direction == domain::FileTransferDirection::Inbound && !record.local_path.empty()) {
        remove_file_quietly(part_file_path_for(record.local_path));
    }
    if (secure_storage_ != nullptr && !record.file_id.empty()) {
        (void)secure_storage_->delete_secret(file_key_storage_id(record.file_id));
    }
    record.status = domain::FileTransferStatus::Cancelled;
    record.error_message.clear();
    return persist_and_notify(record);
}

ClientResult<FileUploadResult> FileManager::start_upload(const FileUploadRequest& request) {
    if (const auto deps = ensure_stateful_storage(); deps.is_error()) {
        return ClientResult<FileUploadResult>::error(deps.error());
    }
    if (request.conversation_id.empty() || request.local_file_path.empty()) {
        return ClientResult<FileUploadResult>::error(
            ClientError::validation("Conversation ID and local file path are required to start upload"));
    }

    domain::UserId effective_owner_user = request.owner_user_id;
    domain::DeviceId effective_owner_device = request.owner_device_id;
    uint32_t configured_chunk_size = domain::kDefaultFileWireChunkSize;
    {
        std::lock_guard<std::mutex> lock(control_mutex_);
        if (effective_owner_user.empty()) {
            effective_owner_user = local_user_id_;
        }
        if (effective_owner_device.empty()) {
            effective_owner_device = local_device_id_;
        }
        configured_chunk_size = wire_chunk_size_;
    }

    if (effective_owner_user.empty() || effective_owner_device.empty()) {
        return ClientResult<FileUploadResult>::error(
            ClientError::validation("Owner user ID and device ID are required to start upload"));
    }

    // ADR-008 pre-flight guard before encrypting or transferring any chunks
    if (messaging_manager_ != nullptr && !(request.is_profile_asset && !request.dispatch_key_envelope)) {
        const auto elig_res =
            messaging_manager_->check_conversation_send_eligibility(request.conversation_id, effective_owner_user);
        if (elig_res.is_error()) {
            return ClientResult<FileUploadResult>::error(elig_res.error());
        }
    }

    std::error_code ec;
    const std::filesystem::path src_path(request.local_file_path);
    if (!std::filesystem::exists(src_path, ec) || ec || !std::filesystem::is_regular_file(src_path, ec) || ec) {
        return ClientResult<FileUploadResult>::error(
            ClientError::validation("Source file does not exist or is not a regular file: " + request.local_file_path));
    }

    const uint64_t plaintext_size = std::filesystem::file_size(src_path, ec);
    if (ec || plaintext_size == 0ULL) {
        return ClientResult<FileUploadResult>::error(
            ClientError::validation("Source file cannot be empty for encrypted upload"));
    }

    const auto engine_res = domain::crypto::FileCryptoEngine::create(configured_chunk_size);
    if (engine_res.is_error()) {
        return ClientResult<FileUploadResult>::error(engine_res.error());
    }
    const auto& engine = engine_res.value();

    const auto chunk_count_res = engine.calculate_chunk_count(plaintext_size);
    if (chunk_count_res.is_error()) {
        return ClientResult<FileUploadResult>::error(chunk_count_res.error());
    }
    const auto encrypted_size_res = engine.calculate_encrypted_size(plaintext_size);
    if (encrypted_size_res.is_error()) {
        return ClientResult<FileUploadResult>::error(encrypted_size_res.error());
    }

    const std::string transfer_id = make_unique_id("tx-up");
    const std::string file_id = make_unique_id("file");

    const auto key_res = domain::crypto::FileCryptoEngine::generate_file_key();
    if (key_res.is_error()) {
        return ClientResult<FileUploadResult>::error(key_res.error());
    }
    const auto hex_key_res = domain::crypto::FileCryptoEngine::encode_key_hex(key_res.value());
    if (hex_key_res.is_error()) {
        return ClientResult<FileUploadResult>::error(hex_key_res.error());
    }

    const std::string storage_key = file_key_storage_id(file_id);
    const auto store_key_res = secure_storage_->store_secret(storage_key, hex_key_res.value());
    if (store_key_res.is_error()) {
        return ClientResult<FileUploadResult>::error(store_key_res.error());
    }

    nlohmann::json crypto_meta;
    crypto_meta["cipher_suite"] = std::string(domain::kDefaultFileCipherSuite);
    crypto_meta["chunk_size_bytes"] = engine.wire_chunk_size();

    const auto init_res = gateway_.init_file_upload(interfaces::FileUploadInitRequest{
        .file_id = file_id,
        .owner_user_id = effective_owner_user,
        .owner_device_id = effective_owner_device,
        .conversation_id = request.conversation_id,
        .encrypted_size_bytes = encrypted_size_res.value(),
        .expected_chunk_count = chunk_count_res.value(),
        .encryption_version = "v1",
        .client_crypto_metadata = crypto_meta.dump(),
    });
    if (init_res.is_error()) {
        (void)secure_storage_->delete_secret(storage_key);
        return ClientResult<FileUploadResult>::error(init_res.error());
    }

    const int64_t now_ms = current_unix_ms();
    domain::FileTransferRecord record;
    record.transfer_id = transfer_id;
    record.file_id = file_id;
    record.upload_id = init_res.value().upload_id;
    record.conversation_id = request.conversation_id;
    record.peer_user_id = request.peer_user_id;
    record.local_path = request.local_file_path;
    record.file_name = src_path.filename().string();
    record.mime_type = request.mime_type.empty() ? "application/octet-stream" : request.mime_type;
    record.cipher_suite = std::string(domain::kDefaultFileCipherSuite);
    record.direction = domain::FileTransferDirection::Outbound;
    record.status = domain::FileTransferStatus::InProgress;
    record.plaintext_size_bytes = plaintext_size;
    record.encrypted_size_bytes = encrypted_size_res.value();
    record.chunk_size_bytes = engine.wire_chunk_size();
    record.total_chunks = chunk_count_res.value();
    record.completed_chunks = 0U;
    record.created_at_ms = now_ms;
    record.updated_at_ms = now_ms;

    if (const auto save_res = persist_and_notify(record); save_res.is_error()) {
        (void)gateway_.cancel_file_upload(record.upload_id, "Local checkpoint persistence failed");
        (void)secure_storage_->delete_secret(storage_key);
        return ClientResult<FileUploadResult>::error(save_res.error());
    }

    return execute_upload_loop(std::move(record), effective_owner_user, effective_owner_device,
                               request.sender_display_name, request.priority, request.dispatch_key_envelope);
}

ClientResult<FileUploadResult> FileManager::resume_upload(std::string_view transfer_id,
                                                          const domain::UserId& owner_user_id,
                                                          const domain::DeviceId& owner_device_id,
                                                          const std::string& sender_display_name, int32_t priority,
                                                          bool dispatch_key_envelope) {
    if (const auto deps = ensure_stateful_storage(); deps.is_error()) {
        return ClientResult<FileUploadResult>::error(deps.error());
    }
    if (transfer_id.empty()) {
        return ClientResult<FileUploadResult>::error(ClientError::validation("Transfer ID cannot be empty"));
    }

    const auto rec_res = local_store_->get_file_transfer(transfer_id);
    if (rec_res.is_error()) {
        return ClientResult<FileUploadResult>::error(rec_res.error());
    }
    domain::FileTransferRecord record = rec_res.value();
    if (record.direction != domain::FileTransferDirection::Outbound) {
        return ClientResult<FileUploadResult>::error(
            ClientError::validation("Transfer is not an outbound upload: " + std::string(transfer_id)));
    }
    if (record.status == domain::FileTransferStatus::Completed ||
        record.status == domain::FileTransferStatus::Cancelled) {
        return ClientResult<FileUploadResult>::error(ClientError::validation(
            "Cannot resume upload in terminal state: " + std::string(to_string(record.status))));
    }

    domain::UserId effective_user = owner_user_id;
    domain::DeviceId effective_device = owner_device_id;
    {
        std::lock_guard<std::mutex> lock(control_mutex_);
        if (effective_user.empty()) {
            effective_user = local_user_id_;
        }
        if (effective_device.empty()) {
            effective_device = local_device_id_;
        }
    }
    if (effective_user.empty() || effective_device.empty()) {
        return ClientResult<FileUploadResult>::error(
            ClientError::validation("Owner user ID and device ID are required to resume upload"));
    }

    return execute_upload_loop(std::move(record), effective_user, effective_device, sender_display_name, priority,
                               dispatch_key_envelope);
}

ClientResult<FileUploadResult> FileManager::execute_upload_loop(domain::FileTransferRecord record,
                                                                const domain::UserId& owner_user_id,
                                                                const domain::DeviceId& owner_device_id,
                                                                const std::string& sender_display_name,
                                                                int32_t priority, bool dispatch_key_envelope) {
    {
        std::lock_guard<std::mutex> lock(control_mutex_);
        if (active_transfers_.contains(record.transfer_id)) {
            return ClientResult<FileUploadResult>::error(
                ClientError::validation("Upload transfer is already running: " + record.transfer_id));
        }
    }
    ActiveTransferGuard active_guard(*this, record.transfer_id);

    const auto hex_key_res = secure_storage_->get_secret(file_key_storage_id(record.file_id));
    if (hex_key_res.is_error()) {
        return ClientResult<FileUploadResult>::error(hex_key_res.error());
    }
    const auto raw_key_res = domain::crypto::FileCryptoEngine::decode_key_hex(hex_key_res.value());
    if (raw_key_res.is_error()) {
        return ClientResult<FileUploadResult>::error(raw_key_res.error());
    }

    const auto engine_res = domain::crypto::FileCryptoEngine::create(record.chunk_size_bytes);
    if (engine_res.is_error()) {
        return ClientResult<FileUploadResult>::error(engine_res.error());
    }
    const auto& engine = engine_res.value();

    std::error_code ec;
    const std::filesystem::path src_path(record.local_path);
    const uint64_t current_file_size = std::filesystem::file_size(src_path, ec);
    if (ec || current_file_size != record.plaintext_size_bytes || record.completed_chunks > record.total_chunks) {
        record.status = domain::FileTransferStatus::Failed;
        record.error_message = "Local source file missing or modified before upload resume";
        (void)persist_and_notify(record);
        return ClientResult<FileUploadResult>::error(ClientError::validation(record.error_message));
    }

    std::ifstream in(src_path, std::ios::binary | std::ios::in);
    if (!in.is_open()) {
        record.status = domain::FileTransferStatus::Failed;
        record.error_message = "Failed to open source file for streaming upload";
        (void)persist_and_notify(record);
        return ClientResult<FileUploadResult>::error(ClientError::storage(record.error_message));
    }

    if (record.status != domain::FileTransferStatus::InProgress || !record.error_message.empty()) {
        record.status = domain::FileTransferStatus::InProgress;
        record.error_message.clear();
        if (const auto save_res = persist_and_notify(record); save_res.is_error()) {
            return ClientResult<FileUploadResult>::error(save_res.error());
        }
    }

    domain::crypto::StreamingSha256 plaintext_hasher;
    domain::crypto::StreamingSha256 ciphertext_hasher;
    std::vector<uint8_t> chunk_buffer;
    chunk_buffer.reserve(engine.max_plaintext_chunk_size());

    uint64_t remaining_bytes = record.plaintext_size_bytes;
    for (uint32_t idx = 0U; idx < record.total_chunks; ++idx) {
        const std::size_t slice_len = static_cast<std::size_t>(
            std::min<uint64_t>(remaining_bytes, static_cast<uint64_t>(engine.max_plaintext_chunk_size())));
        const bool is_final = (idx + 1U == record.total_chunks);
        const bool already_acked = (idx < record.completed_chunks);

        if (!already_acked) {
            const ControlAction action = poll_control_action(record.transfer_id);
            if (action == ControlAction::Cancel) {
                (void)abort_and_mark_cancelled(record);
                return ClientResult<FileUploadResult>::error(ClientError::validation("File upload cancelled by user"));
            }
            if (action == ControlAction::Pause) {
                record.status = domain::FileTransferStatus::Paused;
                record.error_message.clear();
                (void)persist_and_notify(record);
                return ClientResult<FileUploadResult>::ok(FileUploadResult{
                    .record = std::move(record),
                    .key_envelope = std::nullopt,
                    .dispatched_message = std::nullopt,
                });
            }
        }

        if (const auto read_res = read_exact_slice(in, slice_len, chunk_buffer); read_res.is_error()) {
            record.status = domain::FileTransferStatus::Failed;
            record.error_message = read_res.error().user_message();
            (void)persist_and_notify(record);
            return ClientResult<FileUploadResult>::error(read_res.error());
        }
        remaining_bytes -= static_cast<uint64_t>(slice_len);

        if (const auto pt_upd = plaintext_hasher.update(chunk_buffer); pt_upd.is_error()) {
            return ClientResult<FileUploadResult>::error(pt_upd.error());
        }
        const auto frame_res =
            engine.encrypt_chunk(crypto_provider_, raw_key_res.value(), record.file_id, idx, is_final, chunk_buffer);
        if (frame_res.is_error()) {
            return ClientResult<FileUploadResult>::error(frame_res.error());
        }
        if (const auto ct_upd = ciphertext_hasher.update(frame_res.value().framed_bytes); ct_upd.is_error()) {
            return ClientResult<FileUploadResult>::error(ct_upd.error());
        }

        if (already_acked) {
            continue;
        }

        const auto up_res = gateway_.upload_file_chunk(interfaces::FileChunkUploadRequest{
            .upload_id = record.upload_id,
            .chunk_index = idx,
            .encrypted_data = frame_res.value().framed_bytes,
            .ciphertext_sha256 = frame_res.value().ciphertext_sha256,
        });
        if (up_res.is_error()) {
            if (up_res.error().category() == ClientErrorCategory::Network) {
                record.status = domain::FileTransferStatus::Paused;
            } else {
                record.status = domain::FileTransferStatus::Failed;
            }
            record.error_message = up_res.error().user_message();
            (void)persist_and_notify(record);
            return ClientResult<FileUploadResult>::error(up_res.error());
        }

        record.completed_chunks = idx + 1U;
        record.error_message.clear();
        if (const auto ckpt_res = persist_and_notify(record); ckpt_res.is_error()) {
            return ClientResult<FileUploadResult>::error(ckpt_res.error());
        }
    }

    // Honor pause or cancel requested during the final chunk callback before finalizing
    const ControlAction post_loop_action = poll_control_action(record.transfer_id);
    if (post_loop_action == ControlAction::Cancel) {
        (void)abort_and_mark_cancelled(record);
        return ClientResult<FileUploadResult>::error(ClientError::validation("File upload cancelled by user"));
    }
    if (post_loop_action == ControlAction::Pause) {
        record.status = domain::FileTransferStatus::Paused;
        record.error_message.clear();
        (void)persist_and_notify(record);
        return ClientResult<FileUploadResult>::ok(FileUploadResult{
            .record = std::move(record),
            .key_envelope = std::nullopt,
            .dispatched_message = std::nullopt,
        });
    }

    const auto pt_sha_res = plaintext_hasher.finalize_hex();
    if (pt_sha_res.is_error()) {
        return ClientResult<FileUploadResult>::error(pt_sha_res.error());
    }
    const auto ct_sha_res = ciphertext_hasher.finalize_hex();
    if (ct_sha_res.is_error()) {
        return ClientResult<FileUploadResult>::error(ct_sha_res.error());
    }

    record.plaintext_sha256 = pt_sha_res.value();
    record.ciphertext_sha256 = ct_sha_res.value();
    record.status = domain::FileTransferStatus::Finalizing;
    if (const auto fin_ckpt = persist_and_notify(record); fin_ckpt.is_error()) {
        return ClientResult<FileUploadResult>::error(fin_ckpt.error());
    }

    const auto fin_res = gateway_.finalize_file_upload(interfaces::FileUploadFinalizeRequest{
        .upload_id = record.upload_id,
        .file_id = record.file_id,
        .expected_ciphertext_sha256 = record.ciphertext_sha256,
    });
    if (fin_res.is_error()) {
        record.status = (fin_res.error().category() == ClientErrorCategory::Network)
                            ? domain::FileTransferStatus::Paused
                            : domain::FileTransferStatus::Failed;
        record.error_message = fin_res.error().user_message();
        (void)persist_and_notify(record);
        return ClientResult<FileUploadResult>::error(fin_res.error());
    }

    domain::FileAttachmentKeyEnvelope key_envelope;
    key_envelope.file_id = record.file_id;
    key_envelope.file_key_hex = hex_key_res.value();
    key_envelope.file_name = record.file_name;
    key_envelope.mime_type = record.mime_type;
    key_envelope.plaintext_size_bytes = record.plaintext_size_bytes;
    key_envelope.encrypted_size_bytes = record.encrypted_size_bytes;
    key_envelope.chunk_size_bytes = record.chunk_size_bytes;
    key_envelope.chunk_count = record.total_chunks;
    key_envelope.ciphertext_sha256 = record.ciphertext_sha256;
    key_envelope.plaintext_sha256 = record.plaintext_sha256;
    key_envelope.cipher_suite = record.cipher_suite;

    std::optional<domain::Message> dispatched_message;
    if (dispatch_key_envelope && messaging_manager_ != nullptr) {
        const std::string envelope_json = key_envelope.serialize();
        const auto msg_res = messaging_manager_->stage_outbound_message(
            record.conversation_id, owner_user_id, owner_device_id, envelope_json, priority, sender_display_name,
            record.file_name, static_cast<int64_t>(record.plaintext_size_bytes), record.ciphertext_sha256);
        if (msg_res.is_error()) {
            record.status = (msg_res.error().category() == ClientErrorCategory::Network)
                                ? domain::FileTransferStatus::Paused
                                : domain::FileTransferStatus::Failed;
            record.error_message = msg_res.error().user_message();
            (void)persist_and_notify(record);
            return ClientResult<FileUploadResult>::error(msg_res.error());
        }
        dispatched_message = msg_res.value();
    }

    record.status = domain::FileTransferStatus::Completed;
    record.completed_chunks = record.total_chunks;
    record.error_message.clear();
    if (const auto done_res = persist_and_notify(record); done_res.is_error()) {
        return ClientResult<FileUploadResult>::error(done_res.error());
    }

    return ClientResult<FileUploadResult>::ok(FileUploadResult{
        .record = std::move(record),
        .key_envelope = std::move(key_envelope),
        .dispatched_message = std::move(dispatched_message),
    });
}

ClientResult<domain::FileTransferRecord>
FileManager::ingest_inbound_key_envelope(const domain::ConversationId& conversation_id,
                                         const domain::UserId& peer_user_id,
                                         const domain::FileAttachmentKeyEnvelope& envelope) {
    if (const auto deps = ensure_stateful_storage(); deps.is_error()) {
        return ClientResult<domain::FileTransferRecord>::error(deps.error());
    }
    if (conversation_id.empty()) {
        return ClientResult<domain::FileTransferRecord>::error(
            ClientError::validation("Conversation ID is required to ingest inbound file key envelope"));
    }

    const auto validated_env_opt = domain::FileAttachmentKeyEnvelope::deserialize(envelope.serialize());
    if (!validated_env_opt.has_value()) {
        return ClientResult<domain::FileTransferRecord>::error(
            ClientError::validation("Invalid FileAttachmentKeyEnvelope metadata or digest format"));
    }
    const auto& validated_env = *validated_env_opt;

    const auto raw_key_check = domain::crypto::FileCryptoEngine::decode_key_hex(validated_env.file_key_hex);
    if (raw_key_check.is_error()) {
        return ClientResult<domain::FileTransferRecord>::error(raw_key_check.error());
    }

    const auto store_res =
        secure_storage_->store_secret(file_key_storage_id(validated_env.file_id), validated_env.file_key_hex);
    if (store_res.is_error()) {
        return ClientResult<domain::FileTransferRecord>::error(store_res.error());
    }

    const int64_t now_ms = current_unix_ms();
    domain::FileTransferRecord record;
    record.transfer_id = make_unique_id("tx-dl");
    record.file_id = validated_env.file_id;
    record.conversation_id = conversation_id;
    record.peer_user_id = peer_user_id;
    record.file_name = validated_env.file_name;
    record.mime_type = validated_env.mime_type;
    record.cipher_suite = validated_env.cipher_suite;
    record.direction = domain::FileTransferDirection::Inbound;
    record.status = domain::FileTransferStatus::Pending;
    record.plaintext_size_bytes = validated_env.plaintext_size_bytes;
    record.encrypted_size_bytes = validated_env.encrypted_size_bytes;
    record.chunk_size_bytes = validated_env.chunk_size_bytes;
    record.total_chunks = validated_env.chunk_count;
    record.completed_chunks = 0U;
    record.plaintext_sha256 = to_lower_ascii(validated_env.plaintext_sha256);
    record.ciphertext_sha256 = to_lower_ascii(validated_env.ciphertext_sha256);
    record.created_at_ms = now_ms;
    record.updated_at_ms = now_ms;

    if (const auto save_res = persist_and_notify(record); save_res.is_error()) {
        (void)secure_storage_->delete_secret(file_key_storage_id(validated_env.file_id));
        return ClientResult<domain::FileTransferRecord>::error(save_res.error());
    }

    return ClientResult<domain::FileTransferRecord>::ok(std::move(record));
}

ClientResult<domain::FileTransferRecord>
FileManager::ingest_inbound_key_envelope_json(const domain::ConversationId& conversation_id,
                                              const domain::UserId& peer_user_id,
                                              std::string_view decrypted_payload_json) {
    const auto env_opt = domain::FileAttachmentKeyEnvelope::deserialize(decrypted_payload_json);
    if (!env_opt.has_value()) {
        return ClientResult<domain::FileTransferRecord>::error(
            ClientError::validation("Failed to parse decrypted FileAttachmentKeyEnvelope JSON"));
    }
    return ingest_inbound_key_envelope(conversation_id, peer_user_id, *env_opt);
}

ClientResult<domain::FileTransferRecord> FileManager::start_download(std::string_view transfer_id,
                                                                     std::string_view destination_path) {
    if (const auto deps = ensure_stateful_storage(); deps.is_error()) {
        return ClientResult<domain::FileTransferRecord>::error(deps.error());
    }
    if (transfer_id.empty() || destination_path.empty()) {
        return ClientResult<domain::FileTransferRecord>::error(
            ClientError::validation("Transfer ID and destination path are required to download file"));
    }

    const auto rec_res = local_store_->get_file_transfer(transfer_id);
    if (rec_res.is_error()) {
        return ClientResult<domain::FileTransferRecord>::error(rec_res.error());
    }

    domain::FileTransferRecord record = rec_res.value();
    if (record.direction != domain::FileTransferDirection::Inbound) {
        return ClientResult<domain::FileTransferRecord>::error(
            ClientError::validation("Transfer is not an inbound download: " + std::string(transfer_id)));
    }
    if (record.status == domain::FileTransferStatus::Completed ||
        record.status == domain::FileTransferStatus::Cancelled || record.status == domain::FileTransferStatus::Failed) {
        return ClientResult<domain::FileTransferRecord>::error(ClientError::validation(
            "Cannot start download in terminal state: " + std::string(to_string(record.status))));
    }

    std::error_code ec;
    const std::filesystem::path dest_path(destination_path);
    if (dest_path.has_parent_path()) {
        std::filesystem::create_directories(dest_path.parent_path(), ec);
        if (ec) {
            return ClientResult<domain::FileTransferRecord>::error(
                ClientError::storage("Failed to create download destination directory: " + ec.message()));
        }
    }

    record.local_path = std::string(destination_path);
    if (const auto save_res = persist_and_notify(record); save_res.is_error()) {
        return ClientResult<domain::FileTransferRecord>::error(save_res.error());
    }

    return execute_download_loop(std::move(record));
}

ClientResult<domain::FileTransferRecord> FileManager::resume_download(std::string_view transfer_id) {
    if (const auto deps = ensure_stateful_storage(); deps.is_error()) {
        return ClientResult<domain::FileTransferRecord>::error(deps.error());
    }
    if (transfer_id.empty()) {
        return ClientResult<domain::FileTransferRecord>::error(ClientError::validation("Transfer ID cannot be empty"));
    }

    const auto rec_res = local_store_->get_file_transfer(transfer_id);
    if (rec_res.is_error()) {
        return ClientResult<domain::FileTransferRecord>::error(rec_res.error());
    }
    const domain::FileTransferRecord& record = rec_res.value();
    if (record.direction != domain::FileTransferDirection::Inbound) {
        return ClientResult<domain::FileTransferRecord>::error(
            ClientError::validation("Transfer is not an inbound download: " + std::string(transfer_id)));
    }
    if (record.local_path.empty()) {
        return ClientResult<domain::FileTransferRecord>::error(
            ClientError::validation("Download destination path has not been configured"));
    }
    if (record.status == domain::FileTransferStatus::Completed ||
        record.status == domain::FileTransferStatus::Cancelled || record.status == domain::FileTransferStatus::Failed) {
        return ClientResult<domain::FileTransferRecord>::error(ClientError::validation(
            "Cannot resume download in terminal state: " + std::string(to_string(record.status))));
    }

    return execute_download_loop(record);
}

ClientResult<domain::FileTransferRecord> FileManager::execute_download_loop(domain::FileTransferRecord record) {
    {
        std::lock_guard<std::mutex> lock(control_mutex_);
        if (active_transfers_.contains(record.transfer_id)) {
            return ClientResult<domain::FileTransferRecord>::error(
                ClientError::validation("Download transfer is already running: " + record.transfer_id));
        }
    }
    ActiveTransferGuard active_guard(*this, record.transfer_id);

    const auto fail_closed = [&](const std::filesystem::path* part_to_remove, const std::string& message,
                                 ClientErrorCategory category = ClientErrorCategory::Crypto) {
        if (part_to_remove != nullptr) {
            remove_file_quietly(*part_to_remove);
        }
        record.status = domain::FileTransferStatus::Failed;
        record.error_message = message;
        (void)persist_and_notify(record);
        return ClientResult<domain::FileTransferRecord>::error(
            category == ClientErrorCategory::Storage ? ClientError::storage(message) : ClientError::crypto(message));
    };

    const auto hex_key_res = secure_storage_->get_secret(file_key_storage_id(record.file_id));
    if (hex_key_res.is_error()) {
        return fail_closed(nullptr, hex_key_res.error().user_message());
    }
    const auto raw_key_res = domain::crypto::FileCryptoEngine::decode_key_hex(hex_key_res.value());
    if (raw_key_res.is_error()) {
        return fail_closed(nullptr, raw_key_res.error().user_message());
    }

    const auto engine_res = domain::crypto::FileCryptoEngine::create(record.chunk_size_bytes);
    if (engine_res.is_error()) {
        return fail_closed(nullptr, engine_res.error().user_message());
    }
    const auto& engine = engine_res.value();

    const std::filesystem::path dest_path(record.local_path);
    const std::filesystem::path part_path = part_file_path_for(record.local_path);

    const auto meta_res = gateway_.get_file_metadata(record.file_id);
    if (meta_res.is_error()) {
        if (meta_res.error().category() == ClientErrorCategory::Network) {
            record.status = domain::FileTransferStatus::Paused;
            record.error_message = meta_res.error().user_message();
            (void)persist_and_notify(record);
            return ClientResult<domain::FileTransferRecord>::error(meta_res.error());
        }
        return fail_closed(&part_path, meta_res.error().user_message());
    }

    const auto& meta = meta_res.value();
    if (meta.lifecycle_state != "FILE_LIFECYCLE_STATE_AVAILABLE" || meta.chunk_count != record.total_chunks ||
        meta.encrypted_size_bytes != record.encrypted_size_bytes ||
        (!meta.ciphertext_integrity_hash.empty() &&
         to_lower_ascii(meta.ciphertext_integrity_hash) != to_lower_ascii(record.ciphertext_sha256))) {
        return fail_closed(&part_path, "Remote file metadata mismatch against trusted E2EE key envelope");
    }

    if (record.total_chunks == 0U || record.completed_chunks > record.total_chunks) {
        return fail_closed(&part_path, "Corrupt inbound transfer chunk bounds");
    }

    if (record.status != domain::FileTransferStatus::InProgress || !record.error_message.empty()) {
        record.status = domain::FileTransferStatus::InProgress;
        record.error_message.clear();
        if (const auto save_res = persist_and_notify(record); save_res.is_error()) {
            return ClientResult<domain::FileTransferRecord>::error(save_res.error());
        }
    }

    domain::crypto::StreamingSha256 plaintext_hasher;
    domain::crypto::StreamingSha256 ciphertext_hasher;

    if (record.completed_chunks > 0U) {
        std::error_code ec;
        const uint64_t expected_part_bytes = (record.completed_chunks == record.total_chunks)
                                                 ? record.plaintext_size_bytes
                                                 : static_cast<uint64_t>(record.completed_chunks) *
                                                       static_cast<uint64_t>(engine.max_plaintext_chunk_size());
        if (!std::filesystem::exists(part_path, ec) || ec ||
            std::filesystem::file_size(part_path, ec) != expected_part_bytes || ec) {
            return fail_closed(&part_path, "Staging .part file missing or size mismatched on download resume");
        }

        std::ifstream part_in(part_path, std::ios::binary | std::ios::in);
        if (!part_in.is_open()) {
            return fail_closed(&part_path, "Failed to open .part file to rebuild resume hashes",
                               ClientErrorCategory::Storage);
        }

        std::vector<uint8_t> replay_buf;
        uint64_t remaining_part = expected_part_bytes;
        for (uint32_t idx = 0U; idx < record.completed_chunks; ++idx) {
            const std::size_t slice_len = static_cast<std::size_t>(
                std::min<uint64_t>(remaining_part, static_cast<uint64_t>(engine.max_plaintext_chunk_size())));
            const bool is_final = (idx + 1U == record.total_chunks);
            if (const auto read_res = read_exact_slice(part_in, slice_len, replay_buf); read_res.is_error()) {
                return fail_closed(&part_path, read_res.error().user_message(), ClientErrorCategory::Storage);
            }
            remaining_part -= static_cast<uint64_t>(slice_len);

            if (const auto pt_upd = plaintext_hasher.update(replay_buf); pt_upd.is_error()) {
                return fail_closed(&part_path, pt_upd.error().user_message());
            }
            const auto frame_res =
                engine.encrypt_chunk(crypto_provider_, raw_key_res.value(), record.file_id, idx, is_final, replay_buf);
            if (frame_res.is_error()) {
                return fail_closed(&part_path, frame_res.error().user_message());
            }
            if (const auto ct_upd = ciphertext_hasher.update(frame_res.value().framed_bytes); ct_upd.is_error()) {
                return fail_closed(&part_path, ct_upd.error().user_message());
            }
        }
    }

    const std::ios::openmode out_mode = (record.completed_chunks > 0U)
                                            ? (std::ios::binary | std::ios::out | std::ios::app)
                                            : (std::ios::binary | std::ios::out | std::ios::trunc);
    std::ofstream part_out(part_path, out_mode);
    if (!part_out.is_open()) {
        return fail_closed(&part_path, "Failed to open download staging .part file for writing",
                           ClientErrorCategory::Storage);
    }

    for (uint32_t idx = record.completed_chunks; idx < record.total_chunks; ++idx) {
        const ControlAction action = poll_control_action(record.transfer_id);
        if (action == ControlAction::Cancel) {
            part_out.close();
            (void)abort_and_mark_cancelled(record);
            return ClientResult<domain::FileTransferRecord>::error(
                ClientError::validation("File download cancelled by user"));
        }
        if (action == ControlAction::Pause) {
            part_out.close();
            record.status = domain::FileTransferStatus::Paused;
            record.error_message.clear();
            (void)persist_and_notify(record);
            return ClientResult<domain::FileTransferRecord>::ok(std::move(record));
        }

        const auto dl_res = gateway_.download_file_chunk(record.file_id, idx);
        if (dl_res.is_error()) {
            part_out.close();
            if (dl_res.error().category() == ClientErrorCategory::Network) {
                record.status = domain::FileTransferStatus::Paused;
                record.error_message = dl_res.error().user_message();
                (void)persist_and_notify(record);
                return ClientResult<domain::FileTransferRecord>::error(dl_res.error());
            }
            return fail_closed(&part_path, dl_res.error().user_message());
        }

        const bool is_final = (idx + 1U == record.total_chunks);
        const auto& chunk_dl = dl_res.value();
        if (const auto ct_upd = ciphertext_hasher.update(chunk_dl.encrypted_data); ct_upd.is_error()) {
            part_out.close();
            return fail_closed(&part_path, ct_upd.error().user_message());
        }

        const auto pt_res = engine.decrypt_chunk(crypto_provider_, raw_key_res.value(), record.file_id, idx, is_final,
                                                 chunk_dl.encrypted_data, chunk_dl.ciphertext_sha256);
        if (pt_res.is_error()) {
            part_out.close();
            return fail_closed(&part_path, pt_res.error().user_message());
        }

        const auto& pt_bytes = pt_res.value();
        if (const auto pt_upd = plaintext_hasher.update(pt_bytes); pt_upd.is_error()) {
            part_out.close();
            return fail_closed(&part_path, pt_upd.error().user_message());
        }

        if (!pt_bytes.empty()) {
            part_out.write(reinterpret_cast<const char*>(pt_bytes.data()),
                           static_cast<std::streamsize>(pt_bytes.size()));
            part_out.flush();
            if (!part_out.good()) {
                part_out.close();
                return fail_closed(&part_path, "Disk write error while staging decrypted chunk",
                                   ClientErrorCategory::Storage);
            }
        }

        record.completed_chunks = idx + 1U;
        record.error_message.clear();
        if (const auto ckpt_res = persist_and_notify(record); ckpt_res.is_error()) {
            part_out.close();
            return ClientResult<domain::FileTransferRecord>::error(ckpt_res.error());
        }
    }

    part_out.close();
    if (!part_out.good()) {
        return fail_closed(&part_path, "Failed to flush and close download staging file", ClientErrorCategory::Storage);
    }

    const ControlAction post_loop_action = poll_control_action(record.transfer_id);
    if (post_loop_action == ControlAction::Cancel) {
        (void)abort_and_mark_cancelled(record);
        return ClientResult<domain::FileTransferRecord>::error(
            ClientError::validation("File download cancelled by user"));
    }

    const auto ct_sha_res = ciphertext_hasher.finalize_hex();
    const auto pt_sha_res = plaintext_hasher.finalize_hex();
    if (ct_sha_res.is_error() || pt_sha_res.is_error()) {
        return fail_closed(&part_path, "Failed to finalize dual SHA-256 verification digests");
    }

    std::error_code size_ec;
    const uint64_t staged_size = std::filesystem::file_size(part_path, size_ec);
    if (size_ec || staged_size != record.plaintext_size_bytes ||
        ct_sha_res.value() != to_lower_ascii(record.ciphertext_sha256) ||
        pt_sha_res.value() != to_lower_ascii(record.plaintext_sha256)) {
        return fail_closed(&part_path,
                           "Whole-file dual SHA-256 or byte-length verification failed against E2EE key envelope");
    }

    std::error_code rename_ec;
    std::filesystem::rename(part_path, dest_path, rename_ec);
    if (rename_ec) {
        remove_file_quietly(dest_path);
        rename_ec.clear();
        std::filesystem::rename(part_path, dest_path, rename_ec);
        if (rename_ec) {
            return fail_closed(&part_path, "Failed to commit verified download file: " + rename_ec.message(),
                               ClientErrorCategory::Storage);
        }
    }

    record.status = domain::FileTransferStatus::Completed;
    record.completed_chunks = record.total_chunks;
    record.error_message.clear();
    if (const auto done_res = persist_and_notify(record); done_res.is_error()) {
        return ClientResult<domain::FileTransferRecord>::error(done_res.error());
    }

    return ClientResult<domain::FileTransferRecord>::ok(std::move(record));
}

ClientResult<domain::FileTransferRecord> FileManager::resume_transfer(std::string_view transfer_id) {
    if (const auto deps = ensure_stateful_storage(); deps.is_error()) {
        return ClientResult<domain::FileTransferRecord>::error(deps.error());
    }
    if (transfer_id.empty()) {
        return ClientResult<domain::FileTransferRecord>::error(ClientError::validation("Transfer ID cannot be empty"));
    }

    const auto rec_res = local_store_->get_file_transfer(transfer_id);
    if (rec_res.is_error()) {
        return ClientResult<domain::FileTransferRecord>::error(rec_res.error());
    }

    if (rec_res.value().direction == domain::FileTransferDirection::Outbound) {
        return resume_upload(transfer_id).transform([](const FileUploadResult& res) { return res.record; });
    }
    return resume_download(transfer_id);
}

ClientResult<std::size_t> FileManager::resume_interrupted_transfers() {
    if (const auto deps = ensure_stateful_storage(); deps.is_error()) {
        return ClientResult<std::size_t>::error(deps.error());
    }

    const auto list_res = local_store_->list_file_transfers();
    if (list_res.is_error()) {
        return ClientResult<std::size_t>::error(list_res.error());
    }

    std::size_t resumed_count = 0U;
    for (const auto& record : list_res.value()) {
        {
            std::lock_guard<std::mutex> lock(control_mutex_);
            if (active_transfers_.contains(record.transfer_id)) {
                continue;
            }
        }

        if (record.status == domain::FileTransferStatus::Completed ||
            record.status == domain::FileTransferStatus::Cancelled ||
            record.status == domain::FileTransferStatus::Failed) {
            continue;
        }
        // Respect explicit user pause (Paused with empty error_message)
        if (record.status == domain::FileTransferStatus::Paused && record.error_message.empty()) {
            continue;
        }
        // Never auto-download an inbound key envelope before the user selects a destination path
        if (record.direction == domain::FileTransferDirection::Inbound && record.local_path.empty()) {
            continue;
        }

        const auto resume_res = resume_transfer(record.transfer_id);
        if (resume_res.is_ok()) {
            ++resumed_count;
            continue;
        }
        if (resume_res.error().category() == ClientErrorCategory::Network) {
            break;
        }
    }

    return ClientResult<std::size_t>::ok(resumed_count);
}

ClientResult<void> FileManager::pause_transfer(std::string_view transfer_id) {
    if (transfer_id.empty()) {
        return ClientResult<void>::error(ClientError::validation("Transfer ID cannot be empty"));
    }

    const std::string key(transfer_id);
    {
        std::lock_guard<std::mutex> lock(control_mutex_);
        if (active_transfers_.contains(key)) {
            pause_requested_transfers_.insert(key);
            return ClientResult<void>::ok();
        }
    }

    if (local_store_ == nullptr) {
        return ClientResult<void>::ok();
    }

    const auto rec_res = local_store_->get_file_transfer(transfer_id);
    if (rec_res.is_error()) {
        return ClientResult<void>::error(rec_res.error());
    }
    domain::FileTransferRecord record = rec_res.value();
    if (record.status == domain::FileTransferStatus::Completed ||
        record.status == domain::FileTransferStatus::Cancelled || record.status == domain::FileTransferStatus::Failed) {
        return ClientResult<void>::error(ClientError::validation("Cannot pause transfer in terminal state: " +
                                                                 std::string(to_string(record.status))));
    }
    if (record.status == domain::FileTransferStatus::Paused) {
        return ClientResult<void>::ok();
    }
    record.status = domain::FileTransferStatus::Paused;
    return persist_and_notify(record);
}

ClientResult<void> FileManager::cancel_transfer(std::string_view transfer_id) {
    if (transfer_id.empty()) {
        return ClientResult<void>::error(ClientError::validation("Transfer ID cannot be empty"));
    }

    const std::string key(transfer_id);
    {
        std::lock_guard<std::mutex> lock(control_mutex_);
        if (active_transfers_.contains(key)) {
            cancel_requested_transfers_.insert(key);
            return ClientResult<void>::ok();
        }
    }

    if (local_store_ == nullptr) {
        return ClientResult<void>::ok();
    }

    const auto rec_res = local_store_->get_file_transfer(transfer_id);
    if (rec_res.is_error()) {
        // Allow legacy WorkspaceViewModel in-memory stub transfer IDs before T05 wires start_upload
        return ClientResult<void>::ok();
    }

    domain::FileTransferRecord record = rec_res.value();
    return abort_and_mark_cancelled(record);
}

ClientResult<domain::FileTransferRecord> FileManager::get_transfer(std::string_view transfer_id) {
    if (const auto deps = ensure_stateful_storage(); deps.is_error()) {
        return ClientResult<domain::FileTransferRecord>::error(deps.error());
    }
    return local_store_->get_file_transfer(transfer_id);
}

ClientResult<std::vector<domain::FileTransferRecord>>
FileManager::list_transfers(const domain::ConversationId& conversation_id) {
    if (const auto deps = ensure_stateful_storage(); deps.is_error()) {
        return ClientResult<std::vector<domain::FileTransferRecord>>::error(deps.error());
    }
    return local_store_->list_file_transfers(conversation_id);
}

std::vector<std::filesystem::path> FileManager::wipe_volatile_state() {
    std::vector<std::filesystem::path> part_paths;
    if (local_store_ != nullptr) {
        const auto transfers_res = local_store_->list_file_transfers();
        if (transfers_res.is_ok()) {
            part_paths.reserve(transfers_res.value().size());
            for (const auto& rec : transfers_res.value()) {
                if (rec.local_path.empty()) {
                    continue;
                }
                static constexpr std::string_view kPartExt = ".part";
                if (rec.local_path.size() >= kPartExt.size() &&
                    rec.local_path.compare(rec.local_path.size() - kPartExt.size(), kPartExt.size(), kPartExt) == 0) {
                    part_paths.emplace_back(rec.local_path);
                } else {
                    part_paths.emplace_back(rec.local_path + ".part");
                }
            }
        }
    }

    std::lock_guard<std::mutex> lock(control_mutex_);
    active_transfers_.clear();
    pause_requested_transfers_.clear();
    cancel_requested_transfers_.clear();
    local_user_id_ = domain::UserId{};
    local_device_id_ = domain::DeviceId{};
    return part_paths;
}

ClientResult<std::string> FileManager::prepare_encrypted_upload(std::string_view local_file_path) {
    if (local_file_path.empty()) {
        return ClientResult<std::string>::error(ClientError::validation("File path cannot be empty"));
    }
    const auto probe_res = gateway_.probe_gateway("/health");
    if (probe_res.is_error()) {
        return ClientResult<std::string>::error(probe_res.error());
    }
    return ClientResult<std::string>::ok("transfer-id-001");
}

} // namespace securecloud::client::application::managers
