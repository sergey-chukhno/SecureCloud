#include "file_spool_pending_store.hpp"

#include <chrono>
#include <cstring>
#include <fstream>

namespace securecloud::gateway::audit {

namespace {

constexpr uint32_t kWalMagic = 0x53435741; // "SCWA"
constexpr uint16_t kWalVersion = 1;

#pragma pack(push, 1)
struct RecordHeader {
    uint32_t magic{kWalMagic};
    uint16_t version{kWalVersion};
    uint32_t payload_length{0};
    uint32_t crc32c{0};
    int64_t enqueued_at_ms{0};
    uint32_t attempt_count{0};
    uint8_t event_id_bytes[16]{};
};
#pragma pack(pop)

} // namespace

FileSpoolPendingStore::FileSpoolPendingStore(GatewayAuditSpoolConfig config) : config_(std::move(config)) {
    init_spool();
}

FileSpoolPendingStore::~FileSpoolPendingStore() {
    running_.store(false, std::memory_order_release);
    cv_.notify_all();
    if (writer_thread_.joinable()) {
        writer_thread_.join();
    }
}

void FileSpoolPendingStore::init_spool() {
    try {
        std::error_code ec;
        std::filesystem::create_directories(config_.spool_directory, ec);
        if (ec) {
            available_.store(false, std::memory_order_release);
            return;
        }

        recover_and_rebuild_index();
        available_.store(true, std::memory_order_release);

        writer_thread_ = std::thread(&FileSpoolPendingStore::writer_thread_loop, this);
    } catch (...) {
        available_.store(false, std::memory_order_release);
    }
}

void FileSpoolPendingStore::recover_and_rebuild_index() {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto wal_path = std::filesystem::path(config_.spool_directory) / "spool.wal";

    if (!std::filesystem::exists(wal_path)) {
        return;
    }

    std::ifstream file(wal_path, std::ios::binary);
    if (!file) {
        return;
    }

    while (file.peek() != EOF) {
        RecordHeader hdr;
        file.read(reinterpret_cast<char*>(&hdr), sizeof(RecordHeader));
        if (file.gcount() < static_cast<std::streamsize>(sizeof(RecordHeader))) {
            ++unrecoverable_count_;
            break;
        }

        if (hdr.magic != kWalMagic || hdr.version != kWalVersion) {
            ++unrecoverable_count_;
            break;
        }

        std::vector<uint8_t> payload(hdr.payload_length);
        file.read(reinterpret_cast<char*>(payload.data()), hdr.payload_length);
        if (file.gcount() < static_cast<std::streamsize>(hdr.payload_length)) {
            ++unrecoverable_count_;
            break;
        }

        const uint32_t calculated_crc = compute_crc32c(payload);
        if (calculated_crc != hdr.crc32c) {
            ++unrecoverable_count_;
            break;
        }

        securecloud::audit::domain::EventId::bytes_type bytes;
        std::memcpy(bytes.data(), hdr.event_id_bytes, 16);
        const auto id = securecloud::audit::domain::EventId(bytes);

        PendingRecord rec;
        rec.event_id = id;
        rec.proto_bytes = std::move(payload);
        rec.enqueued_at = std::chrono::system_clock::time_point(std::chrono::milliseconds(hdr.enqueued_at_ms));
        rec.attempt_count = hdr.attempt_count;

        total_spool_bytes_ += rec.proto_bytes.size() + sizeof(RecordHeader);
        pending_map_[id] = rec;
        pending_order_.push_back(id);
    }
}

AdmissionResult FileSpoolPendingStore::append(PendingRecord record) noexcept {
    if (!available_.load(std::memory_order_relaxed)) {
        return AdmissionResult::RejectedUnavailable;
    }

    std::unique_lock<std::mutex> lock(mutex_);

    if (pending_map_.size() + handoff_queue_.size() >= config_.max_spool_records) {
        ++dropped_count_;
        return AdmissionResult::RejectedFull;
    }

    handoff_queue_.push_back(std::move(record));
    cv_.notify_one();

    return AdmissionResult::AcceptedPendingSync;
}

void FileSpoolPendingStore::writer_thread_loop() {
    while (running_.load(std::memory_order_acquire)) {
        std::unique_lock<std::mutex> lock(mutex_);
        cv_.wait_for(lock, std::chrono::milliseconds(config_.group_commit_interval_ms),
                     [this] { return !handoff_queue_.empty() || !running_.load(std::memory_order_relaxed); });

        if (handoff_queue_.empty()) {
            continue;
        }

        perform_group_commit();
    }
}

void FileSpoolPendingStore::perform_group_commit() {
    std::vector<PendingRecord> batch;
    while (!handoff_queue_.empty() && batch.size() < config_.group_commit_record_threshold) {
        batch.push_back(std::move(handoff_queue_.front()));
        handoff_queue_.pop_front();
    }

    const auto wal_path = std::filesystem::path(config_.spool_directory) / "spool.wal";
    std::ofstream file(wal_path, std::ios::binary | std::ios::app);

    if (!file) {
        available_.store(false, std::memory_order_release);
        return;
    }

    for (auto& rec : batch) {
        RecordHeader hdr;
        hdr.payload_length = static_cast<uint32_t>(rec.proto_bytes.size());
        hdr.crc32c = compute_crc32c(rec.proto_bytes);
        hdr.enqueued_at_ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(rec.enqueued_at.time_since_epoch()).count();
        hdr.attempt_count = rec.attempt_count;
        std::memcpy(hdr.event_id_bytes, rec.event_id.bytes().data(), 16);

        file.write(reinterpret_cast<const char*>(&hdr), sizeof(RecordHeader));
        file.write(reinterpret_cast<const char*>(rec.proto_bytes.data()), rec.proto_bytes.size());

        total_spool_bytes_ += rec.proto_bytes.size() + sizeof(RecordHeader);
        const auto id = rec.event_id;
        pending_map_[id] = rec;
        pending_order_.push_back(id);
    }

    file.flush();
}

std::vector<PendingRecord> FileSpoolPendingStore::claim_batch(size_t max_records) {
    std::lock_guard<std::mutex> lock(mutex_);

    std::vector<PendingRecord> batch;
    batch.reserve(std::min(max_records, pending_order_.size()));

    size_t claimed = 0;
    while (!pending_order_.empty() && claimed < max_records) {
        const auto id = pending_order_.front();
        pending_order_.pop_front();

        auto it = pending_map_.find(id);
        if (it != pending_map_.end()) {
            it->second.attempt_count++;
            claimed_map_[id] = it->second;
            batch.push_back(it->second);
            pending_map_.erase(it);
            ++claimed;
        }
    }

    return batch;
}

void FileSpoolPendingStore::mark_delivered(std::span<const securecloud::audit::domain::EventId> event_ids) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& id : event_ids) {
        claimed_map_.erase(id);
        delivered_set_.insert(id);
    }
}

void FileSpoolPendingStore::mark_terminal(const securecloud::audit::domain::EventId& event_id,
                                          TerminalReason /*reason*/) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (claimed_map_.erase(event_id) > 0) {
        ++unrecoverable_count_;
    }
}

void FileSpoolPendingStore::release(std::span<const securecloud::audit::domain::EventId> event_ids) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (const auto& id : event_ids) {
        auto it = claimed_map_.find(id);
        if (it != claimed_map_.end()) {
            pending_map_[id] = std::move(it->second);
            pending_order_.push_front(id);
            claimed_map_.erase(it);
        }
    }
}

PendingStats FileSpoolPendingStore::stats() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    PendingStats s;
    s.total_records = pending_map_.size() + claimed_map_.size() + handoff_queue_.size();
    s.total_bytes = total_spool_bytes_;
    s.claimed_records = claimed_map_.size();
    s.dropped_records = dropped_count_;
    s.unrecoverable_records = unrecoverable_count_;
    return s;
}

} // namespace securecloud::gateway::audit
