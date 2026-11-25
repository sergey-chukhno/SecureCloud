#include "application/managers/sync_manager.hpp"

#include "application/managers/contact_manager.hpp"
#include "application/managers/file_manager.hpp"
#include "application/managers/messaging_manager.hpp"
#include "domain/file_transfer.hpp"

#include <algorithm>
#include <chrono>
#include <vector>

namespace securecloud::client::application::managers {

namespace {

int64_t current_unix_ms() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
        .count();
}

uint64_t resolve_page_delivered_sequence(const domain::ConversationMessagesPage& page) noexcept {
    uint64_t max_event_seq = 0ULL;
    for (const auto& ev : page.events) {
        max_event_seq = std::max(max_event_seq, ev.server_sequence_number);
    }
    if (max_event_seq > 0ULL) {
        return max_event_seq;
    }
    if (page.latest_sequence > 0ULL) {
        return page.latest_sequence;
    }
    return page.events.empty() ? 0ULL : page.next_sequence;
}

class ScopedAtomicBool {
  public:
    explicit ScopedAtomicBool(std::atomic<bool>& flag) noexcept : flag_(flag), previous_(flag.exchange(true)) {}
    ~ScopedAtomicBool() { flag_.store(previous_); }

    ScopedAtomicBool(const ScopedAtomicBool&) = delete;
    ScopedAtomicBool& operator=(const ScopedAtomicBool&) = delete;

  private:
    std::atomic<bool>& flag_;
    bool previous_;
};

} // namespace

SyncManager::SyncManager(interfaces::IGatewayClient& gateway, const ClientConfig& config)
    : gateway_(gateway), config_(config) {}

void SyncManager::set_local_store(interfaces::ILocalStore* local_store) noexcept {
    local_store_ = local_store;
}

void SyncManager::set_messaging_manager(MessagingManager* messaging_manager) noexcept {
    messaging_manager_ = messaging_manager;
    if (messaging_manager_ != nullptr) {
        messaging_manager_->set_offline_mode(connectivity_state() == domain::ConnectivityState::Offline);
    }
}

void SyncManager::set_contact_manager(ContactManager* contact_manager) noexcept {
    contact_manager_ = contact_manager;
}

void SyncManager::set_file_manager(FileManager* file_manager) noexcept {
    file_manager_ = file_manager;
}

void SyncManager::set_local_identity(const domain::UserId& user_id, const domain::DeviceId& device_id) {
    std::lock_guard<std::mutex> lock(state_mutex_);
    local_user_id_ = user_id;
    local_device_id_ = device_id;
}

ClientResult<void> SyncManager::start_sync() {
    is_syncing_.store(true);
    return ClientResult<void>::ok();
}

ClientResult<void> SyncManager::stop_sync() {
    is_syncing_.store(false);
    return ClientResult<void>::ok();
}

domain::ConnectivityState SyncManager::connectivity_state() const noexcept {
    std::lock_guard<std::mutex> lock(state_mutex_);
    return connectivity_state_;
}

uint64_t SyncManager::subscribe_connectivity_state(ConnectivityStateCallback callback) {
    std::lock_guard<std::mutex> lock(state_mutex_);
    const uint64_t id = next_connectivity_sub_id_++;
    if (callback) {
        connectivity_subscribers_.emplace(id, std::move(callback));
    }
    return id;
}

void SyncManager::unsubscribe_connectivity_state(uint64_t subscription_id) {
    std::lock_guard<std::mutex> lock(state_mutex_);
    connectivity_subscribers_.erase(subscription_id);
}

bool SyncManager::transition_connectivity_state(domain::ConnectivityState next_state) {
    std::vector<ConnectivityStateCallback> callbacks;
    {
        std::lock_guard<std::mutex> lock(state_mutex_);
        if (connectivity_state_ == next_state) {
            return true;
        }
        if (!domain::can_transition_connectivity_state(connectivity_state_, next_state)) {
            return false;
        }
        connectivity_state_ = next_state;
        callbacks.reserve(connectivity_subscribers_.size());
        for (const auto& [_, cb] : connectivity_subscribers_) {
            callbacks.push_back(cb);
        }
    }

    if (messaging_manager_ != nullptr) {
        messaging_manager_->set_offline_mode(next_state == domain::ConnectivityState::Offline);
    }
    for (const auto& cb : callbacks) {
        if (cb) {
            cb(next_state);
        }
    }
    return true;
}

ClientResult<domain::ConnectivityState> SyncManager::set_simulated_offline(bool offline) {
    simulated_offline_.store(offline);
    if (offline) {
        (void)transition_connectivity_state(domain::ConnectivityState::Offline);
        return ClientResult<domain::ConnectivityState>::ok(domain::ConnectivityState::Offline);
    }

    domain::UserId uid;
    domain::DeviceId did;
    domain::ConnectivityState current = domain::ConnectivityState::Online;
    {
        std::lock_guard<std::mutex> lock(state_mutex_);
        uid = local_user_id_;
        did = local_device_id_;
        current = connectivity_state_;
    }

    if (current != domain::ConnectivityState::Offline) {
        return ClientResult<domain::ConnectivityState>::ok(current);
    }

    if (!did.empty()) {
        const auto sync_res = execute_catch_up_sync(uid, did);
        if (sync_res.is_error()) {
            return ClientResult<domain::ConnectivityState>::error(sync_res.error());
        }
        return ClientResult<domain::ConnectivityState>::ok(connectivity_state());
    }

    const auto probe_res = gateway_.probe_gateway("/health");
    if (probe_res.is_error()) {
        return ClientResult<domain::ConnectivityState>::error(probe_res.error());
    }
    (void)transition_connectivity_state(domain::ConnectivityState::Syncing);
    (void)transition_connectivity_state(domain::ConnectivityState::Online);
    return ClientResult<domain::ConnectivityState>::ok(domain::ConnectivityState::Online);
}

ClientResult<domain::ConnectivityState> SyncManager::check_connectivity() {
    if (simulated_offline_.load()) {
        (void)transition_connectivity_state(domain::ConnectivityState::Offline);
        return ClientResult<domain::ConnectivityState>::ok(domain::ConnectivityState::Offline);
    }

    const auto probe_res = gateway_.probe_gateway("/health");
    if (probe_res.is_error()) {
        (void)transition_connectivity_state(domain::ConnectivityState::Offline);
        return ClientResult<domain::ConnectivityState>::ok(domain::ConnectivityState::Offline);
    }

    domain::UserId uid;
    domain::DeviceId did;
    domain::ConnectivityState current = domain::ConnectivityState::Online;
    {
        std::lock_guard<std::mutex> lock(state_mutex_);
        uid = local_user_id_;
        did = local_device_id_;
        current = connectivity_state_;
    }

    if (current == domain::ConnectivityState::Offline) {
        if (!did.empty()) {
            (void)execute_catch_up_sync(uid, did);
            return ClientResult<domain::ConnectivityState>::ok(connectivity_state());
        }
        (void)transition_connectivity_state(domain::ConnectivityState::Syncing);
        (void)transition_connectivity_state(domain::ConnectivityState::Online);
        return ClientResult<domain::ConnectivityState>::ok(domain::ConnectivityState::Online);
    }

    return ClientResult<domain::ConnectivityState>::ok(current);
}

void SyncManager::hydrate_local_cursors(const domain::DeviceId& device_id) {
    if (local_store_ == nullptr || device_id.empty()) {
        return;
    }
    const auto cursors_res = local_store_->list_sync_cursors(device_id);
    if (cursors_res.is_error()) {
        return;
    }
    std::lock_guard<std::mutex> lock(state_mutex_);
    for (const auto& cur : cursors_res.value()) {
        if (cur.conversation_id.empty()) {
            continue;
        }
        auto& stored = conversation_cursors_[cur.conversation_id];
        if (cur.last_delivered_sequence > stored) {
            stored = cur.last_delivered_sequence;
        }
    }
}

void SyncManager::persist_local_cursor(const domain::DeviceId& device_id, const domain::ConversationId& conversation_id,
                                       uint64_t sequence) {
    {
        std::lock_guard<std::mutex> lock(state_mutex_);
        auto& stored = conversation_cursors_[conversation_id];
        if (sequence > stored) {
            stored = sequence;
        } else {
            sequence = stored;
        }
    }
    if (local_store_ != nullptr && !device_id.empty()) {
        (void)local_store_->save_sync_cursor(domain::SyncCursorRecord{
            .device_id = device_id,
            .conversation_id = conversation_id,
            .last_delivered_sequence = sequence,
            .last_sync_timestamp_ms = current_unix_ms(),
            .sync_version = 1,
        });
    }
}

ClientResult<domain::CatchUpSyncReport> SyncManager::execute_catch_up_sync(const domain::UserId& local_user_id,
                                                                           const domain::DeviceId& local_device_id,
                                                                           std::size_t page_limit,
                                                                           std::size_t max_pages_per_conversation) {
    domain::UserId effective_user_id = local_user_id;
    domain::DeviceId effective_device_id = local_device_id;
    {
        std::lock_guard<std::mutex> lock(state_mutex_);
        if (effective_user_id.empty()) {
            effective_user_id = local_user_id_;
        }
        if (effective_device_id.empty()) {
            effective_device_id = local_device_id_;
        }
    }

    if (effective_device_id.empty()) {
        return ClientResult<domain::CatchUpSyncReport>::error(
            ClientError::validation("Local device ID is required for catch-up synchronization"));
    }
    if (simulated_offline_.load()) {
        (void)transition_connectivity_state(domain::ConnectivityState::Offline);
        return ClientResult<domain::CatchUpSyncReport>::error(
            ClientError::network("Cannot run catch-up sync while simulated offline mode is enabled"));
    }

    ScopedAtomicBool syncing_guard(is_syncing_);
    (void)transition_connectivity_state(domain::ConnectivityState::Syncing);

    domain::CatchUpSyncReport report;
    const std::size_t effective_page_limit = page_limit == 0U ? 50U : page_limit;
    const std::size_t effective_max_pages = max_pages_per_conversation == 0U ? 100U : max_pages_per_conversation;

    auto fail_offline = [this](const ClientError& err) -> ClientResult<domain::CatchUpSyncReport> {
        if (err.category() == ClientErrorCategory::Network) {
            (void)transition_connectivity_state(domain::ConnectivityState::Offline);
        }
        return ClientResult<domain::CatchUpSyncReport>::error(err);
    };

    // Phase 1: Cursor Hydration & Remote Floor Check
    hydrate_local_cursors(effective_device_id);
    if (local_store_ != nullptr) {
        const auto local_convs_res = local_store_->list_conversations();
        if (local_convs_res.is_ok()) {
            for (const auto& conv : local_convs_res.value()) {
                const auto& cid = conv.conversation_id();
                if (conversation_cursor(cid) == 0ULL) {
                    const auto remote_cur_res = gateway_.get_sync_cursor(effective_device_id, cid);
                    if (remote_cur_res.is_error()) {
                        return fail_offline(remote_cur_res.error());
                    }
                    if (remote_cur_res.value().last_delivered_sequence > 0ULL) {
                        persist_local_cursor(effective_device_id, cid, remote_cur_res.value().last_delivered_sequence);
                    }
                }
            }
        }
    }

    // Phase 2: Durable Offline Outbox Flush & Interrupted File Transfer Resumption
    if (messaging_manager_ != nullptr) {
        messaging_manager_->set_offline_mode(false);
        report.outbox_flushed_count = messaging_manager_->flush_offline_outbox();
        report.outbox_remaining_count = messaging_manager_->pending_outbox_count();
    }
    if (file_manager_ != nullptr) {
        const auto resumed_res = file_manager_->resume_interrupted_transfers();
        if (resumed_res.is_ok()) {
            report.transfers_resumed_count = resumed_res.value();
        }
    }

    // Phase 3: Remote Conversation & Contact Reconciliation
    if (local_store_ != nullptr && !effective_user_id.empty()) {
        const auto remote_convs_res = gateway_.list_remote_conversations(effective_user_id);
        if (remote_convs_res.is_error()) {
            return fail_offline(remote_convs_res.error());
        }

        for (const auto& remote : remote_convs_res.value()) {
            if (remote.conversation_id.empty()) {
                continue;
            }
            const auto existing_res = local_store_->get_conversation(remote.conversation_id);
            const auto remote_created_tp =
                remote.created_at_ms > 0
                    ? std::chrono::system_clock::time_point(std::chrono::milliseconds(remote.created_at_ms))
                    : std::chrono::system_clock::now();

            if (existing_res.is_error()) {
                std::vector<domain::UserId> participants = remote.participant_user_ids;
                if (!remote.creator_user_id.empty() &&
                    std::find(participants.begin(), participants.end(), remote.creator_user_id) == participants.end()) {
                    participants.push_back(remote.creator_user_id);
                }
                domain::Conversation new_conv(remote.conversation_id, remote.type, remote.title,
                                              std::move(participants), remote_created_tp, remote_created_tp, 0U, false);
                if (remote.type == domain::ConversationType::Group && !remote.creator_user_id.empty()) {
                    new_conv.set_participant_role(remote.creator_user_id, domain::ParticipantRole::Admin);
                }
                if (local_store_->save_conversation(new_conv).is_ok()) {
                    ++report.conversations_reconciled_count;
                }
            } else {
                domain::Conversation merged = existing_res.value();
                bool changed = false;
                if (!remote.title.empty() && remote.title != merged.title()) {
                    merged.set_title(remote.title);
                    changed = true;
                }
                for (const auto& pid : remote.participant_user_ids) {
                    if (!pid.empty() && !merged.has_participant(pid)) {
                        merged.add_participant(pid, domain::ParticipantRole::Member);
                        changed = true;
                    }
                }
                if (remote_created_tp > merged.last_activity_at()) {
                    merged.set_last_activity_at(remote_created_tp);
                    changed = true;
                }
                if (changed && local_store_->save_conversation(merged).is_ok()) {
                    ++report.conversations_reconciled_count;
                }
            }
        }
    }

    if (contact_manager_ != nullptr) {
        const auto contacts_res = contact_manager_->sync_contacts();
        if (contacts_res.is_error()) {
            return fail_offline(contacts_res.error());
        }
        report.contacts_reconciled_count = contacts_res.value();
    }

    // Phase 4: Multi-Page Per-Conversation Delta Catch-Up & Durable Cursor Checkpointing
    std::vector<domain::Conversation> all_conversations;
    if (local_store_ != nullptr) {
        const auto convs_res = local_store_->list_conversations();
        if (convs_res.is_ok()) {
            all_conversations = convs_res.value();
        }
    } else if (messaging_manager_ != nullptr) {
        const auto convs_res = messaging_manager_->list_conversations();
        if (convs_res.is_ok()) {
            all_conversations = convs_res.value();
        }
    }

    for (const auto& conv : all_conversations) {
        const auto& cid = conv.conversation_id();
        uint64_t since_seq = conversation_cursor(cid);

        for (std::size_t page_idx = 0U; page_idx < effective_max_pages; ++page_idx) {
            const auto page_res =
                gateway_.fetch_conversation_messages(cid, effective_device_id, since_seq, effective_page_limit);
            if (page_res.is_error()) {
                return fail_offline(page_res.error());
            }

            const auto& page = page_res.value();
            if (messaging_manager_ != nullptr) {
                for (const auto& ev : page.events) {
                    const bool is_message_event = (ev.type == domain::RealtimeEventType::InboundDirectMessage ||
                                                   ev.type == domain::RealtimeEventType::InboundGroupMessage);
                    const bool already_present = is_message_event && local_store_ != nullptr &&
                                                 !ev.message_id.empty() &&
                                                 local_store_->get_message(cid, ev.message_id).is_ok();

                    const auto proc_res = messaging_manager_->process_inbound_realtime_event(ev);
                    if (proc_res.is_ok()) {
                        if (already_present) {
                            ++report.duplicates_skipped_count;
                        } else if (proc_res.value().has_value()) {
                            ++report.messages_merged_count;
                            const auto& msg = *proc_res.value();
                            if (file_manager_ != nullptr &&
                                domain::FileAttachmentKeyEnvelope::is_file_attachment_envelope(
                                    msg.encrypted_envelope_ref())) {
                                (void)file_manager_->ingest_inbound_key_envelope_json(cid, msg.sender_user_id(),
                                                                                      msg.encrypted_envelope_ref());
                            }
                        }
                    }
                }
            }

            const uint64_t page_cursor = resolve_page_delivered_sequence(page);
            const uint64_t next_seq = std::max(since_seq, page_cursor);
            if (next_seq > since_seq) {
                since_seq = next_seq;
                persist_local_cursor(effective_device_id, cid, since_seq);
                const auto gw_cur_res = gateway_.update_sync_cursor(domain::SyncCursorRecord{
                    .device_id = effective_device_id,
                    .conversation_id = cid,
                    .last_delivered_sequence = since_seq,
                    .last_sync_timestamp_ms = current_unix_ms(),
                    .sync_version = 1,
                });
                if (gw_cur_res.is_error()) {
                    return fail_offline(gw_cur_res.error());
                }
            }

            if (!page.has_more || page.events.empty()) {
                break;
            }
        }
    }

    (void)transition_connectivity_state(domain::ConnectivityState::Online);
    return ClientResult<domain::CatchUpSyncReport>::ok(report);
}

ClientResult<std::size_t> SyncManager::poll_sync() {
    if (!is_syncing_.load()) {
        return ClientResult<std::size_t>::ok(0);
    }
    const auto sync_res = gateway_.sync_messages("");
    if (sync_res.is_error()) {
        return ClientResult<std::size_t>::error(sync_res.error());
    }
    return ClientResult<std::size_t>::ok(sync_res.value().size());
}

uint64_t SyncManager::conversation_cursor(const domain::ConversationId& conversation_id) const {
    std::lock_guard<std::mutex> lock(state_mutex_);
    const auto it = conversation_cursors_.find(conversation_id);
    return it != conversation_cursors_.end() ? it->second : 0ULL;
}

ClientResult<std::size_t> SyncManager::poll_realtime_updates(const domain::DeviceId& local_device_id) {
    if (!messaging_manager_ || local_device_id.empty()) {
        return ClientResult<std::size_t>::ok(0);
    }

    hydrate_local_cursors(local_device_id);
    std::size_t processed = messaging_manager_->process_retry_queue();

    const auto convs_res = messaging_manager_->list_conversations();
    if (convs_res.is_error()) {
        return ClientResult<std::size_t>::error(convs_res.error());
    }

    for (const auto& conv : convs_res.value()) {
        const auto& cid = conv.conversation_id();
        const uint64_t since_seq = conversation_cursor(cid);
        auto page_res = gateway_.fetch_conversation_messages(cid, local_device_id, since_seq, 50);
        if (page_res.is_ok()) {
            const auto& page = page_res.value();
            for (const auto& ev : page.events) {
                auto proc_res = messaging_manager_->process_inbound_realtime_event(ev);
                if (proc_res.is_ok()) {
                    ++processed;
                }
            }
            const uint64_t page_seq = resolve_page_delivered_sequence(page);
            if (page_seq > since_seq) {
                persist_local_cursor(local_device_id, cid, page_seq);
            }
        }

        // Poll delivery status for recent in-flight outbound messages
        auto msgs_res = messaging_manager_->get_conversation_messages(cid, 50);
        if (msgs_res.is_ok()) {
            for (const auto& msg : msgs_res.value()) {
                const auto state = msg.delivery_state();
                if (state == domain::DeliveryState::Accepted || state == domain::DeliveryState::Delivering ||
                    state == domain::DeliveryState::Delivered) {
                    auto status_res = gateway_.get_message_delivery_status(cid, msg.message_id());
                    if (status_res.is_ok()) {
                        const auto& info = status_res.value();
                        if (info.delivery_state != state ||
                            info.server_sequence_number > msg.server_sequence_number()) {
                            (void)messaging_manager_->update_message_delivery_state(
                                cid, msg.message_id(), info.delivery_state, info.server_sequence_number);
                            ++processed;
                        }
                    }
                }
            }
        }
    }

    return ClientResult<std::size_t>::ok(processed);
}

std::size_t SyncManager::wipe_volatile_state() {
    std::lock_guard<std::mutex> lock(state_mutex_);
    const std::size_t cleared_cursors = conversation_cursors_.size();
    conversation_cursors_.clear();
    local_user_id_ = domain::UserId{};
    local_device_id_ = domain::DeviceId{};
    is_syncing_.store(false);
    simulated_offline_.store(false);
    return cleared_cursors;
}

} // namespace securecloud::client::application::managers
