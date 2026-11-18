#include "application/managers/sync_manager.hpp"

#include "application/managers/messaging_manager.hpp"

namespace securecloud::client::application::managers {

SyncManager::SyncManager(interfaces::IGatewayClient& gateway, const ClientConfig& config)
    : gateway_(gateway), config_(config) {}

void SyncManager::set_messaging_manager(MessagingManager* messaging_manager) noexcept {
    messaging_manager_ = messaging_manager;
}

ClientResult<void> SyncManager::start_sync() {
    is_syncing_.store(true);
    return ClientResult<void>::ok();
}

ClientResult<void> SyncManager::stop_sync() {
    is_syncing_.store(false);
    return ClientResult<void>::ok();
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
    const auto it = conversation_cursors_.find(conversation_id);
    return it != conversation_cursors_.end() ? it->second : 0;
}

ClientResult<std::size_t> SyncManager::poll_realtime_updates(const domain::DeviceId& local_device_id) {
    if (!messaging_manager_ || local_device_id.empty()) {
        return ClientResult<std::size_t>::ok(0);
    }

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
            if (page.latest_sequence > since_seq) {
                conversation_cursors_[cid] = page.latest_sequence;
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

} // namespace securecloud::client::application::managers
