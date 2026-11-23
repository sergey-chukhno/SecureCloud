#pragma once

#include "application/client_error.hpp"
#include "application/interfaces/i_local_store.hpp"
#include "application/interfaces/i_secure_storage.hpp"
#include "domain/conversation_id.hpp"
#include "domain/message_id.hpp"
#include "domain/user_id.hpp"

#include <cstddef>

namespace securecloud::client::application::managers {

class EmergencyManager {
  public:
    EmergencyManager(interfaces::ILocalStore& local_store, interfaces::ISecureStorage& secure_storage);
    ~EmergencyManager() = default;

    EmergencyManager(const EmergencyManager&) = delete;
    EmergencyManager& operator=(const EmergencyManager&) = delete;

    ClientResult<void> trigger_emergency_wipe();
    [[nodiscard]] bool is_wiped() const noexcept { return is_wiped_; }

    ClientResult<void> acknowledge_emergency_message(const domain::ConversationId& conversation_id,
                                                     const domain::MessageId& message_id,
                                                     const domain::UserId& acknowledger_user_id);

    [[nodiscard]] size_t unacknowledged_emergency_count(const domain::ConversationId& conversation_id);

  private:
    interfaces::ILocalStore& local_store_;
    interfaces::ISecureStorage& secure_storage_;
    bool is_wiped_{false};
};

} // namespace securecloud::client::application::managers
