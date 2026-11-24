#pragma once

#include "domain/conversation_entity.hpp"
#include "domain/conversation_participant_entity.hpp"
#include "domain/conversation_types.hpp"
#include "domain/group_metadata_entity.hpp"
#include "domain/outbox_event.hpp"
#include "messaging/repository/messaging_audit_outbox_repository_interface.hpp"
#include "repository/conversation_repository_interface.hpp"
#include "repository/membership_repository_interface.hpp"
#include "securecloud/messaging/v1/messaging.pb.h"
#include "service/conversation_authorization_service.hpp"

#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace securecloud::messaging::service {

template <typename T> struct ServiceResult {
    bool success{false};
    T value{};
    v1::MessagingErrorCode error_code{v1::MESSAGING_ERROR_CODE_UNSPECIFIED};
    std::string error_message{};

    [[nodiscard]] static ServiceResult ok(T val) {
        return ServiceResult{true, std::move(val), v1::MESSAGING_ERROR_CODE_UNSPECIFIED, ""};
    }

    [[nodiscard]] static ServiceResult fail(v1::MessagingErrorCode code, std::string msg) {
        return ServiceResult{false, T{}, code, std::move(msg)};
    }

    [[nodiscard]] explicit operator bool() const noexcept { return success; }
};

template <> struct ServiceResult<void> {
    bool success{false};
    v1::MessagingErrorCode error_code{v1::MESSAGING_ERROR_CODE_UNSPECIFIED};
    std::string error_message{};

    [[nodiscard]] static ServiceResult ok() noexcept {
        return ServiceResult{true, v1::MESSAGING_ERROR_CODE_UNSPECIFIED, ""};
    }

    [[nodiscard]] static ServiceResult fail(v1::MessagingErrorCode code, std::string msg) {
        return ServiceResult{false, code, std::move(msg)};
    }

    [[nodiscard]] explicit operator bool() const noexcept { return success; }
};

struct ConversationDetails {
    domain::ConversationEntity conversation;
    std::optional<domain::GroupMetadataEntity> group_metadata{std::nullopt};
    std::vector<domain::ConversationParticipantEntity> active_participants;
};

class ConversationService {
  public:
    ConversationService(repository::IConversationRepository& conversation_repo,
                        repository::IMembershipRepository& membership_repo,
                        ConversationAuthorizationService& auth_service,
                        std::shared_ptr<repository::IMessagingAuditOutboxRepository> audit_repo = nullptr);

    [[nodiscard]] ServiceResult<domain::ConversationEntity>
    create_direct_conversation(const domain::UserId& caller, const domain::UserId& recipient,
                               std::string_view correlation_id = {});

    [[nodiscard]] ServiceResult<domain::ConversationEntity>
    create_group_conversation(const domain::UserId& caller, std::string_view title,
                              const std::vector<domain::UserId>& initial_participant_user_ids,
                              std::string_view correlation_id = {});

    [[nodiscard]] ServiceResult<void> add_participant(const domain::UserId& caller,
                                                      const domain::ConversationId& conv_id,
                                                      const domain::UserId& target_user,
                                                      std::string_view correlation_id = {});

    [[nodiscard]] ServiceResult<void> remove_participant(const domain::UserId& caller,
                                                         const domain::ConversationId& conv_id,
                                                         const domain::UserId& target_user,
                                                         std::string_view correlation_id = {});

    [[nodiscard]] ServiceResult<void> leave_conversation(const domain::UserId& caller,
                                                         const domain::ConversationId& conv_id,
                                                         std::string_view correlation_id = {});

    [[nodiscard]] ServiceResult<domain::GroupMetadataEntity>
    update_group_metadata(const domain::UserId& caller, const domain::ConversationId& conv_id,
                          std::string_view new_title, std::string_view correlation_id = {});

    [[nodiscard]] ServiceResult<ConversationDetails> get_conversation(const domain::UserId& caller,
                                                                      const domain::ConversationId& conv_id);

    [[nodiscard]] ServiceResult<repository::UserConversationsPage>
    list_user_conversations(const domain::UserId& caller, int limit, const std::optional<std::string>& page_token);

    [[nodiscard]] std::vector<domain::ConversationOutboxEvent> get_outbox_events() const;

    void clear_outbox_events();

    [[nodiscard]] bool shares_mutual_conversation(const domain::UserId& caller, const domain::UserId& target) const {
        return auth_service_.shares_mutual_conversation(caller, target);
    }

  private:
    repository::IConversationRepository& conversation_repo_;
    repository::IMembershipRepository& membership_repo_;
    ConversationAuthorizationService& auth_service_;
    std::shared_ptr<repository::IMessagingAuditOutboxRepository> audit_repo_;

    mutable std::mutex outbox_mutex_;
    std::vector<domain::ConversationOutboxEvent> outbox_events_;

    void record_outbox_event(const domain::ConversationId& conv_id, domain::ConversationOutboxEventType type,
                             std::string payload_json);
};

} // namespace securecloud::messaging::service
