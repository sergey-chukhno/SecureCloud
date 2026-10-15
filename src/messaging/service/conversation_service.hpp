#pragma once

#include "domain/conversation_entity.hpp"
#include "domain/conversation_participant_entity.hpp"
#include "domain/conversation_types.hpp"
#include "domain/group_metadata_entity.hpp"
#include "domain/outbox_event.hpp"
#include "repository/conversation_repository_interface.hpp"
#include "repository/membership_repository_interface.hpp"
#include "securecloud/messaging/v1/messaging.pb.h"
#include "service/conversation_authorization_service.hpp"

#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace securecloud::messaging::service {

/// Strongly-typed service operation result.
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

/// Specialization for void-returning service operations.
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

/// Detailed aggregated view of a conversation for client retrieval.
struct ConversationDetails {
    domain::ConversationEntity conversation;
    std::optional<domain::GroupMetadataEntity> group_metadata{std::nullopt};
    std::vector<domain::ConversationParticipantEntity> active_participants;
};

/// Core domain orchestration service managing conversation lifecycles,
/// membership mutations, idempotent duplicate requests, and transactional outbox events.
class ConversationService {
  public:
    ConversationService(repository::IConversationRepository& conversation_repo,
                        repository::IMembershipRepository& membership_repo,
                        ConversationAuthorizationService& auth_service);

    /// Creates or returns an existing 1-on-1 direct conversation idempotently.
    [[nodiscard]] ServiceResult<domain::ConversationEntity> create_direct_conversation(const domain::UserId& caller,
                                                                                       const domain::UserId& recipient);

    /// Creates a new group conversation with caller as Admin and initial members.
    [[nodiscard]] ServiceResult<domain::ConversationEntity>
    create_group_conversation(const domain::UserId& caller, std::string_view title,
                              const std::vector<domain::UserId>& initial_participant_user_ids);

    /// Adds a participant to a group conversation or reactivates a previously left member.
    [[nodiscard]] ServiceResult<void> add_participant(const domain::UserId& caller,
                                                      const domain::ConversationId& conv_id,
                                                      const domain::UserId& target_user);

    /// Removes an active participant from a group conversation.
    [[nodiscard]] ServiceResult<void> remove_participant(const domain::UserId& caller,
                                                         const domain::ConversationId& conv_id,
                                                         const domain::UserId& target_user);

    /// Leaves an active group conversation, enforcing admin succession rules.
    [[nodiscard]] ServiceResult<void> leave_conversation(const domain::UserId& caller,
                                                         const domain::ConversationId& conv_id);

    /// Updates the title of an active group conversation.
    [[nodiscard]] ServiceResult<domain::GroupMetadataEntity>
    update_group_metadata(const domain::UserId& caller, const domain::ConversationId& conv_id,
                          std::string_view new_title);

    /// Fetches full conversation details after validating caller's view permission.
    [[nodiscard]] ServiceResult<ConversationDetails> get_conversation(const domain::UserId& caller,
                                                                      const domain::ConversationId& conv_id);

    /// Lists conversations for the caller with pagination.
    [[nodiscard]] ServiceResult<repository::UserConversationsPage>
    list_user_conversations(const domain::UserId& caller, int limit, const std::optional<std::string>& page_token);

    /// Inspects currently buffered outbox events.
    [[nodiscard]] std::vector<domain::ConversationOutboxEvent> get_outbox_events() const;

    /// Clears recorded outbox events (useful after publishing / testing).
    void clear_outbox_events();

  private:
    repository::IConversationRepository& conversation_repo_;
    repository::IMembershipRepository& membership_repo_;
    ConversationAuthorizationService& auth_service_;

    mutable std::mutex outbox_mutex_;
    std::vector<domain::ConversationOutboxEvent> outbox_events_;

    void record_outbox_event(const domain::ConversationId& conv_id, domain::ConversationOutboxEventType type,
                             std::string payload_json);
};

} // namespace securecloud::messaging::service
