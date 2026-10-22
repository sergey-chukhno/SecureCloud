#pragma once

#include "domain/idempotency_types.hpp"
#include "domain/submission_types.hpp"
#include "messaging/repository/idempotency_repository_interface.hpp"
#include "securecloud/messaging/v1/messaging.pb.h"

#include <memory>
#include <optional>
#include <string>
#include <string_view>

namespace securecloud::messaging::service {

/**
 * @brief Action determined by evaluating client submission idempotency.
 */
enum class IdempotencyAction {
    ProceedNew,     ///< First time seeing this idempotency key. Safe to process and persist.
    ReturnCached,   ///< Identical repeat submission already committed. Return previous response.
    RejectConflict, ///< Conflicting reuse of idempotency token (mismatched conversation or fingerprint).
    RetryWait,      ///< Previous identical submission is still PROCESSING in-flight.
};

[[nodiscard]] inline std::string_view to_string(IdempotencyAction action) noexcept {
    switch (action) {
    case IdempotencyAction::ProceedNew:
        return "ProceedNew";
    case IdempotencyAction::ReturnCached:
        return "ReturnCached";
    case IdempotencyAction::RejectConflict:
        return "RejectConflict";
    case IdempotencyAction::RetryWait:
        return "RetryWait";
    }
    return "Unknown";
}

/**
 * @brief Structured result of idempotency evaluation.
 */
struct IdempotencyEvaluationResult {
    IdempotencyAction action{IdempotencyAction::ProceedNew};
    std::optional<domain::IdempotencyRecord> cached_record{std::nullopt};
    std::string error_message;
    v1::MessagingErrorCode error_code{v1::MESSAGING_ERROR_CODE_UNSPECIFIED};

    [[nodiscard]] static IdempotencyEvaluationResult proceed_new() noexcept {
        return {IdempotencyAction::ProceedNew, std::nullopt, "", v1::MESSAGING_ERROR_CODE_UNSPECIFIED};
    }

    [[nodiscard]] static IdempotencyEvaluationResult return_cached(domain::IdempotencyRecord record) noexcept {
        return {IdempotencyAction::ReturnCached, std::move(record), "", v1::MESSAGING_ERROR_CODE_UNSPECIFIED};
    }

    [[nodiscard]] static IdempotencyEvaluationResult
    reject_conflict(std::string message, v1::MessagingErrorCode code = v1::MESSAGING_ERROR_CODE_IDEMPOTENCY_CONFLICT) {
        return {IdempotencyAction::RejectConflict, std::nullopt, std::move(message), code};
    }

    [[nodiscard]] static IdempotencyEvaluationResult retry_wait(std::string message) {
        return {IdempotencyAction::RetryWait, std::nullopt, std::move(message), v1::MESSAGING_ERROR_CODE_UNSPECIFIED};
    }
};

/**
 * @brief Authoritative idempotency enforcement and conflict resolution engine.
 */
class MessageSubmissionIdempotencyGuard {
  public:
    explicit MessageSubmissionIdempotencyGuard(std::shared_ptr<repository::IIdempotencyRepository> repo);

    /**
     * @brief Evaluates an incoming message submission command against durable idempotency records.
     *
     * @param cmd Submission command containing sender_device_id and client_idempotency_token.
     * @param request_fingerprint Cryptographic SHA-256 fingerprint of the request.
     * @return IdempotencyEvaluationResult dictating the execution path.
     */
    [[nodiscard]] IdempotencyEvaluationResult evaluate_submission(const domain::MessageSubmissionCommand& cmd,
                                                                  const std::string& request_fingerprint);

    /**
     * @brief Marks a submission as PROCESSING with an allocated message_id and fingerprint.
     */
    void mark_processing(const domain::MessageSubmissionCommand& cmd, const std::string& request_fingerprint,
                         const domain::MessageId& message_id);

    /**
     * @brief Marks a submission as COMMITTED with allocated message_id, sequence number, and fingerprint.
     */
    void mark_committed(const domain::MessageSubmissionCommand& cmd, const std::string& request_fingerprint,
                        const domain::MessageId& message_id, uint64_t message_sequence);

    /**
     * @brief Marks a submission as FAILED so that clients can potentially retry.
     */
    void mark_failed(const domain::DeviceId& sender_device_id, const std::string& idempotency_key);

    /**
     * @brief Queries an existing idempotency record, if present.
     */
    [[nodiscard]] std::optional<domain::IdempotencyRecord> find_submission(const domain::DeviceId& sender_device_id,
                                                                           const std::string& idempotency_key);

  private:
    std::shared_ptr<repository::IIdempotencyRepository> repo_;
};

} // namespace securecloud::messaging::service
