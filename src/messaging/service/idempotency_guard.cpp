#include "service/idempotency_guard.hpp"

#include <chrono>
#include <stdexcept>

namespace securecloud::messaging::service {

MessageSubmissionIdempotencyGuard::MessageSubmissionIdempotencyGuard(
    std::shared_ptr<repository::IIdempotencyRepository> repo)
    : repo_(std::move(repo)) {
    if (!repo_) {
        throw std::invalid_argument("MessageSubmissionIdempotencyGuard requires non-null IIdempotencyRepository");
    }
}

IdempotencyEvaluationResult
MessageSubmissionIdempotencyGuard::evaluate_submission(const domain::MessageSubmissionCommand& cmd,
                                                       const std::string& request_fingerprint) {
    auto opt_record = repo_->find_submission(cmd.sender_device_id, cmd.client_idempotency_token);
    if (!opt_record.has_value()) {
        return IdempotencyEvaluationResult::proceed_new();
    }

    const auto& record = *opt_record;

    // 1. Check conversation ID consistency
    if (record.conversation_id != cmd.conversation_id) {
        return IdempotencyEvaluationResult::reject_conflict(
            "Idempotency token was previously used for a different conversation: " +
            record.conversation_id.to_string());
    }

    // 2. Check fingerprint consistency (detect conflicting token reuse with altered payload)
    if (!record.request_fingerprint.empty() && record.request_fingerprint != request_fingerprint) {
        return IdempotencyEvaluationResult::reject_conflict(
            "Idempotency token was previously used with different payload content");
    }

    // 3. Check lifecycle status
    switch (record.submission_status) {
    case domain::SubmissionStatus::Committed:
        return IdempotencyEvaluationResult::return_cached(record);

    case domain::SubmissionStatus::Processing:
        return IdempotencyEvaluationResult::retry_wait("Submission with idempotency token is currently in-flight");

    case domain::SubmissionStatus::Failed:
        // Previous submission failed; allow safe retry
        return IdempotencyEvaluationResult::proceed_new();
    }

    return IdempotencyEvaluationResult::proceed_new();
}

void MessageSubmissionIdempotencyGuard::mark_processing(const domain::MessageSubmissionCommand& cmd,
                                                        const std::string& request_fingerprint,
                                                        const domain::MessageId& message_id) {
    domain::IdempotencyRecord record;
    record.sender_device_id = cmd.sender_device_id;
    record.idempotency_key = cmd.client_idempotency_token;
    record.message_id = message_id;
    record.conversation_id = cmd.conversation_id;
    record.message_sequence = 0;
    record.submission_status = domain::SubmissionStatus::Processing;
    record.created_at = std::chrono::system_clock::now();
    record.request_fingerprint = request_fingerprint;

    repo_->save_submission(record);
}

void MessageSubmissionIdempotencyGuard::mark_committed(const domain::MessageSubmissionCommand& cmd,
                                                       const std::string& request_fingerprint,
                                                       const domain::MessageId& message_id, uint64_t message_sequence) {
    domain::IdempotencyRecord record;
    record.sender_device_id = cmd.sender_device_id;
    record.idempotency_key = cmd.client_idempotency_token;
    record.message_id = message_id;
    record.conversation_id = cmd.conversation_id;
    record.message_sequence = message_sequence;
    record.submission_status = domain::SubmissionStatus::Committed;
    record.created_at = std::chrono::system_clock::now();
    record.request_fingerprint = request_fingerprint;

    repo_->save_submission(record);
}

void MessageSubmissionIdempotencyGuard::mark_failed(const domain::DeviceId& sender_device_id,
                                                    const std::string& idempotency_key) {
    auto opt_record = repo_->find_submission(sender_device_id, idempotency_key);
    if (opt_record) {
        opt_record->submission_status = domain::SubmissionStatus::Failed;
        repo_->save_submission(*opt_record);
    }
}

std::optional<domain::IdempotencyRecord>
MessageSubmissionIdempotencyGuard::find_submission(const domain::DeviceId& sender_device_id,
                                                   const std::string& idempotency_key) {
    return repo_->find_submission(sender_device_id, idempotency_key);
}

} // namespace securecloud::messaging::service
