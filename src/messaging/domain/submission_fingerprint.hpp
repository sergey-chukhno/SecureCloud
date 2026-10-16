#pragma once

#include "domain/submission_types.hpp"

#include <string>

namespace securecloud::messaging::domain {

/**
 * @brief Computes a deterministic canonical SHA-256 payload fingerprint (64 lowercase hex characters)
 * for a message submission command.
 *
 * Used for idempotency conflict resolution:
 * - Matching token + identical fingerprint => identical retry (replay original response)
 * - Matching token + different fingerprint => conflicting token reuse (reject with 409)
 *
 * Canonical input format:
 *   conversation_id | sender_device_id | priority_str | sorted_targets
 * where targets are sorted canonically by recipient_device_id (and recipient_user_id) and formatted as:
 *   recipient_device_id : sha256_hex(ciphertext_blob)
 */
[[nodiscard]] std::string calculate_submission_fingerprint(const MessageSubmissionCommand& cmd);

} // namespace securecloud::messaging::domain
