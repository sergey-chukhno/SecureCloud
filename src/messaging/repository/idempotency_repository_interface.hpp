#pragma once

#include "domain/conversation_types.hpp"
#include "domain/idempotency_types.hpp"
#include "domain/message_types.hpp"

#include <optional>
#include <string>

namespace securecloud::messaging::repository {

/// Abstract repository contract for Client Message Submission Idempotency Deduplication.
/// Conforms to:
/// - securecloud_messaging.message_submission_by_idempotency_key
/// - Partition Key: ((sender_device_id))
/// - Clustering Key: idempotency_key
class IIdempotencyRepository {
  public:
    virtual ~IIdempotencyRepository() = default;

    /// Finds an existing submission record by sender device and idempotency key.
    [[nodiscard]] virtual std::optional<domain::IdempotencyRecord>
    find_submission(const domain::DeviceId& sender_device_id, const std::string& idempotency_key) = 0;

    /// Stores a submission deduplication record.
    virtual void save_submission(const domain::IdempotencyRecord& record) = 0;
};

} // namespace securecloud::messaging::repository
