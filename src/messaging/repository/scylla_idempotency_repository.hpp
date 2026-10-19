#pragma once

#include "messaging/db/scylla_session_interface.hpp"
#include "messaging/repository/idempotency_repository_interface.hpp"

#include <memory>
#include <mutex>

namespace securecloud::messaging::repository {

/// ScyllaDB persistence adapter for Client Message Submission Idempotency.
/// Conforms to:
/// - securecloud_messaging.message_submission_by_idempotency_key
/// - Partition Key: ((sender_device_id))
/// - Clustering Key: idempotency_key
class ScyllaIdempotencyRepository : public IIdempotencyRepository {
  public:
    explicit ScyllaIdempotencyRepository(std::shared_ptr<db::IScyllaSession> session);

    [[nodiscard]] std::optional<domain::IdempotencyRecord> find_submission(const domain::DeviceId& sender_device_id,
                                                                           const std::string& idempotency_key) override;

    void save_submission(const domain::IdempotencyRecord& record) override;

  private:
    void init_prepared_statements();

    std::shared_ptr<db::IScyllaSession> session_;
    mutable std::mutex mutex_;

    db::PreparedStatementId prep_find_submission_;
    db::PreparedStatementId prep_save_submission_;
};

} // namespace securecloud::messaging::repository
