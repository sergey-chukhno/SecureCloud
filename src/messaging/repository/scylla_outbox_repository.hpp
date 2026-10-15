#pragma once

#include "messaging/db/scylla_session_interface.hpp"
#include "messaging/repository/outbox_repository_interface.hpp"

#include <memory>
#include <mutex>

namespace securecloud::messaging::repository {

/// ScyllaDB persistence adapter for Transactional Outbox events.
/// Conforms strictly to table:
/// securecloud_messaging.messaging_outbox_events
/// - Partition Key: ((outbox_bucket))
/// - Clustering Key: created_at ASC, event_id ASC
class ScyllaOutboxRepository : public IOutboxRepository {
  public:
    explicit ScyllaOutboxRepository(std::shared_ptr<db::IScyllaSession> session);

    void enqueue_event(const domain::ConversationOutboxEvent& event, const std::string& outbox_bucket = "") override;

    [[nodiscard]] std::vector<OutboxEventRecord> fetch_pending_events(const std::string& outbox_bucket,
                                                                      size_t limit) override;

    void mark_event_published(const std::string& outbox_bucket, std::chrono::system_clock::time_point created_at,
                              const std::string& event_id, std::chrono::system_clock::time_point published_at) override;

  private:
    void init_prepared_statements();

    std::shared_ptr<db::IScyllaSession> session_;
    mutable std::mutex mutex_;

    db::PreparedStatementId prep_enqueue_event_;
    db::PreparedStatementId prep_fetch_events_;
    db::PreparedStatementId prep_mark_published_;
};

} // namespace securecloud::messaging::repository
