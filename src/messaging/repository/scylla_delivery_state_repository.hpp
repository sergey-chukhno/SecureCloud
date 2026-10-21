#pragma once

#include "messaging/db/scylla_session_interface.hpp"
#include "messaging/repository/delivery_state_repository_interface.hpp"

#include <memory>
#include <mutex>

namespace securecloud::messaging::repository {

/// ScyllaDB persistence adapter for per-device delivery queues and message delivery acks.
/// Conforms to:
/// - securecloud_messaging.pending_deliveries_by_device
/// - securecloud_messaging.delivery_state_by_message
class ScyllaDeliveryStateRepository : public IDeliveryStateRepository {
  public:
    explicit ScyllaDeliveryStateRepository(std::shared_ptr<db::IScyllaSession> session);

    void save_pending_deliveries(const std::vector<domain::DeviceDeliveryRecord>& records) override;

    [[nodiscard]] std::vector<domain::DeviceDeliveryRecord> fetch_pending_for_device(const domain::DeviceId& device_id,
                                                                                     const std::string& delivery_bucket,
                                                                                     size_t limit) override;

    void update_device_delivery_status(const domain::DeviceId& device_id, const std::string& delivery_bucket,
                                       const std::chrono::system_clock::time_point& accepted_at,
                                       const domain::MessageId& message_id, domain::DeliveryState state,
                                       int32_t attempt_count,
                                       std::optional<std::chrono::system_clock::time_point> next_retry) override;

    void save_recipient_delivery_states(const std::vector<domain::RecipientDeliveryState>& states) override;

    void record_delivery_ack(const domain::MessageId& message_id, const domain::DeviceId& recipient_device_id,
                             const std::chrono::system_clock::time_point& delivered_at) override;

    void record_read_ack(const domain::MessageId& message_id, const domain::DeviceId& recipient_device_id,
                         const std::chrono::system_clock::time_point& read_at) override;

    [[nodiscard]] std::vector<domain::RecipientDeliveryState>
    get_delivery_states_for_message(const domain::MessageId& message_id) override;

    bool update_delivery_state_monotonic(const domain::MessageId& message_id,
                                         const domain::DeviceId& recipient_device_id, domain::DeliveryState new_state,
                                         const std::chrono::system_clock::time_point& updated_at) override;

    [[nodiscard]] std::optional<domain::MessageDeliverySummary>
    get_message_delivery_summary(const domain::MessageId& message_id) override;

  private:
    void init_prepared_statements();

    std::shared_ptr<db::IScyllaSession> session_;
    mutable std::mutex mutex_;

    db::PreparedStatementId prep_insert_pending_;
    db::PreparedStatementId prep_fetch_pending_;
    db::PreparedStatementId prep_update_pending_;
    db::PreparedStatementId prep_insert_recipient_state_;
    db::PreparedStatementId prep_delivery_ack_;
    db::PreparedStatementId prep_read_ack_;
    db::PreparedStatementId prep_get_message_states_;
    db::PreparedStatementId prep_update_delivery_state_;
    db::PreparedStatementId prep_get_single_device_state_;
};

} // namespace securecloud::messaging::repository
