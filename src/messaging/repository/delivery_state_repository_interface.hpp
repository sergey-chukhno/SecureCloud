#pragma once

#include "domain/conversation_types.hpp"
#include "domain/delivery_types.hpp"
#include "domain/message_types.hpp"

#include <chrono>
#include <optional>
#include <string>
#include <vector>

namespace securecloud::messaging::repository {

/// Abstract repository contract for Per-Device Active Delivery Queues and Recipient Ack State.
/// Conforms to ScyllaDB query patterns (ADR-007, 03-messaging-data-model.md):
/// - securecloud_messaging.pending_deliveries_by_device
/// - securecloud_messaging.delivery_state_by_message
class IDeliveryStateRepository {
  public:
    virtual ~IDeliveryStateRepository() = default;

    /// Batch or single enqueue of pending delivery items into pending_deliveries_by_device.
    virtual void save_pending_deliveries(const std::vector<domain::DeviceDeliveryRecord>& records) = 0;

    /// Fetches undelivered / pending records for a specific device in a given bucket, ordered by accepted_at ASC.
    [[nodiscard]] virtual std::vector<domain::DeviceDeliveryRecord>
    fetch_pending_for_device(const domain::DeviceId& device_id, const std::string& delivery_bucket, size_t limit) = 0;

    /// Updates status, attempt count, and next retry timestamp of a pending delivery item.
    virtual void update_device_delivery_status(const domain::DeviceId& device_id, const std::string& delivery_bucket,
                                               const std::chrono::system_clock::time_point& accepted_at,
                                               const domain::MessageId& message_id, domain::DeliveryState state,
                                               int32_t attempt_count,
                                               std::optional<std::chrono::system_clock::time_point> next_retry) = 0;

    /// Inserts fan-out tracking rows into delivery_state_by_message.
    virtual void save_recipient_delivery_states(const std::vector<domain::RecipientDeliveryState>& states) = 0;

    /// Records a device-level delivery acknowledgment (delivered_at, state = DELIVERED).
    virtual void record_delivery_ack(const domain::MessageId& message_id, const domain::DeviceId& recipient_device_id,
                                     const std::chrono::system_clock::time_point& delivered_at) = 0;

    /// Records a user/device read receipt (read_at, state = READ).
    virtual void record_read_ack(const domain::MessageId& message_id, const domain::DeviceId& recipient_device_id,
                                 const std::chrono::system_clock::time_point& read_at) = 0;

    /// Retrieves all recipient delivery states for a given message.
    [[nodiscard]] virtual std::vector<domain::RecipientDeliveryState>
    get_delivery_states_for_message(const domain::MessageId& message_id) = 0;
};

} // namespace securecloud::messaging::repository
