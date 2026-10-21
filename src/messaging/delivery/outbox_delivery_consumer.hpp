#pragma once

#include "delivery/bounded_delivery_scheduler.hpp"
#include "delivery/device_connection_registry_interface.hpp"
#include "repository/delivery_state_repository_interface.hpp"
#include "repository/outbox_repository_interface.hpp"

#include <chrono>
#include <memory>
#include <string>

namespace securecloud::messaging::delivery {

/// Outbox Delivery Consumer that reads Transactional Outbox 'MessageSent' events,
/// resolves encrypted per-device envelopes from IDeliveryStateRepository, filters
/// online recipient devices via IDeviceConnectionRegistry, and enqueues delivery tasks
/// into BoundedDeliveryScheduler.
///
/// Implements drop-to-durable backpressure: if the in-memory scheduler queue is full,
/// tasks are safely dropped from RAM because durable ScyllaDB records already exist
/// and will be dispatched by the Durable Recovery Engine (T06).
class OutboxDeliveryConsumer {
  public:
    OutboxDeliveryConsumer(std::shared_ptr<repository::IOutboxRepository> outbox_repo,
                           std::shared_ptr<repository::IDeliveryStateRepository> delivery_repo,
                           std::shared_ptr<IDeviceConnectionRegistry> connection_registry,
                           std::shared_ptr<BoundedDeliveryScheduler> scheduler);

    ~OutboxDeliveryConsumer() = default;

    OutboxDeliveryConsumer(const OutboxDeliveryConsumer&) = delete;
    OutboxDeliveryConsumer& operator=(const OutboxDeliveryConsumer&) = delete;
    OutboxDeliveryConsumer(OutboxDeliveryConsumer&&) = delete;
    OutboxDeliveryConsumer& operator=(OutboxDeliveryConsumer&&) = delete;

    /// Polls pending outbox events for the given bucket up to limit, dispatches tasks
    /// for online recipients to the scheduler, and marks processed outbox events as published.
    /// Returns the number of outbox events processed.
    size_t poll_and_dispatch(const std::string& outbox_bucket, size_t limit);

  private:
    std::shared_ptr<repository::IOutboxRepository> outbox_repo_;
    std::shared_ptr<repository::IDeliveryStateRepository> delivery_repo_;
    std::shared_ptr<IDeviceConnectionRegistry> connection_registry_;
    std::shared_ptr<BoundedDeliveryScheduler> scheduler_;
};

} // namespace securecloud::messaging::delivery
