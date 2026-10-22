#pragma once

#include "domain/conversation_types.hpp"
#include "domain/delivery_types.hpp"
#include "domain/message_types.hpp"

#include <chrono>

namespace securecloud::messaging::delivery {

/// Abstract port representing an active delivery channel to a recipient client device.
/// Decouples the messaging delivery engine from specific transport protocols
/// (gRPC streaming, WebSockets, in-memory test channels).
class IDeviceDeliveryChannel {
  public:
    virtual ~IDeviceDeliveryChannel() = default;

    /// Unique identifier of the device connected to this channel.
    [[nodiscard]] virtual domain::DeviceId device_id() const noexcept = 0;

    /// User owning the connected device.
    [[nodiscard]] virtual domain::UserId user_id() const noexcept = 0;

    /// Returns true if the underlying transport connection is currently healthy and active.
    [[nodiscard]] virtual bool is_active() const noexcept = 0;

    /// Dispatches an opaque ciphertext envelope to the device within the specified timeout.
    virtual domain::DeliveryAttemptResult send_envelope(const domain::DeliveryTask& task,
                                                        std::chrono::milliseconds timeout) = 0;
};

} // namespace securecloud::messaging::delivery
