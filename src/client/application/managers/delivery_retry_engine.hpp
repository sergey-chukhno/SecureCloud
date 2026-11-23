#pragma once

#include "application/interfaces/i_gateway_client.hpp"
#include "domain/conversation_id.hpp"
#include "domain/message_id.hpp"
#include "domain/realtime_events.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <mutex>
#include <random>
#include <string>
#include <string_view>
#include <vector>

namespace securecloud::client::application::managers {

struct RetryQueueEntry {
    domain::ConversationId conversation_id;
    domain::MessageId message_id;
    interfaces::FanOutSubmissionRequest request;
    int32_t priority{0};
    std::string outbox_id;
    uint32_t attempt_count{0};
    std::chrono::steady_clock::time_point enqueued_at{};
    std::chrono::steady_clock::time_point next_retry_at{};
    std::chrono::steady_clock::time_point expires_at{};
};

class DeliveryRetryEngine {
  public:
    explicit DeliveryRetryEngine(domain::RetryPolicyConfig config = {});

    void set_config(const domain::RetryPolicyConfig& config);
    [[nodiscard]] domain::RetryPolicyConfig config() const;

    [[nodiscard]] std::chrono::milliseconds compute_backoff(uint32_t attempt);

    void enqueue(domain::ConversationId conversation_id, domain::MessageId message_id,
                 interfaces::FanOutSubmissionRequest request,
                 std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now(),
                 std::string outbox_id = "");

    void hydrate_entry(RetryQueueEntry entry);

    bool remove(const domain::MessageId& message_id);
    bool remove_by_outbox_id(std::string_view outbox_id);
    std::size_t clear();
    [[nodiscard]] std::size_t pending_count() const;

    using SubmitFn = std::function<ClientResult<std::string>(const interfaces::FanOutSubmissionRequest&)>;
    using ExpireFn = std::function<void(const domain::ConversationId&, const domain::MessageId&)>;
    using UpdateFn = std::function<void(const RetryQueueEntry&, const ClientError&)>;

    std::size_t process_due(std::chrono::steady_clock::time_point now, const SubmitFn& submit_fn,
                            const ExpireFn& expire_fn, const UpdateFn& update_fn = {});

  private:
    mutable std::mutex mutex_;
    domain::RetryPolicyConfig config_;
    std::mt19937_64 rng_;
    std::vector<RetryQueueEntry> queue_;
};

} // namespace securecloud::client::application::managers
