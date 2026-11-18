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
#include <vector>

namespace securecloud::client::application::managers {

struct RetryQueueEntry {
    domain::ConversationId conversation_id;
    domain::MessageId message_id;
    interfaces::FanOutSubmissionRequest request;
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
                 std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now());

    bool remove(const domain::MessageId& message_id);
    [[nodiscard]] std::size_t pending_count() const;

    using SubmitFn = std::function<ClientResult<std::string>(const interfaces::FanOutSubmissionRequest&)>;
    using ExpireFn = std::function<void(const domain::ConversationId&, const domain::MessageId&)>;

    std::size_t process_due(std::chrono::steady_clock::time_point now, const SubmitFn& submit_fn,
                            const ExpireFn& expire_fn);

  private:
    mutable std::mutex mutex_;
    domain::RetryPolicyConfig config_;
    std::mt19937_64 rng_;
    std::vector<RetryQueueEntry> queue_;
};

} // namespace securecloud::client::application::managers
