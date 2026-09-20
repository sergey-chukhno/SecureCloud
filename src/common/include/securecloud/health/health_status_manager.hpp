#pragma once

#include <atomic>
#include <functional>
#include <mutex>
#include <string>
#include <string_view>

namespace securecloud::common::health {

using ReadinessEvaluator = std::function<bool()>;

class HealthStatusManager {
  public:
    explicit HealthStatusManager(std::string service_name);
    ~HealthStatusManager() = default;

    HealthStatusManager(const HealthStatusManager&) = delete;
    HealthStatusManager& operator=(const HealthStatusManager&) = delete;
    HealthStatusManager(HealthStatusManager&&) = delete;
    HealthStatusManager& operator=(HealthStatusManager&&) = delete;

    [[nodiscard]] const std::string& service_name() const noexcept;

    void set_live(bool live) noexcept;
    [[nodiscard]] bool is_live() const noexcept;

    void set_ready(bool ready) noexcept;
    [[nodiscard]] bool is_ready() const noexcept;

    void set_shutting_down(bool shutting_down) noexcept;
    [[nodiscard]] bool is_shutting_down() const noexcept;

    void set_readiness_evaluator(ReadinessEvaluator evaluator);
    [[nodiscard]] bool evaluate_readiness() const noexcept;

  private:
    std::string service_name_;
    std::atomic<bool> is_live_{false};
    std::atomic<bool> is_ready_{false};
    std::atomic<bool> is_shutting_down_{false};

    mutable std::mutex evaluator_mutex_;
    ReadinessEvaluator readiness_evaluator_{nullptr};
};

} // namespace securecloud::common::health
