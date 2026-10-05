#pragma once

#include <atomic>
#include <chrono>
#include <grpcpp/client_context.h>
#include <memory>
#include <string>
#include <string_view>

namespace securecloud::gateway::grpc {

struct CallContextOptions {
    std::chrono::milliseconds timeout{5000};
    std::string request_id;
    std::string client_service{"gateway"};
};

class ClientCallContext {
  public:
    static constexpr const char* k_metadata_request_id = "x-request-id";
    static constexpr const char* k_metadata_client_service = "x-client-service";
    static constexpr std::chrono::milliseconds k_default_timeout{5000};

    ClientCallContext();
    explicit ClientCallContext(std::chrono::milliseconds timeout);
    explicit ClientCallContext(const CallContextOptions& options);
    ClientCallContext(std::string_view request_id, std::chrono::milliseconds timeout);

    ~ClientCallContext() = default;

    ClientCallContext(const ClientCallContext&) = delete;
    ClientCallContext& operator=(const ClientCallContext&) = delete;
    ClientCallContext(ClientCallContext&& other) noexcept;
    ClientCallContext& operator=(ClientCallContext&& other) noexcept;

    [[nodiscard]] ::grpc::ClientContext& raw_context() noexcept;
    [[nodiscard]] const ::grpc::ClientContext& raw_context() const noexcept;

    void cancel() noexcept;
    [[nodiscard]] bool is_cancelled() const noexcept;

    [[nodiscard]] std::chrono::system_clock::time_point deadline() const noexcept;
    [[nodiscard]] std::chrono::milliseconds deadline_remaining() const noexcept;
    [[nodiscard]] bool is_deadline_expired() const noexcept;

    [[nodiscard]] const std::string& request_id() const noexcept;
    [[nodiscard]] const std::string& client_service() const noexcept;

  private:
    void initialize_context(const CallContextOptions& options);

    std::unique_ptr<::grpc::ClientContext> context_;
    std::atomic<bool> cancelled_{false};
    std::chrono::system_clock::time_point deadline_tp_{};
    std::string request_id_;
    std::string client_service_;
};

} // namespace securecloud::gateway::grpc
