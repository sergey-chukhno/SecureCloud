#include "client_call_context.hpp"

#include <algorithm>
#include <utility>

namespace securecloud::gateway::grpc {

ClientCallContext::ClientCallContext() {
    initialize_context(CallContextOptions{});
}

ClientCallContext::ClientCallContext(std::chrono::milliseconds timeout) {
    CallContextOptions options;
    options.timeout = timeout;
    initialize_context(options);
}

ClientCallContext::ClientCallContext(const CallContextOptions& options) {
    initialize_context(options);
}

ClientCallContext::ClientCallContext(std::string_view request_id, std::chrono::milliseconds timeout) {
    CallContextOptions options;
    options.request_id = std::string(request_id);
    options.timeout = timeout;
    initialize_context(options);
}

ClientCallContext::ClientCallContext(ClientCallContext&& other) noexcept
    : context_(std::move(other.context_)), cancelled_(other.cancelled_.load(std::memory_order_relaxed)),
      deadline_tp_(other.deadline_tp_), request_id_(std::move(other.request_id_)),
      client_service_(std::move(other.client_service_)) {}

ClientCallContext& ClientCallContext::operator=(ClientCallContext&& other) noexcept {
    if (this != &other) {
        context_ = std::move(other.context_);
        cancelled_.store(other.cancelled_.load(std::memory_order_relaxed), std::memory_order_relaxed);
        deadline_tp_ = other.deadline_tp_;
        request_id_ = std::move(other.request_id_);
        client_service_ = std::move(other.client_service_);
    }
    return *this;
}

void ClientCallContext::initialize_context(const CallContextOptions& options) {
    context_ = std::make_unique<::grpc::ClientContext>();
    deadline_tp_ = std::chrono::system_clock::now() + options.timeout;
    context_->set_deadline(deadline_tp_);
    request_id_ = options.request_id;
    client_service_ = options.client_service;

    if (!request_id_.empty()) {
        context_->AddMetadata(k_metadata_request_id, request_id_);
    }
    if (!client_service_.empty()) {
        context_->AddMetadata(k_metadata_client_service, client_service_);
    }
}

::grpc::ClientContext& ClientCallContext::raw_context() noexcept {
    return *context_;
}

const ::grpc::ClientContext& ClientCallContext::raw_context() const noexcept {
    return *context_;
}

void ClientCallContext::cancel() noexcept {
    bool expected = false;
    if (cancelled_.compare_exchange_strong(expected, true, std::memory_order_acq_rel)) {
        if (context_) {
            context_->TryCancel();
        }
    }
}

bool ClientCallContext::is_cancelled() const noexcept {
    return cancelled_.load(std::memory_order_acquire);
}

std::chrono::system_clock::time_point ClientCallContext::deadline() const noexcept {
    return deadline_tp_;
}

std::chrono::milliseconds ClientCallContext::deadline_remaining() const noexcept {
    const auto now = std::chrono::system_clock::now();
    if (now >= deadline_tp_) {
        return std::chrono::milliseconds::zero();
    }
    return std::chrono::duration_cast<std::chrono::milliseconds>(deadline_tp_ - now);
}

bool ClientCallContext::is_deadline_expired() const noexcept {
    return std::chrono::system_clock::now() >= deadline_tp_;
}

const std::string& ClientCallContext::request_id() const noexcept {
    return request_id_;
}

const std::string& ClientCallContext::client_service() const noexcept {
    return client_service_;
}

} // namespace securecloud::gateway::grpc
