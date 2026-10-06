#pragma once

#include "domain/audit_event.hpp"

#include <memory>
#include <string_view>

namespace securecloud::auth::service {

/// Abstract destination sink interface for receiving formatted audit events.
class IAuditEventSink {
  public:
    virtual ~IAuditEventSink() = default;

    /// Emits an audit event record to the sink destination.
    ///
    /// @param event Domain audit event model.
    /// @param json_payload Pre-serialized JSON string representation.
    virtual void emit(const domain::AuditEvent& event, std::string_view json_payload) = 0;
};

/// Default sink implementation outputting structured audit records to standard error / logging stream.
class StandardLogAuditSink final : public IAuditEventSink {
  public:
    ~StandardLogAuditSink() override = default;
    void emit(const domain::AuditEvent& event, std::string_view json_payload) override;
};

/// Abstract publisher interface for recording security audit events.
class IAuditEventPublisher {
  public:
    virtual ~IAuditEventPublisher() = default;

    /// Publishes an audit event.
    /// Invariant: Must be noexcept — publishing an audit event must never crash or interrupt
    /// the primary authentication workflow.
    virtual void publish(const domain::AuditEvent& event) noexcept = 0;
};

/// Production implementation of IAuditEventPublisher.
/// Serializes events into structured JSON, validates zero-leakage invariants,
/// and delegates emission to the configured IAuditEventSink.
class AuditEventPublisher final : public IAuditEventPublisher {
  public:
    explicit AuditEventPublisher(std::shared_ptr<IAuditEventSink> sink = nullptr);
    ~AuditEventPublisher() override = default;

    AuditEventPublisher(const AuditEventPublisher&) = delete;
    AuditEventPublisher& operator=(const AuditEventPublisher&) = delete;
    AuditEventPublisher(AuditEventPublisher&&) noexcept = default;
    AuditEventPublisher& operator=(AuditEventPublisher&&) noexcept = default;

    void publish(const domain::AuditEvent& event) noexcept override;

    [[nodiscard]] std::shared_ptr<IAuditEventSink> sink() const noexcept { return sink_; }

  private:
    std::shared_ptr<IAuditEventSink> sink_;
};

} // namespace securecloud::auth::service
