#pragma once

#include "auth/domain/audit_event.hpp"
#include "auth/audit/auth_outbox_metrics.hpp"
#include "auth/repository/auth_outbox_repository.hpp"

#include <memory>
#include <pqxx/pqxx>
#include <string>
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

    /// Category B: Publishes an audit event autonomously (standalone transaction or sink).
    /// Invariant: Must be noexcept — publishing an autonomous audit event must never crash
    /// or interrupt a rejection/authentication workflow.
    virtual void publish(const domain::AuditEvent& event) noexcept = 0;

    /// Category A: Enlists audit event staging inside an active PostgreSQL business transaction.
    /// Invariant: Must throw on persistence failure so the enclosing business transaction rolls back
    /// atomically (zero un-audited state mutations).
    virtual void publish_in_tx(const domain::AuditEvent& event, pqxx::transaction_base& tx) {
        (void)tx;
        publish(event);
    }
};

/// Log-sink implementation of IAuditEventPublisher (used for fallback and standalone unit tests).
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

/// Transactional Outbox-backed implementation of IAuditEventPublisher (AUDIT-013).
/// Stages Category A events inside the caller's PostgreSQL transaction and commits Category B
/// events in an autonomous outbox transaction.
class OutboxAuditEventPublisher final : public IAuditEventPublisher {
  public:
    explicit OutboxAuditEventPublisher(std::shared_ptr<repository::IAuthOutboxRepository> outbox_repo,
                                       std::string producer_instance = "auth-1",
                                       std::shared_ptr<IAuditEventSink> fallback_sink = nullptr,
                                       audit::AuthOutboxMetrics* metrics = nullptr);
    ~OutboxAuditEventPublisher() override = default;

    OutboxAuditEventPublisher(const OutboxAuditEventPublisher&) = delete;
    OutboxAuditEventPublisher& operator=(const OutboxAuditEventPublisher&) = delete;
    OutboxAuditEventPublisher(OutboxAuditEventPublisher&&) noexcept = default;
    OutboxAuditEventPublisher& operator=(OutboxAuditEventPublisher&&) noexcept = default;

    void publish(const domain::AuditEvent& event) noexcept override;
    void publish_in_tx(const domain::AuditEvent& event, pqxx::transaction_base& tx) override;

  private:
    std::shared_ptr<repository::IAuthOutboxRepository> outbox_repo_;
    std::string producer_instance_;
    std::shared_ptr<IAuditEventSink> fallback_sink_;
    audit::AuthOutboxMetrics* metrics_;
};

} // namespace securecloud::auth::service
