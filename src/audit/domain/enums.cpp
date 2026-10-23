#include "enums.hpp"

namespace securecloud::audit::domain {

std::string_view to_string(Severity severity) noexcept {
    switch (severity) {
    case Severity::Info:
        return "INFO";
    case Severity::Warning:
        return "WARNING";
    case Severity::Security:
        return "SECURITY";
    case Severity::Critical:
        return "CRITICAL";
    }
    return "UNKNOWN";
}

std::optional<Severity> severity_from_string(std::string_view sv) noexcept {
    if (sv == "INFO" || sv == "info" || sv == "1")
        return Severity::Info;
    if (sv == "WARNING" || sv == "warning" || sv == "2")
        return Severity::Warning;
    if (sv == "SECURITY" || sv == "security" || sv == "3")
        return Severity::Security;
    if (sv == "CRITICAL" || sv == "critical" || sv == "4")
        return Severity::Critical;
    return std::nullopt;
}

std::string_view to_string(ProducerService service) noexcept {
    switch (service) {
    case ProducerService::Gateway:
        return "gateway";
    case ProducerService::Auth:
        return "auth";
    case ProducerService::Messaging:
        return "messaging";
    case ProducerService::Files:
        return "files";
    case ProducerService::Audit:
        return "audit";
    }
    return "unknown";
}

std::optional<ProducerService> producer_from_string(std::string_view sv) noexcept {
    if (sv == "gateway" || sv == "GATEWAY" || sv == "1")
        return ProducerService::Gateway;
    if (sv == "auth" || sv == "AUTH" || sv == "2")
        return ProducerService::Auth;
    if (sv == "messaging" || sv == "MESSAGING" || sv == "3")
        return ProducerService::Messaging;
    if (sv == "files" || sv == "FILES" || sv == "4")
        return ProducerService::Files;
    if (sv == "audit" || sv == "AUDIT" || sv == "5")
        return ProducerService::Audit;
    return std::nullopt;
}

std::string_view to_string(ActorType actor_type) noexcept {
    switch (actor_type) {
    case ActorType::User:
        return "USER";
    case ActorType::Device:
        return "DEVICE";
    case ActorType::Service:
        return "SERVICE";
    case ActorType::System:
        return "SYSTEM";
    case ActorType::Unknown:
        return "UNKNOWN";
    }
    return "UNKNOWN";
}

std::optional<ActorType> actor_type_from_string(std::string_view sv) noexcept {
    if (sv == "USER" || sv == "user" || sv == "1")
        return ActorType::User;
    if (sv == "DEVICE" || sv == "device" || sv == "2")
        return ActorType::Device;
    if (sv == "SERVICE" || sv == "service" || sv == "3")
        return ActorType::Service;
    if (sv == "SYSTEM" || sv == "system" || sv == "4")
        return ActorType::System;
    if (sv == "UNKNOWN" || sv == "unknown" || sv == "5")
        return ActorType::Unknown;
    return std::nullopt;
}

std::string_view to_string(TargetType target_type) noexcept {
    switch (target_type) {
    case TargetType::User:
        return "USER";
    case TargetType::Device:
        return "DEVICE";
    case TargetType::Conversation:
        return "CONVERSATION";
    case TargetType::File:
        return "FILE";
    case TargetType::Service:
        return "SERVICE";
    case TargetType::Unknown:
        return "UNKNOWN";
    }
    return "UNKNOWN";
}

std::optional<TargetType> target_type_from_string(std::string_view sv) noexcept {
    if (sv == "USER" || sv == "user" || sv == "1")
        return TargetType::User;
    if (sv == "DEVICE" || sv == "device" || sv == "2")
        return TargetType::Device;
    if (sv == "CONVERSATION" || sv == "conversation" || sv == "3")
        return TargetType::Conversation;
    if (sv == "FILE" || sv == "file" || sv == "4")
        return TargetType::File;
    if (sv == "SERVICE" || sv == "service" || sv == "5")
        return TargetType::Service;
    if (sv == "UNKNOWN" || sv == "unknown" || sv == "6")
        return TargetType::Unknown;
    return std::nullopt;
}

} // namespace securecloud::audit::domain