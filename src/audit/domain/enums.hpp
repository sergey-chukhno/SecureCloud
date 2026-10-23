#pragma once

#include <cstdint>
#include <optional>
#include <string_view>

namespace securecloud::audit::domain {

enum class Severity : uint8_t { Info = 1, Warning = 2, Security = 3, Critical = 4 };

[[nodiscard]] std::string_view to_string(Severity severity) noexcept;
[[nodiscard]] std::optional<Severity> severity_from_string(std::string_view sv) noexcept;

enum class ProducerService : uint8_t { Gateway = 1, Auth = 2, Messaging = 3, Files = 4, Audit = 5 };

[[nodiscard]] std::string_view to_string(ProducerService service) noexcept;
[[nodiscard]] std::optional<ProducerService> producer_from_string(std::string_view sv) noexcept;

enum class ActorType : uint8_t { User = 1, Device = 2, Service = 3, System = 4, Unknown = 5 };

[[nodiscard]] std::string_view to_string(ActorType actor_type) noexcept;
[[nodiscard]] std::optional<ActorType> actor_type_from_string(std::string_view sv) noexcept;

enum class TargetType : uint8_t { User = 1, Device = 2, Conversation = 3, File = 4, Service = 5, Unknown = 6 };

[[nodiscard]] std::string_view to_string(TargetType target_type) noexcept;
[[nodiscard]] std::optional<TargetType> target_type_from_string(std::string_view sv) noexcept;

} // namespace securecloud::audit::domain