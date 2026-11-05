#pragma once

#include <string>
#include <string_view>

namespace securecloud::client::domain {

enum class SessionStatus { LoggedOut, Authenticating, Active, Locked, Expired };

[[nodiscard]] std::string_view to_string(SessionStatus status) noexcept;

class SessionState {
  public:
    SessionState() = default;
    SessionState(std::string userId, std::string deviceId, SessionStatus status = SessionStatus::LoggedOut);

    [[nodiscard]] const std::string& userId() const noexcept;
    [[nodiscard]] const std::string& deviceId() const noexcept;
    [[nodiscard]] SessionStatus status() const noexcept;
    [[nodiscard]] bool isAuthenticated() const noexcept;

    void setStatus(SessionStatus newStatus) noexcept;
    void reset() noexcept;

  private:
    std::string userId_;
    std::string deviceId_;
    SessionStatus status_{SessionStatus::LoggedOut};
};

} // namespace securecloud::client::domain
