#pragma once

#include <functional>
#include <iosfwd>
#include <string>
#include <string_view>

namespace securecloud::client::domain {

class DeviceId {
  public:
    DeviceId() = default;
    explicit DeviceId(std::string value);

    [[nodiscard]] const std::string& value() const noexcept { return value_; }
    [[nodiscard]] std::string_view str() const noexcept { return value_; }
    [[nodiscard]] bool empty() const noexcept { return value_.empty(); }

    bool operator==(const DeviceId& other) const noexcept { return value_ == other.value_; }
    bool operator!=(const DeviceId& other) const noexcept { return value_ != other.value_; }
    bool operator<(const DeviceId& other) const noexcept { return value_ < other.value_; }

  private:
    std::string value_;
};

std::ostream& operator<<(std::ostream& os, const DeviceId& id);

} // namespace securecloud::client::domain

template <> struct std::hash<securecloud::client::domain::DeviceId> {
    std::size_t operator()(const securecloud::client::domain::DeviceId& id) const noexcept {
        return std::hash<std::string>{}(id.value());
    }
};
