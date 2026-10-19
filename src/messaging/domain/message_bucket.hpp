#pragma once

#include <chrono>
#include <compare>
#include <optional>
#include <string>
#include <string_view>

namespace securecloud::messaging::domain {

/// Time-bucket value object formatting and validating monthly UTC bucket strings (YYYYMM).
/// Conforms to ADR-007 and 03-messaging-data-model.md to bound ScyllaDB partition sizes.
class MessageBucket {
  public:
    MessageBucket() = default;

    /// Constructs a bucket from explicit year and month (1-12).
    /// Throws std::invalid_argument if year < 1970 or month not in [1, 12].
    static MessageBucket from_year_month(int year, int month);

    /// Computes UTC monthly bucket (YYYYMM) from a system clock time_point.
    [[nodiscard]] static MessageBucket from_time_point(std::chrono::system_clock::time_point tp);

    /// Parses and validates a 6-character YYYYMM string.
    [[nodiscard]] static std::optional<MessageBucket> from_string(std::string_view sv) noexcept;

    /// Current bucket string (e.g. "202610").
    [[nodiscard]] const std::string& value() const noexcept { return bucket_; }
    [[nodiscard]] const std::string& to_string() const noexcept { return bucket_; }
    [[nodiscard]] bool empty() const noexcept { return bucket_.empty(); }

    /// Extracted numeric year and month.
    [[nodiscard]] int year() const noexcept { return year_; }
    [[nodiscard]] int month() const noexcept { return month_; }

    /// Returns the immediately succeeding month bucket (e.g. 202612 -> 202701).
    [[nodiscard]] MessageBucket next_bucket() const;

    /// Returns the immediately preceding month bucket (e.g. 202701 -> 202612).
    [[nodiscard]] MessageBucket previous_bucket() const;

    auto operator<=>(const MessageBucket& other) const noexcept = default;
    bool operator==(const MessageBucket& other) const noexcept = default;

  private:
    explicit MessageBucket(std::string bucket, int year, int month)
        : bucket_(std::move(bucket)), year_(year), month_(month) {}

    std::string bucket_;
    int year_{0};
    int month_{0};
};

} // namespace securecloud::messaging::domain

namespace std {
template <> struct hash<securecloud::messaging::domain::MessageBucket> {
    std::size_t operator()(const securecloud::messaging::domain::MessageBucket& mb) const noexcept {
        return std::hash<std::string>{}(mb.value());
    }
};
} // namespace std
