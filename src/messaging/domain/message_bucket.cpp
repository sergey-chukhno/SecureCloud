#include "messaging/domain/message_bucket.hpp"

#include <ctime>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace securecloud::messaging::domain {

MessageBucket MessageBucket::from_year_month(int year, int month) {
    if (year < 1970 || year > 9999) {
        throw std::invalid_argument("MessageBucket year must be between 1970 and 9999");
    }
    if (month < 1 || month > 12) {
        throw std::invalid_argument("MessageBucket month must be between 1 and 12");
    }

    std::ostringstream oss;
    oss << std::setfill('0') << std::setw(4) << year << std::setw(2) << month;
    return MessageBucket(oss.str(), year, month);
}

MessageBucket MessageBucket::from_time_point(std::chrono::system_clock::time_point tp) {
    std::time_t tt = std::chrono::system_clock::to_time_t(tp);
    std::tm tm_utc{};
#ifdef _WIN32
    if (gmtime_s(&tm_utc, &tt) != 0) {
        throw std::runtime_error("gmtime_s failed in MessageBucket::from_time_point");
    }
#else
    if (gmtime_r(&tt, &tm_utc) == nullptr) {
        throw std::runtime_error("gmtime_r failed in MessageBucket::from_time_point");
    }
#endif

    int year = tm_utc.tm_year + 1900;
    int month = tm_utc.tm_mon + 1;
    return from_year_month(year, month);
}

std::optional<MessageBucket> MessageBucket::from_string(std::string_view sv) noexcept {
    if (sv.size() != 6) {
        return std::nullopt;
    }
    for (char c : sv) {
        if (c < '0' || c > '9') {
            return std::nullopt;
        }
    }

    int year = (sv[0] - '0') * 1000 + (sv[1] - '0') * 100 + (sv[2] - '0') * 10 + (sv[3] - '0');
    int month = (sv[4] - '0') * 10 + (sv[5] - '0');

    if (year < 1970 || year > 9999 || month < 1 || month > 12) {
        return std::nullopt;
    }

    return MessageBucket(std::string(sv), year, month);
}

MessageBucket MessageBucket::next_bucket() const {
    if (bucket_.empty()) {
        throw std::logic_error("Cannot call next_bucket on uninitialized MessageBucket");
    }
    int y = year_;
    int m = month_ + 1;
    if (m > 12) {
        m = 1;
        ++y;
    }
    return from_year_month(y, m);
}

MessageBucket MessageBucket::previous_bucket() const {
    if (bucket_.empty()) {
        throw std::logic_error("Cannot call previous_bucket on uninitialized MessageBucket");
    }
    int y = year_;
    int m = month_ - 1;
    if (m < 1) {
        m = 12;
        --y;
    }
    return from_year_month(y, m);
}

} // namespace securecloud::messaging::domain
