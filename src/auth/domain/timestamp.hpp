#pragma once

#include <chrono>
#include <cstdint>
#include <ctime>
#include <iomanip>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>

namespace securecloud::auth::domain {

using time_point = std::chrono::system_clock::time_point;

[[nodiscard]] inline time_point now_utc() noexcept {
    return std::chrono::system_clock::now();
}

[[nodiscard]] inline int64_t to_epoch_ms(time_point tp) noexcept {
    return std::chrono::duration_cast<std::chrono::milliseconds>(tp.time_since_epoch()).count();
}

[[nodiscard]] inline time_point from_epoch_ms(int64_t ms) noexcept {
    return time_point(std::chrono::milliseconds(ms));
}

/// Formats UTC time_point as ISO-8601 string: YYYY-MM-DDTHH:MM:SS.ffffffZ
[[nodiscard]] inline std::string to_iso8601_utc(time_point tp) {
    auto duration = tp.time_since_epoch();
    auto seconds = std::chrono::duration_cast<std::chrono::seconds>(duration);
    auto micros = std::chrono::duration_cast<std::chrono::microseconds>(duration - seconds).count();

    std::time_t tt = seconds.count();
    std::tm tm_buf{};
#if defined(_WIN32)
    gmtime_s(&tm_buf, &tt);
#else
    gmtime_r(&tt, &tm_buf);
#endif

    std::ostringstream oss;
    oss << std::put_time(&tm_buf, "%Y-%m-%dT%H:%M:%S") << '.' << std::setfill('0') << std::setw(6) << micros << 'Z';
    return oss.str();
}

/// Parses ISO-8601 or PostgreSQL timestamptz string (e.g. "2026-10-05 10:30:00.123456+00" or
/// "2026-10-05T10:30:00.123456Z")
[[nodiscard]] inline std::optional<time_point> from_iso8601_utc(std::string_view str) {
    if (str.empty()) {
        return std::nullopt;
    }

    // Replace 'T' with ' ' for uniform parsing if present
    std::string s(str);
    auto t_pos = s.find('T');
    if (t_pos != std::string::npos) {
        s[t_pos] = ' ';
    }
    if (!s.empty() && s.back() == 'Z') {
        s.pop_back();
    }

    std::tm tm_buf{};
    std::istringstream iss(s);
    iss >> std::get_time(&tm_buf, "%Y-%m-%d %H:%M:%S");
    if (iss.fail()) {
        return std::nullopt;
    }

    int64_t micros = 0;
    if (iss.peek() == '.') {
        iss.ignore(1);
        std::string frac;
        while (std::isdigit(iss.peek())) {
            frac.push_back(static_cast<char>(iss.get()));
        }
        while (frac.size() < 6) {
            frac.push_back('0');
        }
        if (frac.size() > 6) {
            frac.resize(6);
        }
        micros = std::stoll(frac);
    }

#if defined(_WIN32)
    std::time_t tt = _mkgmtime(&tm_buf);
#else
    std::time_t tt = timegm(&tm_buf);
#endif

    if (tt == -1) {
        return std::nullopt;
    }

    return time_point(std::chrono::seconds(tt) + std::chrono::microseconds(micros));
}

/// Convenience aliases for ISO-8601 UTC string conversions
[[nodiscard]] inline std::string to_iso8601(time_point tp) {
    return to_iso8601_utc(tp);
}

[[nodiscard]] inline std::optional<time_point> from_iso8601(std::string_view str) {
    return from_iso8601_utc(str);
}

} // namespace securecloud::auth::domain
