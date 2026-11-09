#pragma once

#include <functional>
#include <string>
#include <string_view>

namespace securecloud::client::infrastructure {

enum class LogLevel { Trace = 0, Debug, Info, Warning, Error, Fatal };

[[nodiscard]] std::string_view to_string(LogLevel level) noexcept;

class ClientLogger {
  public:
    using LogSink = std::function<void(LogLevel level, std::string_view tag, std::string_view message,
                                       std::string_view correlation_id)>;

    static void set_min_level(LogLevel level) noexcept;
    static LogLevel min_level() noexcept;

    static void set_custom_sink(LogSink sink);
    static void reset_sink();

    static void log(LogLevel level, std::string_view tag, std::string_view message,
                    std::string_view correlation_id = "");

    static void trace(std::string_view tag, std::string_view message, std::string_view correlation_id = "");
    static void debug(std::string_view tag, std::string_view message, std::string_view correlation_id = "");
    static void info(std::string_view tag, std::string_view message, std::string_view correlation_id = "");
    static void warn(std::string_view tag, std::string_view message, std::string_view correlation_id = "");
    static void error(std::string_view tag, std::string_view message, std::string_view correlation_id = "");

    /// Intercepts and scrubs tokens, passwords, private keys, and sensitive auth data.
    [[nodiscard]] static std::string sanitize(std::string_view raw);
};

} // namespace securecloud::client::infrastructure
