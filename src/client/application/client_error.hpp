#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <variant>

namespace securecloud::client::application {

enum class ClientErrorCode {
    Success = 0,
    NetworkUnavailable,
    ConnectionTimeout,
    TlsHandshakeFailed,
    ProtocolError,
    AuthenticationRequired,
    InvalidCredentials,
    SessionExpired,
    Unauthorized,
    StorageReadError,
    StorageWriteError,
    DatabaseCorrupted,
    ValidationFailed,
    CryptoOperationFailed,
    InternalError
};

enum class ClientErrorCategory { Network, Authentication, Storage, Validation, Crypto, Internal };

[[nodiscard]] std::string_view to_string(ClientErrorCode code) noexcept;
[[nodiscard]] std::string_view to_string(ClientErrorCategory category) noexcept;

class ClientError {
  public:
    ClientError() = default;
    ClientError(ClientErrorCode code, ClientErrorCategory category, std::string user_message, std::string details = "",
                std::string correlation_id = "");

    [[nodiscard]] ClientErrorCode code() const noexcept { return code_; }
    [[nodiscard]] ClientErrorCategory category() const noexcept { return category_; }
    [[nodiscard]] const std::string& user_message() const noexcept { return user_message_; }
    [[nodiscard]] const std::string& details() const noexcept { return details_; }
    [[nodiscard]] const std::string& correlation_id() const noexcept { return correlation_id_; }

    [[nodiscard]] std::string to_string() const;

    // Factory methods
    static ClientError network(std::string user_message, std::string details = "", std::string correlation_id = "");
    static ClientError timeout(std::string user_message, std::string details = "", std::string correlation_id = "");
    static ClientError authentication(std::string user_message, std::string details = "",
                                      std::string correlation_id = "");
    static ClientError storage(std::string user_message, std::string details = "", std::string correlation_id = "");
    static ClientError validation(std::string user_message, std::string details = "", std::string correlation_id = "");
    static ClientError crypto(std::string user_message, std::string details = "", std::string correlation_id = "");
    static ClientError internal_error(std::string user_message, std::string details = "",
                                      std::string correlation_id = "");

  private:
    ClientErrorCode code_{ClientErrorCode::InternalError};
    ClientErrorCategory category_{ClientErrorCategory::Internal};
    std::string user_message_{"An unknown error occurred"};
    std::string details_{};
    std::string correlation_id_{};
};

template <typename T> class ClientResult {
  public:
    ClientResult(T value) : storage_(std::move(value)) {}
    ClientResult(ClientError error) : storage_(std::move(error)) {}

    static ClientResult<T> ok(T value) { return ClientResult<T>(std::move(value)); }
    static ClientResult<T> error(ClientError err) { return ClientResult<T>(std::move(err)); }

    [[nodiscard]] bool is_ok() const noexcept { return std::holds_alternative<T>(storage_); }
    [[nodiscard]] bool is_error() const noexcept { return std::holds_alternative<ClientError>(storage_); }
    explicit operator bool() const noexcept { return is_ok(); }

    [[nodiscard]] const T& value() const& { return std::get<T>(storage_); }
    [[nodiscard]] T& value() & { return std::get<T>(storage_); }
    [[nodiscard]] T&& value() && { return std::get<T>(std::move(storage_)); }

    [[nodiscard]] const ClientError& error() const& { return std::get<ClientError>(storage_); }
    [[nodiscard]] ClientError& error() & { return std::get<ClientError>(storage_); }
    [[nodiscard]] ClientError&& error() && { return std::get<ClientError>(std::move(storage_)); }

    [[nodiscard]] const T& value_or(const T& default_val) const& {
        return is_ok() ? std::get<T>(storage_) : default_val;
    }

    template <typename F> auto and_then(F&& f) const {
        using ReturnType = std::invoke_result_t<F, const T&>;
        if (is_ok()) {
            return f(value());
        }
        return ReturnType::error(error());
    }

    template <typename F> auto transform(F&& f) const {
        using ReturnType = std::invoke_result_t<F, const T&>;
        if (is_ok()) {
            return ClientResult<ReturnType>::ok(f(value()));
        }
        return ClientResult<ReturnType>::error(error());
    }

  private:
    std::variant<T, ClientError> storage_;
};

template <> class ClientResult<void> {
  public:
    ClientResult() noexcept : error_(std::nullopt) {}
    ClientResult(ClientError error) : error_(std::move(error)) {}

    static ClientResult<void> ok() noexcept { return ClientResult<void>(); }
    static ClientResult<void> error(ClientError err) { return ClientResult<void>(std::move(err)); }

    [[nodiscard]] bool is_ok() const noexcept { return !error_.has_value(); }
    [[nodiscard]] bool is_error() const noexcept { return error_.has_value(); }
    explicit operator bool() const noexcept { return is_ok(); }

    [[nodiscard]] const ClientError& error() const& { return error_.value(); }
    [[nodiscard]] ClientError& error() & { return error_.value(); }
    [[nodiscard]] ClientError&& error() && { return std::move(error_).value(); }

    template <typename F> auto and_then(F&& f) const {
        using ReturnType = std::invoke_result_t<F>;
        if (is_ok()) {
            return f();
        }
        return ReturnType::error(error());
    }

  private:
    std::optional<ClientError> error_;
};

} // namespace securecloud::client::application
