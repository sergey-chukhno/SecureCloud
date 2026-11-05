#include "application/client_error.hpp"

#include <sstream>

namespace securecloud::client::application {

std::string_view to_string(ClientErrorCode code) noexcept {
    switch (code) {
    case ClientErrorCode::Success:
        return "Success";
    case ClientErrorCode::NetworkUnavailable:
        return "NetworkUnavailable";
    case ClientErrorCode::ConnectionTimeout:
        return "ConnectionTimeout";
    case ClientErrorCode::TlsHandshakeFailed:
        return "TlsHandshakeFailed";
    case ClientErrorCode::ProtocolError:
        return "ProtocolError";
    case ClientErrorCode::AuthenticationRequired:
        return "AuthenticationRequired";
    case ClientErrorCode::InvalidCredentials:
        return "InvalidCredentials";
    case ClientErrorCode::SessionExpired:
        return "SessionExpired";
    case ClientErrorCode::Unauthorized:
        return "Unauthorized";
    case ClientErrorCode::StorageReadError:
        return "StorageReadError";
    case ClientErrorCode::StorageWriteError:
        return "StorageWriteError";
    case ClientErrorCode::DatabaseCorrupted:
        return "DatabaseCorrupted";
    case ClientErrorCode::ValidationFailed:
        return "ValidationFailed";
    case ClientErrorCode::CryptoOperationFailed:
        return "CryptoOperationFailed";
    case ClientErrorCode::InternalError:
        return "InternalError";
    }
    return "Unknown";
}

std::string_view to_string(ClientErrorCategory category) noexcept {
    switch (category) {
    case ClientErrorCategory::Network:
        return "Network";
    case ClientErrorCategory::Authentication:
        return "Authentication";
    case ClientErrorCategory::Storage:
        return "Storage";
    case ClientErrorCategory::Validation:
        return "Validation";
    case ClientErrorCategory::Crypto:
        return "Crypto";
    case ClientErrorCategory::Internal:
        return "Internal";
    }
    return "Unknown";
}

ClientError::ClientError(ClientErrorCode code, ClientErrorCategory category, std::string user_message,
                         std::string details, std::string correlation_id)
    : code_(code), category_(category), user_message_(std::move(user_message)), details_(std::move(details)),
      correlation_id_(std::move(correlation_id)) {}

std::string ClientError::to_string() const {
    std::ostringstream oss;
    oss << "[" << application::to_string(category_) << "::" << application::to_string(code_) << "] " << user_message_;
    if (!details_.empty()) {
        oss << " (details: " << details_ << ")";
    }
    if (!correlation_id_.empty()) {
        oss << " [correlation_id: " << correlation_id_ << "]";
    }
    return oss.str();
}

ClientError ClientError::network(std::string user_message, std::string details, std::string correlation_id) {
    return ClientError(ClientErrorCode::NetworkUnavailable, ClientErrorCategory::Network, std::move(user_message),
                       std::move(details), std::move(correlation_id));
}

ClientError ClientError::timeout(std::string user_message, std::string details, std::string correlation_id) {
    return ClientError(ClientErrorCode::ConnectionTimeout, ClientErrorCategory::Network, std::move(user_message),
                       std::move(details), std::move(correlation_id));
}

ClientError ClientError::authentication(std::string user_message, std::string details, std::string correlation_id) {
    return ClientError(ClientErrorCode::AuthenticationRequired, ClientErrorCategory::Authentication,
                       std::move(user_message), std::move(details), std::move(correlation_id));
}

ClientError ClientError::storage(std::string user_message, std::string details, std::string correlation_id) {
    return ClientError(ClientErrorCode::StorageReadError, ClientErrorCategory::Storage, std::move(user_message),
                       std::move(details), std::move(correlation_id));
}

ClientError ClientError::validation(std::string user_message, std::string details, std::string correlation_id) {
    return ClientError(ClientErrorCode::ValidationFailed, ClientErrorCategory::Validation, std::move(user_message),
                       std::move(details), std::move(correlation_id));
}

ClientError ClientError::crypto(std::string user_message, std::string details, std::string correlation_id) {
    return ClientError(ClientErrorCode::CryptoOperationFailed, ClientErrorCategory::Crypto, std::move(user_message),
                       std::move(details), std::move(correlation_id));
}

ClientError ClientError::internal_error(std::string user_message, std::string details, std::string correlation_id) {
    return ClientError(ClientErrorCode::InternalError, ClientErrorCategory::Internal, std::move(user_message),
                       std::move(details), std::move(correlation_id));
}

} // namespace securecloud::client::application
