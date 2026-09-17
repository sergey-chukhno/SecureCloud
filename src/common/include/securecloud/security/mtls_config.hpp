#pragma once

#include <filesystem>
#include <grpcpp/grpcpp.h>
#include <grpcpp/security/credentials.h>
#include <grpcpp/security/server_credentials.h>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

namespace securecloud::common::security {

/// Filesystem paths for development/production mTLS credentials.
struct SecurityCredentialsConfig {
    std::filesystem::path ca_cert_path;
    std::filesystem::path service_cert_path;
    std::filesystem::path service_key_path;
};

/// Loaded PEM credential buffers.
struct LoadedCredentials {
    std::string ca_cert_pem;
    std::string service_cert_pem;
    std::string service_key_pem;
};

/// Loader and factory for gRPC mTLS credentials and channel creation.
class MtlsCredentialLoader {
  public:
    /// Loads credentials from disk into memory.
    /// Throws std::runtime_error (fails closed) if any credential file is missing, empty, or unreadable.
    static LoadedCredentials load_credentials_or_throw(const SecurityCredentialsConfig& config);

    /// Constructs gRPC SslServerCredentials with mandatory client cert verification.
    /// Uses GRPC_SSL_REQUEST_AND_REQUIRE_CLIENT_CERTIFICATE_AND_VERIFY.
    static std::shared_ptr<grpc::ServerCredentials> create_server_credentials(const SecurityCredentialsConfig& config);

    /// Constructs gRPC SslCredentials for mTLS client connections.
    static std::shared_ptr<grpc::ChannelCredentials> create_client_credentials(const SecurityCredentialsConfig& config);

    /// Creates a secure mTLS gRPC channel with explicit expected peer service SAN target override.
    static std::shared_ptr<grpc::Channel> create_mtls_channel(const std::string& target_address,
                                                              const SecurityCredentialsConfig& config,
                                                              std::string_view expected_peer_service_name);
};

/// Extracts SAN DNS identity from a gRPC AuthContext.
/// SAN DNS identity is used EXCLUSIVELY. If no valid SAN DNS identity exists, returns std::nullopt.
/// Never falls back to Common Name (CN).
std::optional<std::string> extract_peer_service_identity(const grpc::AuthContext& auth_context);

/// Verifies that the extracted SAN DNS identity from auth_context matches expected_service_name.
bool verify_peer_service_identity(const grpc::AuthContext& auth_context, std::string_view expected_service_name);

} // namespace securecloud::common::security
