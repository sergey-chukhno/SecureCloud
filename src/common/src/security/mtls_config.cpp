#include "securecloud/security/mtls_config.hpp"

#include <fstream>
#include <sstream>
#include <stdexcept>

namespace securecloud::common::security {

namespace {

std::string read_file_or_throw(const std::filesystem::path& file_path, std::string_view file_description) {
    if (!std::filesystem::exists(file_path)) {
        throw std::runtime_error("mTLS Credential Error: " + std::string(file_description) + " file missing at " +
                                 file_path.string());
    }

    std::ifstream file_stream(file_path, std::ios::in | std::ios::binary);
    if (!file_stream.is_open()) {
        throw std::runtime_error("mTLS Credential Error: Failed to open " + std::string(file_description) + " at " +
                                 file_path.string());
    }

    std::ostringstream buffer;
    buffer << file_stream.rdbuf();
    std::string content = buffer.str();

    if (content.empty()) {
        throw std::runtime_error("mTLS Credential Error: " + std::string(file_description) + " at " +
                                 file_path.string() + " is empty");
    }

    return content;
}

} // namespace

LoadedCredentials MtlsCredentialLoader::load_credentials_or_throw(const SecurityCredentialsConfig& config) {
    LoadedCredentials loaded;
    loaded.ca_cert_pem = read_file_or_throw(config.ca_cert_path, "CA Root Certificate");
    loaded.service_cert_pem = read_file_or_throw(config.service_cert_path, "Service Certificate");
    loaded.service_key_pem = read_file_or_throw(config.service_key_path, "Service Private Key");
    return loaded;
}

std::shared_ptr<grpc::ServerCredentials>
MtlsCredentialLoader::create_server_credentials(const SecurityCredentialsConfig& config) {
    LoadedCredentials loaded = load_credentials_or_throw(config);

    grpc::SslServerCredentialsOptions options(GRPC_SSL_REQUEST_AND_REQUIRE_CLIENT_CERTIFICATE_AND_VERIFY);
    options.pem_root_certs = loaded.ca_cert_pem;

    grpc::SslServerCredentialsOptions::PemKeyCertPair key_cert_pair;
    key_cert_pair.private_key = loaded.service_key_pem;
    key_cert_pair.cert_chain = loaded.service_cert_pem;

    options.pem_key_cert_pairs.push_back(key_cert_pair);

    return grpc::SslServerCredentials(options);
}

std::shared_ptr<grpc::ChannelCredentials>
MtlsCredentialLoader::create_client_credentials(const SecurityCredentialsConfig& config) {
    LoadedCredentials loaded = load_credentials_or_throw(config);

    grpc::SslCredentialsOptions options;
    options.pem_root_certs = loaded.ca_cert_pem;
    options.pem_private_key = loaded.service_key_pem;
    options.pem_cert_chain = loaded.service_cert_pem;

    return grpc::SslCredentials(options);
}

std::shared_ptr<grpc::Channel> MtlsCredentialLoader::create_mtls_channel(const std::string& target_address,
                                                                         const SecurityCredentialsConfig& config,
                                                                         std::string_view expected_peer_service_name) {
    auto creds = create_client_credentials(config);

    grpc::ChannelArguments channel_args;
    if (!expected_peer_service_name.empty()) {
        channel_args.SetSslTargetNameOverride(std::string(expected_peer_service_name));
    }

    return grpc::CreateCustomChannel(target_address, creds, channel_args);
}

std::optional<std::string> extract_peer_service_identity(const grpc::AuthContext& auth_context) {
    if (!auth_context.IsPeerAuthenticated()) {
        return std::nullopt;
    }

    // SAN DNS identity is used EXCLUSIVELY. Never fall back to CN.
    auto san_properties = auth_context.FindPropertyValues("x509_subject_alternative_name");
    for (const auto& prop : san_properties) {
        std::string_view val(prop.data(), prop.size());
        if (val.starts_with("DNS:")) {
            val.remove_prefix(4);
        }
        if (!val.empty()) {
            return std::string(val);
        }
    }

    auto peer_identity = auth_context.GetPeerIdentity();
    for (const auto& prop : peer_identity) {
        std::string_view val(prop.data(), prop.size());
        if (val.starts_with("DNS:")) {
            val.remove_prefix(4);
        }
        if (!val.empty()) {
            return std::string(val);
        }
    }

    // Fail closed if no valid SAN DNS identity exists.
    return std::nullopt;
}

bool verify_peer_service_identity(const grpc::AuthContext& auth_context, std::string_view expected_service_name) {
    auto extracted_identity = extract_peer_service_identity(auth_context);
    if (!extracted_identity.has_value()) {
        return false;
    }
    return extracted_identity.value() == expected_service_name;
}

} // namespace securecloud::common::security
