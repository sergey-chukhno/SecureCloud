#include "messaging_audit_client.hpp"
#include <fstream>
#include <sstream>
#include <iostream>

namespace securecloud::messaging::audit {

namespace {
std::string read_file(const std::string& filepath) {
    std::ifstream ifs(filepath);
    if (!ifs.is_open()) return "";
    std::ostringstream oss;
    oss << ifs.rdbuf();
    return oss.str();
}
} // namespace

MessagingAuditClient::MessagingAuditClient(const AuditClientConfig& config) {
    grpc::SslCredentialsOptions ssl_opts;
    ssl_opts.pem_root_certs = read_file(config.ca_cert_path);
    ssl_opts.pem_cert_chain = read_file(config.client_cert_path);
    ssl_opts.pem_private_key = read_file(config.client_key_path);

    grpc::ChannelArguments channel_args;
    // Strict SAN validation
    channel_args.SetSslTargetNameOverride(config.expected_peer_san);

    auto credentials = grpc::SslCredentials(ssl_opts);
    channel_ = grpc::CreateCustomChannel(config.target_address, credentials, channel_args);
    stub_ = securecloud::audit::v1::AuditIngestionService::NewStub(channel_);
}

bool MessagingAuditClient::publish_batch(const std::vector<securecloud::audit::v1::AuditEventProto>& events) {
    if (events.empty()) return true;

    securecloud::audit::v1::BatchSubmitAuditEventsRequest request;
    for (const auto& ev : events) {
        *request.add_events() = ev;
    }

    securecloud::audit::v1::BatchSubmitAuditEventsResponse response;
    grpc::ClientContext context;
    context.set_deadline(std::chrono::system_clock::now() + std::chrono::seconds(5));

    grpc::Status status = stub_->BatchSubmitAuditEvents(&context, request, &response);

    if (!status.ok()) {
        std::cerr << "[AuditClient] RPC Failed: " << status.error_message() << std::endl;
        return false;
    }

    if (response.rejected_count() > 0) {
        std::cerr << "[AuditClient] Warning: " << response.rejected_count() << " events rejected by ingestion server." << std::endl;
        // Depending on strictness, we might return false here or track quarantine metrics.
        return false;
    }

    return true;
}

} // namespace securecloud::messaging::audit
