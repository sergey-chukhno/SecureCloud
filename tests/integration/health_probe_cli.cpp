#include "securecloud/common/v1/health.grpc.pb.h"
#include "securecloud/security/mtls_config.hpp"

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <grpcpp/grpcpp.h>
#include <iostream>
#include <memory>
#include <string>
#include <string_view>

namespace {

constexpr int k_exit_ok = 0;
constexpr int k_exit_rpc_error = 1;
constexpr int k_exit_status_mismatch = 2;
constexpr int k_exit_invalid_args = 3;

constexpr int k_default_timeout_ms = 3000;
constexpr int k_decimal_base = 10;

struct ProbeOptions {
    std::string target;
    std::string server_name;
    std::string service_name;
    std::string ca_path;
    std::string cert_path;
    std::string key_path;
    std::string expected_status;
    int timeout_ms{k_default_timeout_ms};
};

void print_usage(std::string_view prog_name) {
    std::cerr << "Usage: " << prog_name << " [options]\n"
              << "Options:\n"
              << "  --target <host:port>            Target address (required)\n"
              << "  --server-name <san>             Expected server SAN identity (required)\n"
              << "  --service-name <name>           Service string for Check (\"\" or \"readiness\")\n"
              << "  --ca <path>                     CA certificate path (required)\n"
              << "  --cert <path>                   Client certificate path (required)\n"
              << "  --key <path>                    Client private key path (required)\n"
              << "  --expected-status <STATUS>      Expected status (SERVING, NOT_SERVING, SERVICE_UNKNOWN)\n"
              << "  --timeout-ms <ms>               RPC deadline in milliseconds (default: 3000)\n";
}

bool parse_flag_value(std::string_view flag, const char* val, ProbeOptions& opts) {
    if (flag == "--target") {
        opts.target = val;
    } else if (flag == "--server-name") {
        opts.server_name = val;
    } else if (flag == "--service-name") {
        opts.service_name = val;
    } else if (flag == "--ca") {
        opts.ca_path = val;
    } else if (flag == "--cert") {
        opts.cert_path = val;
    } else if (flag == "--key") {
        opts.key_path = val;
    } else if (flag == "--expected-status") {
        opts.expected_status = val;
    } else if (flag == "--timeout-ms") {
        char* end = nullptr;
        long timeout_val = std::strtol(val, &end, k_decimal_base);
        if (end != nullptr && *end == '\0' && timeout_val > 0) {
            opts.timeout_ms = static_cast<int>(timeout_val);
        }
    } else {
        return false;
    }
    return true;
}

bool is_valid_options(const ProbeOptions& opts) noexcept {
    if (opts.target.empty() || opts.server_name.empty() || opts.ca_path.empty()) {
        return false;
    }
    return (!opts.cert_path.empty() && !opts.key_path.empty());
}

bool parse_args(int argc, char* const* argv, ProbeOptions& options) {
    for (int i = 1; i < argc; ++i) {
        std::string_view arg(argv[i]);
        if (arg == "--help" || arg == "-h") {
            print_usage(argv[0]);
            return false;
        }

        if (i + 1 >= argc) {
            std::cerr << "Missing value for argument: " << arg << "\n";
            print_usage(argv[0]);
            return false;
        }

        const char* val = argv[++i];
        if (!parse_flag_value(arg, val, options)) {
            std::cerr << "Unknown argument: " << arg << "\n";
            print_usage(argv[0]);
            return false;
        }
    }

    if (!is_valid_options(options)) {
        std::cerr << "Missing required arguments\n";
        print_usage(argv[0]);
        return false;
    }

    return true;
}

std::string_view to_string(securecloud::common::v1::HealthCheckResponse::ServingStatus status) noexcept {
    switch (status) {
    case securecloud::common::v1::HealthCheckResponse::SERVING:
        return "SERVING";
    case securecloud::common::v1::HealthCheckResponse::NOT_SERVING:
        return "NOT_SERVING";
    case securecloud::common::v1::HealthCheckResponse::SERVICE_UNKNOWN:
        return "SERVICE_UNKNOWN";
    default:
        return "UNKNOWN";
    }
}

int run_probe(int argc, char* const* argv) {
    ProbeOptions options;
    if (!parse_args(argc, argv, options)) {
        return k_exit_invalid_args;
    }

    securecloud::common::security::SecurityCredentialsConfig creds_config{
        .ca_cert_path = options.ca_path,
        .service_cert_path = options.cert_path,
        .service_key_path = options.key_path,
    };

    auto channel = securecloud::common::security::MtlsCredentialLoader::create_mtls_channel(
        options.target, creds_config, options.server_name);
    auto stub = securecloud::common::v1::HealthService::NewStub(channel);

    grpc::ClientContext context;
    context.set_deadline(std::chrono::system_clock::now() + std::chrono::milliseconds(options.timeout_ms));

    securecloud::common::v1::HealthCheckRequest request;
    request.set_service(options.service_name);
    securecloud::common::v1::HealthCheckResponse response;

    grpc::Status status = stub->Check(&context, request, &response);

    if (!status.ok()) {
        std::cerr << "ERROR: RPC failed with code " << status.error_code() << ": " << status.error_message() << "\n";
        return k_exit_rpc_error;
    }

    std::string_view status_str = to_string(response.status());
    std::cout << status_str << "\n";

    if (!options.expected_status.empty()) {
        if (status_str != options.expected_status) {
            std::cerr << "STATUS MISMATCH: expected " << options.expected_status << ", got " << status_str << "\n";
            return k_exit_status_mismatch;
        }
        return k_exit_ok;
    }

    return (response.status() == securecloud::common::v1::HealthCheckResponse::SERVING) ? k_exit_ok
                                                                                        : k_exit_status_mismatch;
}

} // namespace

int main(int argc, char* argv[]) noexcept {
    try {
        return run_probe(argc, argv);
    } catch (const std::exception& ex) {
        std::cerr << "FATAL: " << ex.what() << "\n";
        return k_exit_rpc_error;
    } catch (...) {
        std::cerr << "FATAL: unknown exception\n";
        return k_exit_rpc_error;
    }
}
