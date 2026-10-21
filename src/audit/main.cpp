#include "audit_config.hpp"
#include "audit_server.hpp"
#include "securecloud/configuration/configuration_source.hpp"
#include "securecloud/configuration/validation_error.hpp"

#include <atomic>
#include <csignal>
#include <iostream>

namespace {

std::atomic<bool> g_shutdown_requested{false};
securecloud::audit::AuditServer* g_server = nullptr;

void signal_handler(int signal) {
    if (signal == SIGINT || signal == SIGTERM) {
        if (!g_shutdown_requested.exchange(true)) {
            if (g_server) {
                g_server->stop();
            }
        }
    }
}

int run_service() {
    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    securecloud::common::configuration::ProcessEnvironmentSource env_source;
    securecloud::common::configuration::ValidationResult config_errors;
    auto config = securecloud::audit::AuditConfig::load(env_source, config_errors);

    if (!config_errors.is_valid()) {
        std::cerr << "[SecureCloud] [" << config.common.service_name << "] FATAL: Configuration validation failed:\n"
                  << config_errors.to_string() << "\n";
        return 1;
    }

    securecloud::audit::AuditServer server(std::move(config));
    g_server = &server;

    if (!server.start()) {
        return 1;
    }

    server.wait();
    return 0;
}

} // namespace

int main() noexcept {
    try {
        return run_service();
    } catch (const std::exception& ex) {
        std::cerr << "[SecureCloud] [audit] Unhandled exception: " << ex.what() << "\n";
        return 1;
    } catch (...) {
        std::cerr << "[SecureCloud] [audit] Unknown fatal error occurred\n";
        return 1;
    }
}