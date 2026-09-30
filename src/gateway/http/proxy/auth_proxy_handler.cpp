#include "http/proxy/auth_proxy_handler.hpp"

#include "grpc/client_call_context.hpp"
#include "http/auth/request_context.hpp"
#include "http/errors/error_mapper.hpp"
#include "http/routing/router.hpp"

#include <httplib.h>
#include <nlohmann/json.hpp>
#include <stdexcept>
#include <utility>

namespace securecloud::gateway::http {
namespace {

constexpr const char* k_content_type_json = "application/json";

class ActiveCallGuard {
  public:
    ActiveCallGuard(AuthProxyHandler& handler, const std::string& request_id, grpc::ClientCallContext& ctx)
        : handler_(handler), request_id_(request_id) {
        if (!request_id_.empty()) {
            handler_.register_active_call(request_id_, &ctx);
        }
    }
    ~ActiveCallGuard() {
        if (!request_id_.empty()) {
            handler_.unregister_active_call(request_id_);
        }
    }

  private:
    AuthProxyHandler& handler_;
    std::string request_id_;
};

} // namespace

AuthProxyHandler::AuthProxyHandler(std::shared_ptr<grpc::IAuthClient> auth_client,
                                   std::shared_ptr<DeadlineManager> deadline_manager,
                                   std::shared_ptr<RetryPolicy> retry_policy,
                                   std::shared_ptr<BulkheadManager> bulkhead_manager)
    : auth_client_(std::move(auth_client)),
      deadline_manager_(deadline_manager ? std::move(deadline_manager) : std::make_shared<DeadlineManager>()),
      retry_policy_(retry_policy ? std::move(retry_policy) : std::make_shared<RetryPolicy>()),
      bulkhead_manager_(bulkhead_manager ? std::move(bulkhead_manager) : std::make_shared<BulkheadManager>()) {
    if (!auth_client_) {
        throw std::invalid_argument("AuthProxyHandler: auth_client must not be null");
    }
}

void AuthProxyHandler::register_active_call(const std::string& request_id, grpc::ClientCallContext* ctx) {
    if (request_id.empty() || !ctx) {
        return;
    }
    std::lock_guard<std::mutex> lock(active_calls_mutex_);
    active_calls_[request_id] = ctx;
}

void AuthProxyHandler::unregister_active_call(const std::string& request_id) {
    if (request_id.empty()) {
        return;
    }
    std::lock_guard<std::mutex> lock(active_calls_mutex_);
    active_calls_.erase(request_id);
}

bool AuthProxyHandler::cancel_request(const std::string& request_id) {
    if (request_id.empty()) {
        return false;
    }
    std::lock_guard<std::mutex> lock(active_calls_mutex_);
    auto it = active_calls_.find(request_id);
    if (it != active_calls_.end() && it->second != nullptr) {
        it->second->cancel();
        return true;
    }
    return false;
}

void AuthProxyHandler::register_routes(Router& router) {
    router.post("/api/v1/auth/login",
                [this](const httplib::Request& req, httplib::Response& res) { handle_login(req, res); });

    router.post("/api/v1/auth/refresh",
                [this](const httplib::Request& req, httplib::Response& res) { handle_refresh(req, res); });

    router.post_authenticated("/api/v1/auth/revoke",
                              [this](const httplib::Request& req, httplib::Response& res,
                                     const AuthenticatedContext& ctx) { handle_revoke(req, res, ctx); });

    router.get_authenticated("/api/v1/users/me",
                             [this](const httplib::Request& req, httplib::Response& res,
                                    const AuthenticatedContext& ctx) { handle_get_me(req, res, ctx); });

    router.post_authenticated("/api/v1/devices",
                              [this](const httplib::Request& req, httplib::Response& res,
                                     const AuthenticatedContext& ctx) { handle_register_device(req, res, ctx); });
}

std::string AuthProxyHandler::extract_request_id(const httplib::Request& req) {
    if (const auto* rc = RequestContext::current()) {
        if (!rc->request_id().empty()) {
            return rc->request_id();
        }
    }
    if (req.has_header("X-Request-ID")) {
        return req.get_header_value("X-Request-ID");
    }
    return "";
}

void AuthProxyHandler::handle_login(const httplib::Request& req, httplib::Response& res) {
    const auto start_tp = deadline_manager_->now();
    const std::string request_id = extract_request_id(req);

    auto bulkhead_lease = bulkhead_manager_->acquire(WorkloadCategory::Auth);
    if (!bulkhead_lease) {
        BulkheadManager::write_rejection(res, request_id);
        return;
    }

    const auto service_timeout = std::chrono::milliseconds(deadline_manager_->config().auth_timeout_ms);
    const auto effective_deadline = deadline_manager_->compute_effective_deadline(req, service_timeout);

    if (!deadline_manager_->has_sufficient_budget(start_tp, effective_deadline)) {
        ErrorMapper::write_error(res, 504, "GATEWAY_TIMEOUT", "Request deadline exceeded before dispatch", request_id);
        return;
    }

    nlohmann::json body;
    try {
        body = nlohmann::json::parse(req.body);
    } catch (const nlohmann::json::exception&) {
        ErrorMapper::write_error(res, 400, "BAD_REQUEST", "Malformed JSON request body", request_id);
        return;
    }

    if (!body.is_object()) {
        ErrorMapper::write_error(res, 400, "BAD_REQUEST", "Request body must be a JSON object", request_id);
        return;
    }

    std::string identifier;
    if (body.contains("identifier") && body["identifier"].is_string()) {
        identifier = body["identifier"].get<std::string>();
    } else if (body.contains("credential_identifier") && body["credential_identifier"].is_string()) {
        identifier = body["credential_identifier"].get<std::string>();
    }

    std::string credential;
    if (body.contains("credential") && body["credential"].is_string()) {
        credential = body["credential"].get<std::string>();
    } else if (body.contains("password") && body["password"].is_string()) {
        credential = body["password"].get<std::string>();
    }

    if (identifier.empty() || credential.empty()) {
        ErrorMapper::write_error(res, 400, "BAD_REQUEST", "Missing identifier or credential", request_id);
        return;
    }

    securecloud::auth::v1::AuthenticateRequest auth_req;
    auth_req.set_credential_identifier(identifier);
    auth_req.set_password(credential);

    if (body.contains("device_id") && body["device_id"].is_string()) {
        auth_req.set_device_id(body["device_id"].get<std::string>());
    }

    auto rpc_res = retry_policy_->execute(*deadline_manager_, start_tp, effective_deadline, service_timeout,
                                          OperationIdempotency::NON_IDEMPOTENT,
                                          [this, &auth_req, &request_id](std::chrono::milliseconds budget) {
                                              grpc::ClientCallContext call_ctx(request_id, budget);
                                              ActiveCallGuard guard(*this, request_id, call_ctx);
                                              return auth_client_->authenticate(auth_req, call_ctx);
                                          });

    if (!rpc_res) {
        const auto& err = rpc_res.error();
        int http_status = ErrorMapper::grpc_to_http_status(err.grpc_code);
        std::string error_code(ErrorMapper::grpc_to_error_code(err.grpc_code));
        ErrorMapper::write_error(res, http_status, error_code, err.message, request_id);
        return;
    }

    const auto& val = rpc_res.value();
    nlohmann::json res_json = {{"session_id", val.session_id()},
                               {"access_token", val.access_token()},
                               {"refresh_token", val.refresh_token()},
                               {"authentication_level", static_cast<int>(val.authentication_level())},
                               {"expires_at_epoch_ms", val.expires_at_epoch_ms()},
                               {"user_id", val.user_id()},
                               {"mfa_required", val.mfa_required()}};

    if (!val.mfa_challenge_id().empty()) {
        res_json["mfa_challenge_id"] = val.mfa_challenge_id();
    }

    res.status = 200;
    res.set_content(res_json.dump(), k_content_type_json);
}

void AuthProxyHandler::handle_refresh(const httplib::Request& req, httplib::Response& res) {
    const auto start_tp = deadline_manager_->now();
    const std::string request_id = extract_request_id(req);

    auto bulkhead_lease = bulkhead_manager_->acquire(WorkloadCategory::Auth);
    if (!bulkhead_lease) {
        BulkheadManager::write_rejection(res, request_id);
        return;
    }

    const auto service_timeout = std::chrono::milliseconds(deadline_manager_->config().auth_timeout_ms);
    const auto effective_deadline = deadline_manager_->compute_effective_deadline(req, service_timeout);

    if (!deadline_manager_->has_sufficient_budget(start_tp, effective_deadline)) {
        ErrorMapper::write_error(res, 504, "GATEWAY_TIMEOUT", "Request deadline exceeded before dispatch", request_id);
        return;
    }

    nlohmann::json body;
    try {
        body = nlohmann::json::parse(req.body);
    } catch (const nlohmann::json::exception&) {
        ErrorMapper::write_error(res, 400, "BAD_REQUEST", "Malformed JSON request body", request_id);
        return;
    }

    if (!body.is_object() || !body.contains("refresh_token") || !body["refresh_token"].is_string() ||
        body["refresh_token"].get<std::string>().empty()) {
        ErrorMapper::write_error(res, 400, "BAD_REQUEST", "Missing or empty refresh_token", request_id);
        return;
    }

    securecloud::auth::v1::RefreshSessionRequest refresh_req;
    refresh_req.set_refresh_token(body["refresh_token"].get<std::string>());

    if (body.contains("device_id") && body["device_id"].is_string()) {
        refresh_req.set_device_id(body["device_id"].get<std::string>());
    }

    auto rpc_res = retry_policy_->execute(*deadline_manager_, start_tp, effective_deadline, service_timeout,
                                          OperationIdempotency::NON_IDEMPOTENT,
                                          [this, &refresh_req, &request_id](std::chrono::milliseconds budget) {
                                              grpc::ClientCallContext call_ctx(request_id, budget);
                                              ActiveCallGuard guard(*this, request_id, call_ctx);
                                              return auth_client_->refresh_session(refresh_req, call_ctx);
                                          });

    if (!rpc_res) {
        const auto& err = rpc_res.error();
        int http_status = ErrorMapper::grpc_to_http_status(err.grpc_code);
        std::string error_code(ErrorMapper::grpc_to_error_code(err.grpc_code));
        ErrorMapper::write_error(res, http_status, error_code, err.message, request_id);
        return;
    }

    const auto& val = rpc_res.value();
    nlohmann::json res_json = {{"session_id", val.session_id()},
                               {"access_token", val.access_token()},
                               {"refresh_token", val.new_refresh_token()},
                               {"expires_at_epoch_ms", val.expires_at_epoch_ms()}};

    res.status = 200;
    res.set_content(res_json.dump(), k_content_type_json);
}

void AuthProxyHandler::handle_revoke(const httplib::Request& req, httplib::Response& res,
                                     const AuthenticatedContext& ctx) {
    const auto start_tp = deadline_manager_->now();
    const std::string request_id = extract_request_id(req);

    auto bulkhead_lease = bulkhead_manager_->acquire(WorkloadCategory::Auth);
    if (!bulkhead_lease) {
        BulkheadManager::write_rejection(res, request_id);
        return;
    }

    const auto service_timeout = std::chrono::milliseconds(deadline_manager_->config().auth_timeout_ms);
    const auto effective_deadline = deadline_manager_->compute_effective_deadline(req, service_timeout);

    if (!deadline_manager_->has_sufficient_budget(start_tp, effective_deadline)) {
        ErrorMapper::write_error(res, 504, "GATEWAY_TIMEOUT", "Request deadline exceeded before dispatch", request_id);
        return;
    }

    std::string session_id = ctx.session_id();
    std::string reason = "User logout";

    if (!req.body.empty()) {
        try {
            auto body = nlohmann::json::parse(req.body);
            if (body.is_object()) {
                if (body.contains("session_id") && body["session_id"].is_string() &&
                    !body["session_id"].get<std::string>().empty()) {
                    session_id = body["session_id"].get<std::string>();
                }
                if (body.contains("reason") && body["reason"].is_string()) {
                    reason = body["reason"].get<std::string>();
                }
            }
        } catch (const nlohmann::json::exception&) {
            ErrorMapper::write_error(res, 400, "BAD_REQUEST", "Malformed JSON request body", request_id);
            return;
        }
    }

    if (session_id.empty() && req.has_header("x-session-id")) {
        session_id = req.get_header_value("x-session-id");
    }

    if (session_id.empty()) {
        ErrorMapper::write_error(res, 400, "BAD_REQUEST", "Missing session_id to revoke", request_id);
        return;
    }

    securecloud::auth::v1::RevokeSessionRequest revoke_req;
    revoke_req.set_session_id(session_id);
    revoke_req.set_reason(reason);

    auto rpc_res = retry_policy_->execute(*deadline_manager_, start_tp, effective_deadline, service_timeout,
                                          OperationIdempotency::NON_IDEMPOTENT,
                                          [this, &revoke_req, &request_id](std::chrono::milliseconds budget) {
                                              grpc::ClientCallContext call_ctx(request_id, budget);
                                              ActiveCallGuard guard(*this, request_id, call_ctx);
                                              return auth_client_->revoke_session(revoke_req, call_ctx);
                                          });

    if (!rpc_res) {
        const auto& err = rpc_res.error();
        int http_status = ErrorMapper::grpc_to_http_status(err.grpc_code);
        std::string error_code(ErrorMapper::grpc_to_error_code(err.grpc_code));
        ErrorMapper::write_error(res, http_status, error_code, err.message, request_id);
        return;
    }

    nlohmann::json res_json = {{"revoked", rpc_res.value().revoked()}};
    res.status = 200;
    res.set_content(res_json.dump(), k_content_type_json);
}

void AuthProxyHandler::handle_get_me(const httplib::Request& req, httplib::Response& res,
                                     const AuthenticatedContext& ctx) {
    const auto start_tp = deadline_manager_->now();
    const std::string request_id = extract_request_id(req);

    auto bulkhead_lease = bulkhead_manager_->acquire(WorkloadCategory::Auth);
    if (!bulkhead_lease) {
        BulkheadManager::write_rejection(res, request_id);
        return;
    }

    const auto service_timeout = std::chrono::milliseconds(deadline_manager_->config().auth_timeout_ms);
    const auto effective_deadline = deadline_manager_->compute_effective_deadline(req, service_timeout);

    if (!deadline_manager_->has_sufficient_budget(start_tp, effective_deadline)) {
        ErrorMapper::write_error(res, 504, "GATEWAY_TIMEOUT", "Request deadline exceeded before dispatch", request_id);
        return;
    }

    const std::string& user_id = ctx.user_id();
    if (user_id.empty()) {
        ErrorMapper::write_error(res, 401, "UNAUTHORIZED", "Unauthenticated context", request_id);
        return;
    }

    securecloud::auth::v1::GetUserRequest user_req;
    user_req.set_user_id(user_id);

    auto rpc_res = retry_policy_->execute(*deadline_manager_, start_tp, effective_deadline, service_timeout,
                                          OperationIdempotency::SAFE_READONLY,
                                          [this, &user_req, &request_id](std::chrono::milliseconds budget) {
                                              grpc::ClientCallContext call_ctx(request_id, budget);
                                              ActiveCallGuard guard(*this, request_id, call_ctx);
                                              return auth_client_->get_user(user_req, call_ctx);
                                          });

    if (!rpc_res) {
        const auto& err = rpc_res.error();
        int http_status = ErrorMapper::grpc_to_http_status(err.grpc_code);
        std::string error_code(ErrorMapper::grpc_to_error_code(err.grpc_code));
        ErrorMapper::write_error(res, http_status, error_code, err.message, request_id);
        return;
    }

    const auto& user = rpc_res.value().user();
    nlohmann::json res_json = {{"user",
                                {{"user_id", user.user_id()},
                                 {"credential_identifier", user.credential_identifier()},
                                 {"account_status", static_cast<int>(user.account_status())},
                                 {"created_at_epoch_ms", user.created_at_epoch_ms()},
                                 {"updated_at_epoch_ms", user.updated_at_epoch_ms()}}}};

    res.status = 200;
    res.set_content(res_json.dump(), k_content_type_json);
}

void AuthProxyHandler::handle_register_device(const httplib::Request& req, httplib::Response& res,
                                              const AuthenticatedContext& ctx) {
    const auto start_tp = deadline_manager_->now();
    const std::string request_id = extract_request_id(req);

    auto bulkhead_lease = bulkhead_manager_->acquire(WorkloadCategory::Auth);
    if (!bulkhead_lease) {
        BulkheadManager::write_rejection(res, request_id);
        return;
    }

    const auto service_timeout = std::chrono::milliseconds(deadline_manager_->config().auth_timeout_ms);
    const auto effective_deadline = deadline_manager_->compute_effective_deadline(req, service_timeout);

    if (!deadline_manager_->has_sufficient_budget(start_tp, effective_deadline)) {
        ErrorMapper::write_error(res, 504, "GATEWAY_TIMEOUT", "Request deadline exceeded before dispatch", request_id);
        return;
    }

    if (ctx.user_id().empty()) {
        ErrorMapper::write_error(res, 401, "UNAUTHORIZED", "Unauthenticated context", request_id);
        return;
    }

    nlohmann::json body;
    try {
        body = nlohmann::json::parse(req.body);
    } catch (const nlohmann::json::exception&) {
        ErrorMapper::write_error(res, 400, "BAD_REQUEST", "Malformed JSON request body", request_id);
        return;
    }

    if (!body.is_object()) {
        ErrorMapper::write_error(res, 400, "BAD_REQUEST", "Request body must be a JSON object", request_id);
        return;
    }

    securecloud::auth::v1::RegisterDeviceRequest dev_req;
    dev_req.set_user_id(ctx.user_id());

    if (body.contains("identity_key") && body["identity_key"].is_string()) {
        dev_req.set_identity_key(body["identity_key"].get<std::string>());
    }
    if (body.contains("signed_prekey") && body["signed_prekey"].is_string()) {
        dev_req.set_signed_prekey(body["signed_prekey"].get<std::string>());
    }
    if (body.contains("signed_prekey_signature") && body["signed_prekey_signature"].is_string()) {
        dev_req.set_signed_prekey_signature(body["signed_prekey_signature"].get<std::string>());
    }
    if (body.contains("one_time_prekeys") && body["one_time_prekeys"].is_array()) {
        for (const auto& item : body["one_time_prekeys"]) {
            if (item.is_string()) {
                dev_req.add_one_time_prekeys(item.get<std::string>());
            }
        }
    }

    auto rpc_res = retry_policy_->execute(*deadline_manager_, start_tp, effective_deadline, service_timeout,
                                          OperationIdempotency::NON_IDEMPOTENT,
                                          [this, &dev_req, &request_id](std::chrono::milliseconds budget) {
                                              grpc::ClientCallContext call_ctx(request_id, budget);
                                              ActiveCallGuard guard(*this, request_id, call_ctx);
                                              return auth_client_->register_device(dev_req, call_ctx);
                                          });

    if (!rpc_res) {
        const auto& err = rpc_res.error();
        int http_status = ErrorMapper::grpc_to_http_status(err.grpc_code);
        std::string error_code(ErrorMapper::grpc_to_error_code(err.grpc_code));
        ErrorMapper::write_error(res, http_status, error_code, err.message, request_id);
        return;
    }

    const auto& val = rpc_res.value();
    nlohmann::json res_json = {{"device_id", val.device_id()},
                               {"status", static_cast<int>(val.status())},
                               {"registered_at_epoch_ms", val.registered_at_epoch_ms()}};

    res.status = 201;
    res.set_content(res_json.dump(), k_content_type_json);
}

} // namespace securecloud::gateway::http
