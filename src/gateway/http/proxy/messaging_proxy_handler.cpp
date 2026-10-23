#include "http/proxy/messaging_proxy_handler.hpp"

#include "http/auth/request_context.hpp"
#include "http/errors/error_mapper.hpp"
#include "http/routing/router.hpp"

#include <chrono>
#include <httplib.h>
#include <nlohmann/json.hpp>
#include <utility>

namespace securecloud::gateway::http {
namespace {

constexpr const char* k_content_type_json = "application/json";

nlohmann::json conversation_metadata_to_json(const securecloud::messaging::v1::ConversationMetadata& meta) {
    nlohmann::json j;
    j["conversation_id"] = meta.conversation_id();
    j["type"] = (meta.type() == securecloud::messaging::v1::CONVERSATION_TYPE_DIRECT) ? "direct" : "group";
    j["title"] = meta.title();
    j["creator_user_id"] = meta.creator_user_id();
    j["created_at_unix_ms"] = meta.created_at_unix_ms();
    j["participant_user_ids"] = nlohmann::json::array();
    for (const auto& uid : meta.participant_user_ids()) {
        j["participant_user_ids"].push_back(uid);
    }
    return j;
}

std::string delivery_state_to_string(securecloud::messaging::v1::DeliveryState state) {
    switch (state) {
    case securecloud::messaging::v1::DELIVERY_STATE_QUEUED:
        return "QUEUED";
    case securecloud::messaging::v1::DELIVERY_STATE_DELIVERING:
        return "DELIVERING";
    case securecloud::messaging::v1::DELIVERY_STATE_DELIVERED:
        return "DELIVERED";
    case securecloud::messaging::v1::DELIVERY_STATE_RETRY_WAIT:
        return "RETRY_WAIT";
    case securecloud::messaging::v1::DELIVERY_STATE_EXPIRED:
        return "EXPIRED";
    default:
        return "UNSPECIFIED";
    }
}

std::string priority_to_string(securecloud::messaging::v1::MessagePriority priority) {
    switch (priority) {
    case securecloud::messaging::v1::MESSAGE_PRIORITY_URGENT:
        return "urgent";
    case securecloud::messaging::v1::MESSAGE_PRIORITY_EMERGENCY:
        return "emergency";
    case securecloud::messaging::v1::MESSAGE_PRIORITY_NORMAL:
    default:
        return "normal";
    }
}

nlohmann::json message_envelope_to_json(const securecloud::messaging::v1::MessageEnvelope& env) {
    nlohmann::json j;
    j["message_id"] = env.message_id();
    j["conversation_id"] = env.conversation_id();
    j["sender_user_id"] = env.sender_user_id();
    j["sender_device_id"] = env.sender_device_id();
    j["priority"] = priority_to_string(env.priority());
    j["created_at_unix_ms"] = env.created_at_unix_ms();
    j["expires_at_unix_ms"] = env.expires_at_unix_ms();
    j["client_idempotency_token"] = env.client_idempotency_token();

    nlohmann::json targets = nlohmann::json::array();
    for (const auto& target : env.delivery_targets()) {
        nlohmann::json t_json;
        t_json["recipient_user_id"] = target.recipient_user_id();
        t_json["recipient_device_id"] = target.recipient_device_id();
        t_json["state"] = delivery_state_to_string(target.state());
        t_json["updated_at_unix_ms"] = target.updated_at_unix_ms();

        if (target.has_encrypted_payload()) {
            const auto& ep = target.encrypted_payload();
            nlohmann::json ep_json;
            ep_json["ciphertext_blob"] = ep.ciphertext_blob();
            ep_json["ephemeral_public_key"] = ep.ephemeral_public_key();
            ep_json["initialization_vector"] = ep.initialization_vector();
            ep_json["auth_tag"] = ep.auth_tag();
            ep_json["algorithm"] = ep.algorithm();
            t_json["encrypted_payload"] = ep_json;
        }
        targets.push_back(t_json);
    }
    j["delivery_targets"] = targets;
    return j;
}

nlohmann::json sync_cursor_to_json(const securecloud::messaging::v1::SyncCursor& cursor) {
    nlohmann::json j;
    j["device_id"] = cursor.device_id();
    j["conversation_id"] = cursor.conversation_id();
    j["last_delivered_sequence"] = cursor.last_delivered_sequence();
    j["last_sync_timestamp_unix_ms"] = cursor.last_sync_timestamp_unix_ms();
    return j;
}

} // namespace

MessagingProxyHandler::MessagingProxyHandler(std::shared_ptr<grpc::IMessagingClient> messaging_client,
                                             std::shared_ptr<DeadlineManager> deadline_manager,
                                             std::shared_ptr<RetryPolicy> retry_policy,
                                             std::shared_ptr<BulkheadManager> bulkhead_manager,
                                             std::shared_ptr<CircuitBreaker> circuit_breaker)
    : messaging_client_(std::move(messaging_client)), deadline_manager_(std::move(deadline_manager)),
      retry_policy_(std::move(retry_policy)), bulkhead_manager_(std::move(bulkhead_manager)),
      circuit_breaker_(std::move(circuit_breaker)) {}

std::string MessagingProxyHandler::extract_request_id(const httplib::Request& req) {
    if (const auto* rc = RequestContext::current()) {
        return rc->request_id();
    }
    if (req.has_header("X-Request-ID")) {
        return req.get_header_value("X-Request-ID");
    }
    if (req.has_header("X-Request-Id")) {
        return req.get_header_value("X-Request-Id");
    }
    if (req.has_header("x-request-id")) {
        return req.get_header_value("x-request-id");
    }
    return "";
}

std::chrono::milliseconds MessagingProxyHandler::compute_timeout(const httplib::Request& req) const {
    if (deadline_manager_) {
        return deadline_manager_->compute_effective_deadline(req, std::chrono::milliseconds(5000));
    }
    return std::chrono::milliseconds(5000);
}

void MessagingProxyHandler::write_grpc_error(httplib::Response& res, const grpc::DependencyError& error,
                                             const std::string& request_id) const {
    int http_status = 500;
    std::string code = "INTERNAL_ERROR";
    switch (error.kind) {
    case grpc::DependencyErrorKind::InvalidArgument:
        http_status = 400;
        code = "INVALID_ARGUMENT";
        break;
    case grpc::DependencyErrorKind::Unauthenticated:
        http_status = 401;
        code = "UNAUTHENTICATED";
        break;
    case grpc::DependencyErrorKind::PermissionDenied:
        http_status = 403;
        code = "PERMISSION_DENIED";
        break;
    case grpc::DependencyErrorKind::NotFound:
        http_status = 404;
        code = "NOT_FOUND";
        break;
    case grpc::DependencyErrorKind::Timeout:
        http_status = 504;
        code = "DEADLINE_EXCEEDED";
        break;
    case grpc::DependencyErrorKind::ServiceUnavailable:
        http_status = 503;
        code = "SERVICE_UNAVAILABLE";
        break;
    default:
        if (error.grpc_code == ::grpc::StatusCode::ALREADY_EXISTS) {
            http_status = 409;
            code = "CONFLICT";
        } else if (error.grpc_code == ::grpc::StatusCode::RESOURCE_EXHAUSTED) {
            http_status = 429;
            code = "RESOURCE_EXHAUSTED";
        } else if (error.grpc_code == ::grpc::StatusCode::OUT_OF_RANGE) {
            http_status = 400;
            code = "OUT_OF_RANGE";
        } else if (error.grpc_code == ::grpc::StatusCode::FAILED_PRECONDITION) {
            http_status = 412;
            code = "FAILED_PRECONDITION";
        } else {
            http_status = 500;
            code = "DOWNSTREAM_ERROR";
        }
        break;
    }
    ErrorMapper::write_error(res, http_status, code, error.message, request_id);
}

void MessagingProxyHandler::register_routes(Router& router) {
    router.post_authenticated("/api/v1/messages", [this](const auto& req, auto& res, const auto& ctx) {
        handle_send_message(req, res, ctx);
    });

    router.post_authenticated("/api/v1/messages/send", [this](const auto& req, auto& res, const auto& ctx) {
        handle_send_message(req, res, ctx);
    });

    router.post_authenticated("/api/v1/messages/:id/ack", [this](const auto& req, auto& res, const auto& ctx) {
        handle_acknowledge_delivery(req, res, ctx);
    });

    // MSG-008 Read Receipts
    router.post_authenticated(
        "/api/v1/conversations/:conversationId/messages/:messageId/read",
        [this](const auto& req, auto& res, const auto& ctx) { handle_send_read_receipt(req, res, ctx); });
    router.post_authenticated(
        "/v1/conversations/:conversationId/messages/:messageId/read",
        [this](const auto& req, auto& res, const auto& ctx) { handle_send_read_receipt(req, res, ctx); });
    router.post_authenticated(
        "/api/v1/conversations/:conversation_id/messages/:message_id/read",
        [this](const auto& req, auto& res, const auto& ctx) { handle_send_read_receipt(req, res, ctx); });
    router.post_authenticated(
        "/v1/conversations/:conversation_id/messages/:message_id/read",
        [this](const auto& req, auto& res, const auto& ctx) { handle_send_read_receipt(req, res, ctx); });
    router.post_authenticated("/api/v1/messages/:id/read", [this](const auto& req, auto& res, const auto& ctx) {
        handle_send_read_receipt(req, res, ctx);
    });

    // MSG-008 Delivery Status Inspection
    router.get_authenticated(
        "/api/v1/conversations/:conversationId/messages/:messageId/delivery-status",
        [this](const auto& req, auto& res, const auto& ctx) { handle_get_delivery_status(req, res, ctx); });
    router.get_authenticated(
        "/v1/conversations/:conversationId/messages/:messageId/delivery-status",
        [this](const auto& req, auto& res, const auto& ctx) { handle_get_delivery_status(req, res, ctx); });
    router.get_authenticated(
        "/api/v1/conversations/:conversation_id/messages/:message_id/delivery-status",
        [this](const auto& req, auto& res, const auto& ctx) { handle_get_delivery_status(req, res, ctx); });
    router.get_authenticated(
        "/v1/conversations/:conversation_id/messages/:message_id/delivery-status",
        [this](const auto& req, auto& res, const auto& ctx) { handle_get_delivery_status(req, res, ctx); });
    router.get_authenticated(
        "/api/v1/messages/:id/delivery-status",
        [this](const auto& req, auto& res, const auto& ctx) { handle_get_delivery_status(req, res, ctx); });

    router.post_authenticated("/api/v1/conversations", [this](const auto& req, auto& res, const auto& ctx) {
        handle_create_conversation(req, res, ctx);
    });

    router.get_authenticated("/api/v1/conversations/:id", [this](const auto& req, auto& res, const auto& ctx) {
        handle_get_conversation(req, res, ctx);
    });

    router.get_authenticated("/api/v1/conversations", [this](const auto& req, auto& res, const auto& ctx) {
        handle_list_conversations(req, res, ctx);
    });

    router.post_authenticated(
        "/api/v1/conversations/:id/participants",
        [this](const auto& req, auto& res, const auto& ctx) { handle_add_participant(req, res, ctx); });

    router.del_authenticated(
        "/api/v1/conversations/:id/participants/:userId",
        [this](const auto& req, auto& res, const auto& ctx) { handle_remove_participant(req, res, ctx); });

    router.post_authenticated("/api/v1/conversations/:id/leave", [this](const auto& req, auto& res, const auto& ctx) {
        handle_leave_conversation(req, res, ctx);
    });

    router.add_authenticated_route(
        "PATCH", "/api/v1/conversations/:id/metadata",
        [this](const auto& req, auto& res, const auto& ctx) { handle_update_metadata(req, res, ctx); });

    // MSG-009 Message Synchronization and Resumption
    router.get_authenticated("/api/v1/conversations/:id/messages", [this](const auto& req, auto& res, const auto& ctx) {
        handle_sync_messages(req, res, ctx);
    });
    router.get_authenticated("/v1/conversations/:id/messages", [this](const auto& req, auto& res, const auto& ctx) {
        handle_sync_messages(req, res, ctx);
    });
    router.get_authenticated(
        "/api/v1/conversations/:conversationId/messages",
        [this](const auto& req, auto& res, const auto& ctx) { handle_sync_messages(req, res, ctx); });
    router.get_authenticated(
        "/v1/conversations/:conversationId/messages",
        [this](const auto& req, auto& res, const auto& ctx) { handle_sync_messages(req, res, ctx); });
    router.get_authenticated(
        "/api/v1/conversations/:conversation_id/messages",
        [this](const auto& req, auto& res, const auto& ctx) { handle_sync_messages(req, res, ctx); });
    router.get_authenticated(
        "/v1/conversations/:conversation_id/messages",
        [this](const auto& req, auto& res, const auto& ctx) { handle_sync_messages(req, res, ctx); });

    // MSG-009 Sync Cursor Management
    router.get_authenticated("/api/v1/devices/:deviceId/cursor", [this](const auto& req, auto& res, const auto& ctx) {
        handle_get_sync_cursor(req, res, ctx);
    });
    router.get_authenticated("/v1/devices/:deviceId/cursor", [this](const auto& req, auto& res, const auto& ctx) {
        handle_get_sync_cursor(req, res, ctx);
    });
    router.get_authenticated("/api/v1/devices/:device_id/cursor", [this](const auto& req, auto& res, const auto& ctx) {
        handle_get_sync_cursor(req, res, ctx);
    });
    router.get_authenticated("/v1/devices/:device_id/cursor", [this](const auto& req, auto& res, const auto& ctx) {
        handle_get_sync_cursor(req, res, ctx);
    });

    router.put_authenticated("/api/v1/devices/:deviceId/cursor", [this](const auto& req, auto& res, const auto& ctx) {
        handle_update_sync_cursor(req, res, ctx);
    });
    router.put_authenticated("/v1/devices/:deviceId/cursor", [this](const auto& req, auto& res, const auto& ctx) {
        handle_update_sync_cursor(req, res, ctx);
    });
    router.put_authenticated("/api/v1/devices/:device_id/cursor", [this](const auto& req, auto& res, const auto& ctx) {
        handle_update_sync_cursor(req, res, ctx);
    });
    router.put_authenticated("/v1/devices/:device_id/cursor", [this](const auto& req, auto& res, const auto& ctx) {
        handle_update_sync_cursor(req, res, ctx);
    });
}

// ============================================================================
// 1. handle_create_conversation
// ============================================================================

void MessagingProxyHandler::handle_create_conversation(const httplib::Request& req, httplib::Response& res,
                                                       const AuthenticatedContext& ctx) {
    const std::string request_id = extract_request_id(req);

    auto lease = bulkhead_manager_ ? bulkhead_manager_->acquire(WorkloadCategory::Messaging) : BulkheadLease{};
    if (bulkhead_manager_ && !lease) {
        BulkheadManager::write_rejection(res, request_id);
        return;
    }
    if (circuit_breaker_ && !circuit_breaker_->allow_request()) {
        CircuitBreaker::write_rejection(res, request_id);
        return;
    }

    nlohmann::json body;
    try {
        body = nlohmann::json::parse(req.body);
    } catch (const std::exception&) {
        ErrorMapper::write_error(res, 400, "INVALID_ARGUMENT", "Invalid JSON body", request_id);
        return;
    }

    securecloud::messaging::v1::CreateConversationRequest grpc_req;
    std::string type_str = body.value("type", "direct");
    if (type_str == "direct") {
        grpc_req.set_type(securecloud::messaging::v1::CONVERSATION_TYPE_DIRECT);
    } else if (type_str == "group") {
        grpc_req.set_type(securecloud::messaging::v1::CONVERSATION_TYPE_GROUP);
    } else {
        ErrorMapper::write_error(res, 400, "INVALID_ARGUMENT", "Unsupported conversation type", request_id);
        return;
    }

    grpc_req.set_title(body.value("title", ""));

    if (body.contains("participant_user_ids") && body["participant_user_ids"].is_array()) {
        for (const auto& uid : body["participant_user_ids"]) {
            if (uid.is_string()) {
                grpc_req.add_participant_user_ids(uid.get<std::string>());
            }
        }
    } else if (body.contains("recipient_user_id") && body["recipient_user_id"].is_string()) {
        grpc_req.add_participant_user_ids(body["recipient_user_id"].get<std::string>());
    }

    const auto timeout = compute_timeout(req);
    grpc::ClientCallContext call_ctx(timeout);
    call_ctx.add_metadata("x-user-id", ctx.user_id());
    call_ctx.add_metadata("x-device-id", ctx.device_id());
    call_ctx.add_metadata("x-correlation-id", request_id);

    if (req.has_header("X-Idempotency-Token")) {
        call_ctx.add_metadata("x-idempotency-token", req.get_header_value("X-Idempotency-Token"));
    } else if (req.has_header("x-idempotency-token")) {
        call_ctx.add_metadata("x-idempotency-token", req.get_header_value("x-idempotency-token"));
    }

    auto result = messaging_client_->create_conversation(grpc_req, call_ctx);
    if (circuit_breaker_) {
        if (result.has_value()) {
            circuit_breaker_->record_success();
        } else if (result.error().kind == grpc::DependencyErrorKind::ServiceUnavailable ||
                   result.error().kind == grpc::DependencyErrorKind::Timeout) {
            circuit_breaker_->record_failure();
        }
    }

    if (result.has_error()) {
        write_grpc_error(res, result.error(), request_id);
        return;
    }

    nlohmann::json response_body;
    response_body["conversation"] = conversation_metadata_to_json(result.value().conversation());
    res.status = 201;
    res.set_content(response_body.dump(), k_content_type_json);
}

// ============================================================================
// 2. handle_get_conversation
// ============================================================================

void MessagingProxyHandler::handle_get_conversation(const httplib::Request& req, httplib::Response& res,
                                                    const AuthenticatedContext& ctx) {
    const std::string request_id = extract_request_id(req);

    auto lease = bulkhead_manager_ ? bulkhead_manager_->acquire(WorkloadCategory::Messaging) : BulkheadLease{};
    if (bulkhead_manager_ && !lease) {
        BulkheadManager::write_rejection(res, request_id);
        return;
    }
    if (circuit_breaker_ && !circuit_breaker_->allow_request()) {
        CircuitBreaker::write_rejection(res, request_id);
        return;
    }

    std::string conv_id = Router::get_path_param(req, "id");
    if (conv_id.empty()) {
        ErrorMapper::write_error(res, 400, "INVALID_ARGUMENT", "Missing conversation ID", request_id);
        return;
    }

    securecloud::messaging::v1::GetConversationRequest grpc_req;
    grpc_req.set_conversation_id(conv_id);

    const auto timeout = compute_timeout(req);
    grpc::ClientCallContext call_ctx(timeout);
    call_ctx.add_metadata("x-user-id", ctx.user_id());
    call_ctx.add_metadata("x-device-id", ctx.device_id());
    call_ctx.add_metadata("x-correlation-id", request_id);

    auto result = messaging_client_->get_conversation(grpc_req, call_ctx);
    if (circuit_breaker_) {
        if (result.has_value()) {
            circuit_breaker_->record_success();
        } else if (result.error().kind == grpc::DependencyErrorKind::ServiceUnavailable ||
                   result.error().kind == grpc::DependencyErrorKind::Timeout) {
            circuit_breaker_->record_failure();
        }
    }

    if (result.has_error()) {
        write_grpc_error(res, result.error(), request_id);
        return;
    }

    nlohmann::json response_body;
    response_body["conversation"] = conversation_metadata_to_json(result.value().conversation());
    res.status = 200;
    res.set_content(response_body.dump(), k_content_type_json);
}

// ============================================================================
// 3. handle_list_conversations
// ============================================================================

void MessagingProxyHandler::handle_list_conversations(const httplib::Request& req, httplib::Response& res,
                                                      const AuthenticatedContext& ctx) {
    const std::string request_id = extract_request_id(req);

    auto lease = bulkhead_manager_ ? bulkhead_manager_->acquire(WorkloadCategory::Messaging) : BulkheadLease{};
    if (bulkhead_manager_ && !lease) {
        BulkheadManager::write_rejection(res, request_id);
        return;
    }
    if (circuit_breaker_ && !circuit_breaker_->allow_request()) {
        CircuitBreaker::write_rejection(res, request_id);
        return;
    }

    securecloud::messaging::v1::ListConversationsRequest grpc_req;
    grpc_req.set_user_id(ctx.user_id());

    if (req.has_param("limit")) {
        try {
            grpc_req.set_max_results(static_cast<uint32_t>(std::stoul(req.get_param_value("limit"))));
        } catch (...) {
        }
    } else if (req.has_param("max_results")) {
        try {
            grpc_req.set_max_results(static_cast<uint32_t>(std::stoul(req.get_param_value("max_results"))));
        } catch (...) {
        }
    }

    if (req.has_param("page_token")) {
        grpc_req.set_page_token(req.get_param_value("page_token"));
    }

    const auto timeout = compute_timeout(req);
    grpc::ClientCallContext call_ctx(timeout);
    call_ctx.add_metadata("x-user-id", ctx.user_id());
    call_ctx.add_metadata("x-device-id", ctx.device_id());
    call_ctx.add_metadata("x-correlation-id", request_id);

    auto result = messaging_client_->list_conversations(grpc_req, call_ctx);
    if (circuit_breaker_) {
        if (result.has_value()) {
            circuit_breaker_->record_success();
        } else if (result.error().kind == grpc::DependencyErrorKind::ServiceUnavailable ||
                   result.error().kind == grpc::DependencyErrorKind::Timeout) {
            circuit_breaker_->record_failure();
        }
    }

    if (result.has_error()) {
        write_grpc_error(res, result.error(), request_id);
        return;
    }

    nlohmann::json response_body;
    response_body["conversations"] = nlohmann::json::array();
    for (const auto& conv : result.value().conversations()) {
        response_body["conversations"].push_back(conversation_metadata_to_json(conv));
    }
    response_body["next_page_token"] = result.value().next_page_token();

    res.status = 200;
    res.set_content(response_body.dump(), k_content_type_json);
}

// ============================================================================
// 4. handle_add_participant
// ============================================================================

void MessagingProxyHandler::handle_add_participant(const httplib::Request& req, httplib::Response& res,
                                                   const AuthenticatedContext& ctx) {
    const std::string request_id = extract_request_id(req);

    auto lease = bulkhead_manager_ ? bulkhead_manager_->acquire(WorkloadCategory::Messaging) : BulkheadLease{};
    if (bulkhead_manager_ && !lease) {
        BulkheadManager::write_rejection(res, request_id);
        return;
    }
    if (circuit_breaker_ && !circuit_breaker_->allow_request()) {
        CircuitBreaker::write_rejection(res, request_id);
        return;
    }

    std::string conv_id = Router::get_path_param(req, "id");
    if (conv_id.empty()) {
        ErrorMapper::write_error(res, 400, "INVALID_ARGUMENT", "Missing conversation ID", request_id);
        return;
    }

    nlohmann::json body;
    try {
        body = nlohmann::json::parse(req.body);
    } catch (const std::exception&) {
        ErrorMapper::write_error(res, 400, "INVALID_ARGUMENT", "Invalid JSON body", request_id);
        return;
    }

    std::string participant_user_id = body.value("participant_user_id", body.value("userId", ""));
    if (participant_user_id.empty()) {
        ErrorMapper::write_error(res, 400, "INVALID_ARGUMENT", "Missing participant user ID", request_id);
        return;
    }

    securecloud::messaging::v1::AddParticipantRequest grpc_req;
    grpc_req.set_conversation_id(conv_id);
    grpc_req.set_participant_user_id(participant_user_id);

    const auto timeout = compute_timeout(req);
    grpc::ClientCallContext call_ctx(timeout);
    call_ctx.add_metadata("x-user-id", ctx.user_id());
    call_ctx.add_metadata("x-device-id", ctx.device_id());
    call_ctx.add_metadata("x-correlation-id", request_id);

    auto result = messaging_client_->add_participant(grpc_req, call_ctx);
    if (circuit_breaker_) {
        if (result.has_value()) {
            circuit_breaker_->record_success();
        } else if (result.error().kind == grpc::DependencyErrorKind::ServiceUnavailable ||
                   result.error().kind == grpc::DependencyErrorKind::Timeout) {
            circuit_breaker_->record_failure();
        }
    }

    if (result.has_error()) {
        write_grpc_error(res, result.error(), request_id);
        return;
    }

    nlohmann::json response_body;
    response_body["conversation_id"] = result.value().conversation_id();
    response_body["participant_user_id"] = result.value().participant_user_id();
    response_body["total_participants"] = result.value().total_participants();

    res.status = 200;
    res.set_content(response_body.dump(), k_content_type_json);
}

// ============================================================================
// 5. handle_remove_participant
// ============================================================================

void MessagingProxyHandler::handle_remove_participant(const httplib::Request& req, httplib::Response& res,
                                                      const AuthenticatedContext& ctx) {
    const std::string request_id = extract_request_id(req);

    auto lease = bulkhead_manager_ ? bulkhead_manager_->acquire(WorkloadCategory::Messaging) : BulkheadLease{};
    if (bulkhead_manager_ && !lease) {
        BulkheadManager::write_rejection(res, request_id);
        return;
    }
    if (circuit_breaker_ && !circuit_breaker_->allow_request()) {
        CircuitBreaker::write_rejection(res, request_id);
        return;
    }

    std::string conv_id = Router::get_path_param(req, "id");
    std::string user_id = Router::get_path_param(req, "userId");

    if (conv_id.empty() || user_id.empty()) {
        ErrorMapper::write_error(res, 400, "INVALID_ARGUMENT", "Missing conversation ID or user ID parameter",
                                 request_id);
        return;
    }

    securecloud::messaging::v1::RemoveParticipantRequest grpc_req;
    grpc_req.set_conversation_id(conv_id);
    grpc_req.set_participant_user_id(user_id);

    const auto timeout = compute_timeout(req);
    grpc::ClientCallContext call_ctx(timeout);
    call_ctx.add_metadata("x-user-id", ctx.user_id());
    call_ctx.add_metadata("x-device-id", ctx.device_id());
    call_ctx.add_metadata("x-correlation-id", request_id);

    auto result = messaging_client_->remove_participant(grpc_req, call_ctx);
    if (circuit_breaker_) {
        if (result.has_value()) {
            circuit_breaker_->record_success();
        } else if (result.error().kind == grpc::DependencyErrorKind::ServiceUnavailable ||
                   result.error().kind == grpc::DependencyErrorKind::Timeout) {
            circuit_breaker_->record_failure();
        }
    }

    if (result.has_error()) {
        write_grpc_error(res, result.error(), request_id);
        return;
    }

    nlohmann::json response_body;
    response_body["conversation_id"] = result.value().conversation_id();
    response_body["participant_user_id"] = result.value().participant_user_id();
    response_body["total_participants"] = result.value().total_participants();

    res.status = 200;
    res.set_content(response_body.dump(), k_content_type_json);
}

// ============================================================================
// 6. handle_leave_conversation
// ============================================================================

void MessagingProxyHandler::handle_leave_conversation(const httplib::Request& req, httplib::Response& res,
                                                      const AuthenticatedContext& ctx) {
    const std::string request_id = extract_request_id(req);

    auto lease = bulkhead_manager_ ? bulkhead_manager_->acquire(WorkloadCategory::Messaging) : BulkheadLease{};
    if (bulkhead_manager_ && !lease) {
        BulkheadManager::write_rejection(res, request_id);
        return;
    }
    if (circuit_breaker_ && !circuit_breaker_->allow_request()) {
        CircuitBreaker::write_rejection(res, request_id);
        return;
    }

    std::string conv_id = Router::get_path_param(req, "id");
    if (conv_id.empty()) {
        ErrorMapper::write_error(res, 400, "INVALID_ARGUMENT", "Missing conversation ID", request_id);
        return;
    }

    securecloud::messaging::v1::LeaveConversationRequest grpc_req;
    grpc_req.set_conversation_id(conv_id);

    const auto timeout = compute_timeout(req);
    grpc::ClientCallContext call_ctx(timeout);
    call_ctx.add_metadata("x-user-id", ctx.user_id());
    call_ctx.add_metadata("x-device-id", ctx.device_id());
    call_ctx.add_metadata("x-correlation-id", request_id);

    auto result = messaging_client_->leave_conversation(grpc_req, call_ctx);
    if (circuit_breaker_) {
        if (result.has_value()) {
            circuit_breaker_->record_success();
        } else if (result.error().kind == grpc::DependencyErrorKind::ServiceUnavailable ||
                   result.error().kind == grpc::DependencyErrorKind::Timeout) {
            circuit_breaker_->record_failure();
        }
    }

    if (result.has_error()) {
        write_grpc_error(res, result.error(), request_id);
        return;
    }

    nlohmann::json response_body;
    response_body["conversation_id"] = result.value().conversation_id();
    response_body["success"] = result.value().success();

    res.status = 200;
    res.set_content(response_body.dump(), k_content_type_json);
}

// ============================================================================
// 7. handle_update_metadata
// ============================================================================

void MessagingProxyHandler::handle_update_metadata(const httplib::Request& req, httplib::Response& res,
                                                   const AuthenticatedContext& ctx) {
    const std::string request_id = extract_request_id(req);

    auto lease = bulkhead_manager_ ? bulkhead_manager_->acquire(WorkloadCategory::Messaging) : BulkheadLease{};
    if (bulkhead_manager_ && !lease) {
        BulkheadManager::write_rejection(res, request_id);
        return;
    }
    if (circuit_breaker_ && !circuit_breaker_->allow_request()) {
        CircuitBreaker::write_rejection(res, request_id);
        return;
    }

    std::string conv_id = Router::get_path_param(req, "id");
    if (conv_id.empty()) {
        ErrorMapper::write_error(res, 400, "INVALID_ARGUMENT", "Missing conversation ID", request_id);
        return;
    }

    nlohmann::json body;
    try {
        body = nlohmann::json::parse(req.body);
    } catch (const std::exception&) {
        ErrorMapper::write_error(res, 400, "INVALID_ARGUMENT", "Invalid JSON body", request_id);
        return;
    }

    std::string title = body.value("title", "");

    securecloud::messaging::v1::UpdateConversationMetadataRequest grpc_req;
    grpc_req.set_conversation_id(conv_id);
    grpc_req.set_title(title);

    const auto timeout = compute_timeout(req);
    grpc::ClientCallContext call_ctx(timeout);
    call_ctx.add_metadata("x-user-id", ctx.user_id());
    call_ctx.add_metadata("x-device-id", ctx.device_id());
    call_ctx.add_metadata("x-correlation-id", request_id);

    auto result = messaging_client_->update_conversation_metadata(grpc_req, call_ctx);
    if (circuit_breaker_) {
        if (result.has_value()) {
            circuit_breaker_->record_success();
        } else if (result.error().kind == grpc::DependencyErrorKind::ServiceUnavailable ||
                   result.error().kind == grpc::DependencyErrorKind::Timeout) {
            circuit_breaker_->record_failure();
        }
    }

    if (result.has_error()) {
        write_grpc_error(res, result.error(), request_id);
        return;
    }

    nlohmann::json response_body;
    response_body["conversation"] = conversation_metadata_to_json(result.value().conversation());

    res.status = 200;
    res.set_content(response_body.dump(), k_content_type_json);
}

// ============================================================================
// 8. handle_send_message
// ============================================================================

void MessagingProxyHandler::handle_send_message(const httplib::Request& req, httplib::Response& res,
                                                const AuthenticatedContext& ctx) {
    const std::string request_id = extract_request_id(req);

    auto lease = bulkhead_manager_ ? bulkhead_manager_->acquire(WorkloadCategory::Messaging) : BulkheadLease{};
    if (bulkhead_manager_ && !lease) {
        BulkheadManager::write_rejection(res, request_id);
        return;
    }
    if (circuit_breaker_ && !circuit_breaker_->allow_request()) {
        CircuitBreaker::write_rejection(res, request_id);
        return;
    }

    nlohmann::json body;
    try {
        body = nlohmann::json::parse(req.body);
    } catch (const std::exception&) {
        ErrorMapper::write_error(res, 400, "INVALID_ARGUMENT", "Invalid JSON body", request_id);
        return;
    }

    securecloud::messaging::v1::SendMessageRequest grpc_req;
    grpc_req.set_conversation_id(body.value("conversation_id", ""));
    grpc_req.set_sender_device_id(body.value("sender_device_id", ctx.device_id()));

    std::string idempotency_token;
    if (body.contains("idempotency_token") && body["idempotency_token"].is_string()) {
        idempotency_token = body["idempotency_token"].get<std::string>();
    } else if (body.contains("client_idempotency_token") && body["client_idempotency_token"].is_string()) {
        idempotency_token = body["client_idempotency_token"].get<std::string>();
    } else if (req.has_header("X-Idempotency-Token")) {
        idempotency_token = req.get_header_value("X-Idempotency-Token");
    } else if (req.has_header("x-idempotency-token")) {
        idempotency_token = req.get_header_value("x-idempotency-token");
    }
    grpc_req.set_client_idempotency_token(idempotency_token);

    if (body.contains("priority")) {
        if (body["priority"].is_string()) {
            std::string p = body["priority"].get<std::string>();
            if (p == "urgent") {
                grpc_req.set_priority(securecloud::messaging::v1::MESSAGE_PRIORITY_URGENT);
            } else if (p == "emergency") {
                grpc_req.set_priority(securecloud::messaging::v1::MESSAGE_PRIORITY_EMERGENCY);
            } else {
                grpc_req.set_priority(securecloud::messaging::v1::MESSAGE_PRIORITY_NORMAL);
            }
        } else if (body["priority"].is_number_integer()) {
            grpc_req.set_priority(
                static_cast<securecloud::messaging::v1::MessagePriority>(body["priority"].get<int>()));
        }
    } else {
        grpc_req.set_priority(securecloud::messaging::v1::MESSAGE_PRIORITY_NORMAL);
    }

    if (body.contains("expires_at_unix_ms") && body["expires_at_unix_ms"].is_number_integer()) {
        grpc_req.set_expires_at_unix_ms(body["expires_at_unix_ms"].get<int64_t>());
    }

    if (body.contains("delivery_targets") && body["delivery_targets"].is_array()) {
        for (const auto& dt_json : body["delivery_targets"]) {
            if (!dt_json.is_object()) {
                continue;
            }
            auto* target = grpc_req.add_delivery_targets();
            target->set_recipient_user_id(dt_json.value("recipient_user_id", ""));
            target->set_recipient_device_id(dt_json.value("recipient_device_id", ""));

            if (dt_json.contains("encrypted_payload") && dt_json["encrypted_payload"].is_object()) {
                const auto& ep_json = dt_json["encrypted_payload"];
                auto* ep = target->mutable_encrypted_payload();
                ep->set_ciphertext_blob(ep_json.value("ciphertext_blob", ""));
                ep->set_ephemeral_public_key(ep_json.value("ephemeral_public_key", ""));
                ep->set_initialization_vector(ep_json.value("initialization_vector", ""));
                ep->set_auth_tag(ep_json.value("auth_tag", ""));
                ep->set_algorithm(ep_json.value("algorithm", "XChaCha20-Poly1305"));
            }
        }
    }

    const auto timeout = compute_timeout(req);
    grpc::ClientCallContext call_ctx(timeout);
    call_ctx.add_metadata("x-user-id", ctx.user_id());
    call_ctx.add_metadata("x-device-id", ctx.device_id());
    call_ctx.add_metadata("x-correlation-id", request_id);
    if (!idempotency_token.empty()) {
        call_ctx.add_metadata("x-idempotency-token", idempotency_token);
    }

    auto result = messaging_client_->send_message(grpc_req, call_ctx);
    if (circuit_breaker_) {
        if (result.has_value()) {
            circuit_breaker_->record_success();
        } else if (result.error().kind == grpc::DependencyErrorKind::ServiceUnavailable ||
                   result.error().kind == grpc::DependencyErrorKind::Timeout) {
            circuit_breaker_->record_failure();
        }
    }

    if (result.has_error()) {
        write_grpc_error(res, result.error(), request_id);
        return;
    }

    nlohmann::json response_body;
    response_body["message_id"] = result.value().message_id();
    response_body["conversation_id"] = result.value().conversation_id();
    response_body["accepted_at_unix_ms"] = result.value().accepted_at_unix_ms();
    response_body["initial_state"] = "QUEUED";
    response_body["target_count"] = result.value().target_count();

    res.status = 201;
    res.set_content(response_body.dump(), k_content_type_json);
}

// ============================================================================
// 9. handle_acknowledge_delivery
// ============================================================================

void MessagingProxyHandler::handle_acknowledge_delivery(const httplib::Request& req, httplib::Response& res,
                                                        const AuthenticatedContext& ctx) {
    const std::string request_id = extract_request_id(req);

    auto lease = bulkhead_manager_ ? bulkhead_manager_->acquire(WorkloadCategory::Messaging) : BulkheadLease{};
    if (bulkhead_manager_ && !lease) {
        BulkheadManager::write_rejection(res, request_id);
        return;
    }
    if (circuit_breaker_ && !circuit_breaker_->allow_request()) {
        CircuitBreaker::write_rejection(res, request_id);
        return;
    }

    std::string message_id = Router::get_path_param(req, "id");
    if (message_id.empty()) {
        ErrorMapper::write_error(res, 400, "INVALID_ARGUMENT", "Missing message ID", request_id);
        return;
    }

    std::string recipient_device_id = ctx.device_id();
    int64_t delivered_at_ms = 0;

    if (!req.body.empty()) {
        try {
            auto body = nlohmann::json::parse(req.body);
            if (body.contains("device_id") && body["device_id"].is_string()) {
                recipient_device_id = body["device_id"].get<std::string>();
            } else if (body.contains("recipient_device_id") && body["recipient_device_id"].is_string()) {
                recipient_device_id = body["recipient_device_id"].get<std::string>();
            }
            if (body.contains("delivered_at_unix_ms") && body["delivered_at_unix_ms"].is_number_integer()) {
                delivered_at_ms = body["delivered_at_unix_ms"].get<int64_t>();
            }
        } catch (const std::exception&) {
            ErrorMapper::write_error(res, 400, "INVALID_ARGUMENT", "Invalid JSON body", request_id);
            return;
        }
    }

    if (delivered_at_ms <= 0) {
        delivered_at_ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
                .count();
    }

    securecloud::messaging::v1::AcknowledgeDeliveryRequest grpc_req;
    grpc_req.set_message_id(message_id);
    grpc_req.set_recipient_device_id(recipient_device_id);
    grpc_req.set_delivered_at_unix_ms(delivered_at_ms);

    const auto timeout = compute_timeout(req);
    grpc::ClientCallContext call_ctx(timeout);
    call_ctx.add_metadata("x-user-id", ctx.user_id());
    call_ctx.add_metadata("x-device-id", ctx.device_id());
    call_ctx.add_metadata("x-correlation-id", request_id);

    auto result = messaging_client_->acknowledge_delivery(grpc_req, call_ctx);
    if (circuit_breaker_) {
        if (result.has_value()) {
            circuit_breaker_->record_success();
        } else if (result.error().kind == grpc::DependencyErrorKind::ServiceUnavailable ||
                   result.error().kind == grpc::DependencyErrorKind::Timeout) {
            circuit_breaker_->record_failure();
        }
    }

    if (result.has_error()) {
        write_grpc_error(res, result.error(), request_id);
        return;
    }

    nlohmann::json response_body;
    response_body["message_id"] = result.value().message_id();
    response_body["state"] = "DELIVERED";
    response_body["recorded_at_unix_ms"] = result.value().recorded_at_unix_ms();

    res.status = 200;
    res.set_content(response_body.dump(), k_content_type_json);
}

// ============================================================================
// 10. handle_send_read_receipt (MSG-008)
// ============================================================================

void MessagingProxyHandler::handle_send_read_receipt(const httplib::Request& req, httplib::Response& res,
                                                     const AuthenticatedContext& ctx) {
    const std::string request_id = extract_request_id(req);

    auto lease = bulkhead_manager_ ? bulkhead_manager_->acquire(WorkloadCategory::Messaging) : BulkheadLease{};
    if (bulkhead_manager_ && !lease) {
        BulkheadManager::write_rejection(res, request_id);
        return;
    }
    if (circuit_breaker_ && !circuit_breaker_->allow_request()) {
        CircuitBreaker::write_rejection(res, request_id);
        return;
    }

    std::string message_id = Router::get_path_param(req, "message_id");
    if (message_id.empty()) {
        message_id = Router::get_path_param(req, "messageId");
    }
    std::string conversation_id = Router::get_path_param(req, "conversation_id");
    if (conversation_id.empty()) {
        conversation_id = Router::get_path_param(req, "conversationId");
    }

    if (message_id.empty()) {
        message_id = Router::get_path_param(req, "id");
    } else if (conversation_id.empty()) {
        conversation_id = Router::get_path_param(req, "id");
    }

    std::string reader_device_id = ctx.device_id();
    int64_t read_at_ms = 0;

    if (!req.body.empty()) {
        try {
            auto body = nlohmann::json::parse(req.body);
            if (body.contains("reader_device_id") && body["reader_device_id"].is_string()) {
                reader_device_id = body["reader_device_id"].get<std::string>();
            } else if (body.contains("device_id") && body["device_id"].is_string()) {
                reader_device_id = body["device_id"].get<std::string>();
            }
            if (body.contains("conversation_id") && body["conversation_id"].is_string() && conversation_id.empty()) {
                conversation_id = body["conversation_id"].get<std::string>();
            }
            if (body.contains("read_at_unix_ms") && body["read_at_unix_ms"].is_number_integer()) {
                read_at_ms = body["read_at_unix_ms"].get<int64_t>();
            }
        } catch (const std::exception&) {
            ErrorMapper::write_error(res, 400, "INVALID_ARGUMENT", "Invalid JSON body", request_id);
            return;
        }
    }

    if (conversation_id.empty() && req.has_param("conversation_id")) {
        conversation_id = req.get_param_value("conversation_id");
    }

    if (message_id.empty()) {
        ErrorMapper::write_error(res, 400, "INVALID_ARGUMENT", "Missing message ID", request_id);
        return;
    }

    if (read_at_ms <= 0) {
        read_at_ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
                .count();
    }

    securecloud::messaging::v1::SendReadReceiptRequest grpc_req;
    grpc_req.set_conversation_id(conversation_id);
    grpc_req.set_message_id(message_id);
    grpc_req.set_reader_device_id(reader_device_id);
    grpc_req.set_read_at_unix_ms(read_at_ms);

    const auto timeout = compute_timeout(req);
    grpc::ClientCallContext call_ctx(timeout);
    call_ctx.add_metadata("x-user-id", ctx.user_id());
    call_ctx.add_metadata("x-device-id", ctx.device_id());
    call_ctx.add_metadata("x-correlation-id", request_id);

    auto result = messaging_client_->send_read_receipt(grpc_req, call_ctx);
    if (circuit_breaker_) {
        if (result.has_value()) {
            circuit_breaker_->record_success();
        } else if (result.error().kind == grpc::DependencyErrorKind::ServiceUnavailable ||
                   result.error().kind == grpc::DependencyErrorKind::Timeout) {
            circuit_breaker_->record_failure();
        }
    }

    if (result.has_error()) {
        write_grpc_error(res, result.error(), request_id);
        return;
    }

    nlohmann::json response_body;
    response_body["message_id"] = result.value().message_id();
    response_body["state"] = "READ";
    response_body["recorded_at_unix_ms"] = result.value().recorded_at_unix_ms();

    res.status = 200;
    res.set_content(response_body.dump(), k_content_type_json);
}

// ============================================================================
// 11. handle_get_delivery_status (MSG-008)
// ============================================================================

void MessagingProxyHandler::handle_get_delivery_status(const httplib::Request& req, httplib::Response& res,
                                                       const AuthenticatedContext& ctx) {
    const std::string request_id = extract_request_id(req);

    auto lease = bulkhead_manager_ ? bulkhead_manager_->acquire(WorkloadCategory::Messaging) : BulkheadLease{};
    if (bulkhead_manager_ && !lease) {
        BulkheadManager::write_rejection(res, request_id);
        return;
    }
    if (circuit_breaker_ && !circuit_breaker_->allow_request()) {
        CircuitBreaker::write_rejection(res, request_id);
        return;
    }

    std::string message_id = Router::get_path_param(req, "message_id");
    if (message_id.empty()) {
        message_id = Router::get_path_param(req, "messageId");
    }
    std::string conversation_id = Router::get_path_param(req, "conversation_id");
    if (conversation_id.empty()) {
        conversation_id = Router::get_path_param(req, "conversationId");
    }

    if (message_id.empty()) {
        message_id = Router::get_path_param(req, "id");
    } else if (conversation_id.empty()) {
        conversation_id = Router::get_path_param(req, "id");
    }

    if (conversation_id.empty() && req.has_param("conversation_id")) {
        conversation_id = req.get_param_value("conversation_id");
    }

    if (message_id.empty()) {
        ErrorMapper::write_error(res, 400, "INVALID_ARGUMENT", "Missing message ID", request_id);
        return;
    }

    securecloud::messaging::v1::GetMessageDeliveryStatusRequest grpc_req;
    grpc_req.set_conversation_id(conversation_id);
    grpc_req.set_message_id(message_id);

    const auto timeout = compute_timeout(req);
    grpc::ClientCallContext call_ctx(timeout);
    call_ctx.add_metadata("x-user-id", ctx.user_id());
    call_ctx.add_metadata("x-device-id", ctx.device_id());
    call_ctx.add_metadata("x-correlation-id", request_id);

    auto result = messaging_client_->get_message_delivery_status(grpc_req, call_ctx);
    if (circuit_breaker_) {
        if (result.has_value()) {
            circuit_breaker_->record_success();
        } else if (result.error().kind == grpc::DependencyErrorKind::ServiceUnavailable ||
                   result.error().kind == grpc::DependencyErrorKind::Timeout) {
            circuit_breaker_->record_failure();
        }
    }

    if (result.has_error()) {
        write_grpc_error(res, result.error(), request_id);
        return;
    }

    const auto& resp = result.value();
    nlohmann::json response_body;
    response_body["message_id"] = resp.message_id();
    response_body["conversation_id"] = resp.conversation_id();

    nlohmann::json summary;
    summary["total_targets"] = resp.summary().total_targets();
    summary["delivered_targets"] = resp.summary().delivered_targets();
    summary["pending_targets"] = resp.summary().pending_targets();
    summary["expired_targets"] = resp.summary().expired_targets();
    response_body["summary"] = summary;

    nlohmann::json device_statuses = nlohmann::json::array();
    for (const auto& ds : resp.device_statuses()) {
        nlohmann::json ds_json;
        ds_json["device_id"] = ds.device_id();
        ds_json["recipient_user_id"] = ds.recipient_user_id();
        ds_json["delivery_state"] = delivery_state_to_string(ds.delivery_state());
        ds_json["delivered_at_unix_ms"] = ds.delivered_at_unix_ms();
        ds_json["attempt_count"] = ds.attempt_count();
        device_statuses.push_back(ds_json);
    }
    response_body["device_statuses"] = device_statuses;

    nlohmann::json recipient_read_statuses = nlohmann::json::array();
    for (const auto& rrs : resp.recipient_read_statuses()) {
        nlohmann::json rrs_json;
        rrs_json["user_id"] = rrs.user_id();
        rrs_json["is_read"] = rrs.is_read();
        rrs_json["read_at_unix_ms"] = rrs.read_at_unix_ms();
        rrs_json["reader_device_id"] = rrs.reader_device_id();
        recipient_read_statuses.push_back(rrs_json);
    }
    response_body["recipient_read_statuses"] = recipient_read_statuses;

    res.status = 200;
    res.set_content(response_body.dump(), k_content_type_json);
}

// ============================================================================
// MSG-009 Synchronization and Cursor Handlers
// ============================================================================

void MessagingProxyHandler::handle_sync_messages(const httplib::Request& req, httplib::Response& res,
                                                 const AuthenticatedContext& ctx) {
    const std::string request_id = extract_request_id(req);

    auto lease = bulkhead_manager_ ? bulkhead_manager_->acquire(WorkloadCategory::Messaging) : BulkheadLease{};
    if (bulkhead_manager_ && !lease) {
        BulkheadManager::write_rejection(res, request_id);
        return;
    }
    if (circuit_breaker_ && !circuit_breaker_->allow_request()) {
        CircuitBreaker::write_rejection(res, request_id);
        return;
    }

    std::string conversation_id = Router::get_path_param(req, "conversationId");
    if (conversation_id.empty()) {
        conversation_id = Router::get_path_param(req, "conversation_id");
    }
    if (conversation_id.empty()) {
        conversation_id = Router::get_path_param(req, "id");
    }
    if (conversation_id.empty() && req.has_param("conversation_id")) {
        conversation_id = req.get_param_value("conversation_id");
    }

    if (conversation_id.empty()) {
        ErrorMapper::write_error(res, 400, "INVALID_ARGUMENT", "Missing conversation ID", request_id);
        return;
    }

    int64_t since_sequence = 0;
    if (req.has_param("since_sequence")) {
        try {
            since_sequence = std::stoll(req.get_param_value("since_sequence"));
            if (since_sequence < 0) {
                ErrorMapper::write_error(res, 400, "INVALID_ARGUMENT", "since_sequence must be non-negative",
                                         request_id);
                return;
            }
        } catch (const std::exception&) {
            ErrorMapper::write_error(res, 400, "INVALID_ARGUMENT", "Invalid since_sequence parameter", request_id);
            return;
        }
    }

    uint32_t limit = 50;
    if (req.has_param("limit")) {
        try {
            int parsed_limit = std::stoi(req.get_param_value("limit"));
            if (parsed_limit < 1) {
                limit = 1;
            } else if (parsed_limit > 100) {
                limit = 100;
            } else {
                limit = static_cast<uint32_t>(parsed_limit);
            }
        } catch (const std::exception&) {
            ErrorMapper::write_error(res, 400, "INVALID_ARGUMENT", "Invalid limit parameter", request_id);
            return;
        }
    } else if (req.has_param("max_messages")) {
        try {
            int parsed_limit = std::stoi(req.get_param_value("max_messages"));
            if (parsed_limit < 1) {
                limit = 1;
            } else if (parsed_limit > 100) {
                limit = 100;
            } else {
                limit = static_cast<uint32_t>(parsed_limit);
            }
        } catch (const std::exception&) {
            ErrorMapper::write_error(res, 400, "INVALID_ARGUMENT", "Invalid max_messages parameter", request_id);
            return;
        }
    }

    securecloud::messaging::v1::SyncDeviceMessagesRequest grpc_req;
    grpc_req.set_conversation_id(conversation_id);
    grpc_req.set_device_id(ctx.device_id());
    grpc_req.set_since_sequence(since_sequence);
    grpc_req.set_max_messages(limit);

    const auto timeout = compute_timeout(req);
    grpc::ClientCallContext call_ctx(timeout);
    call_ctx.add_metadata("x-user-id", ctx.user_id());
    call_ctx.add_metadata("x-device-id", ctx.device_id());
    call_ctx.add_metadata("x-correlation-id", request_id);

    auto result = messaging_client_->sync_device_messages(grpc_req, call_ctx);
    if (circuit_breaker_) {
        if (result.has_value()) {
            circuit_breaker_->record_success();
        } else if (result.error().kind == grpc::DependencyErrorKind::ServiceUnavailable ||
                   result.error().kind == grpc::DependencyErrorKind::Timeout) {
            circuit_breaker_->record_failure();
        }
    }

    if (result.has_error()) {
        write_grpc_error(res, result.error(), request_id);
        return;
    }

    const auto& resp = result.value();
    nlohmann::json response_body;
    response_body["device_id"] = resp.device_id();
    response_body["conversation_id"] = conversation_id;
    response_body["has_more"] = resp.has_more();
    response_body["next_sequence"] = resp.next_sequence();
    response_body["latest_sequence"] = resp.latest_sequence();

    nlohmann::json messages_json = nlohmann::json::array();
    for (const auto& msg : resp.messages()) {
        messages_json.push_back(message_envelope_to_json(msg));
    }
    response_body["messages"] = messages_json;

    if (resp.has_cursor()) {
        response_body["cursor"] = sync_cursor_to_json(resp.cursor());
    }

    res.status = 200;
    res.set_content(response_body.dump(), k_content_type_json);
}

void MessagingProxyHandler::handle_get_sync_cursor(const httplib::Request& req, httplib::Response& res,
                                                   const AuthenticatedContext& ctx) {
    const std::string request_id = extract_request_id(req);

    auto lease = bulkhead_manager_ ? bulkhead_manager_->acquire(WorkloadCategory::Messaging) : BulkheadLease{};
    if (bulkhead_manager_ && !lease) {
        BulkheadManager::write_rejection(res, request_id);
        return;
    }
    if (circuit_breaker_ && !circuit_breaker_->allow_request()) {
        CircuitBreaker::write_rejection(res, request_id);
        return;
    }

    std::string device_id = Router::get_path_param(req, "deviceId");
    if (device_id.empty()) {
        device_id = Router::get_path_param(req, "device_id");
    }
    if (device_id.empty()) {
        device_id = Router::get_path_param(req, "id");
    }

    if (device_id.empty()) {
        ErrorMapper::write_error(res, 400, "INVALID_ARGUMENT", "Missing device ID", request_id);
        return;
    }

    // AuthenticatedContext device boundary enforcement
    if (!ctx.device_id().empty() && ctx.device_id() != device_id) {
        ErrorMapper::write_error(res, 403, "PERMISSION_DENIED", "Access forbidden to device cursor", request_id);
        return;
    }

    std::string conversation_id;
    if (req.has_param("conversation_id")) {
        conversation_id = req.get_param_value("conversation_id");
    } else if (req.has_param("conversationId")) {
        conversation_id = req.get_param_value("conversationId");
    }

    securecloud::messaging::v1::GetSyncCursorRequest grpc_req;
    grpc_req.set_device_id(device_id);
    grpc_req.set_conversation_id(conversation_id);

    const auto timeout = compute_timeout(req);
    grpc::ClientCallContext call_ctx(timeout);
    call_ctx.add_metadata("x-user-id", ctx.user_id());
    call_ctx.add_metadata("x-device-id", ctx.device_id());
    call_ctx.add_metadata("x-correlation-id", request_id);

    auto result = messaging_client_->get_sync_cursor(grpc_req, call_ctx);
    if (circuit_breaker_) {
        if (result.has_value()) {
            circuit_breaker_->record_success();
        } else if (result.error().kind == grpc::DependencyErrorKind::ServiceUnavailable ||
                   result.error().kind == grpc::DependencyErrorKind::Timeout) {
            circuit_breaker_->record_failure();
        }
    }

    if (result.has_error()) {
        write_grpc_error(res, result.error(), request_id);
        return;
    }

    const auto& resp = result.value();
    nlohmann::json response_body;
    if (resp.has_cursor()) {
        response_body = sync_cursor_to_json(resp.cursor());
    } else {
        response_body["device_id"] = device_id;
        response_body["conversation_id"] = conversation_id;
        response_body["last_delivered_sequence"] = 0;
        response_body["last_sync_timestamp_unix_ms"] = 0;
    }

    res.status = 200;
    res.set_content(response_body.dump(), k_content_type_json);
}

void MessagingProxyHandler::handle_update_sync_cursor(const httplib::Request& req, httplib::Response& res,
                                                      const AuthenticatedContext& ctx) {
    const std::string request_id = extract_request_id(req);

    auto lease = bulkhead_manager_ ? bulkhead_manager_->acquire(WorkloadCategory::Messaging) : BulkheadLease{};
    if (bulkhead_manager_ && !lease) {
        BulkheadManager::write_rejection(res, request_id);
        return;
    }
    if (circuit_breaker_ && !circuit_breaker_->allow_request()) {
        CircuitBreaker::write_rejection(res, request_id);
        return;
    }

    std::string device_id = Router::get_path_param(req, "deviceId");
    if (device_id.empty()) {
        device_id = Router::get_path_param(req, "device_id");
    }
    if (device_id.empty()) {
        device_id = Router::get_path_param(req, "id");
    }

    if (device_id.empty()) {
        ErrorMapper::write_error(res, 400, "INVALID_ARGUMENT", "Missing device ID", request_id);
        return;
    }

    // AuthenticatedContext device boundary enforcement
    if (!ctx.device_id().empty() && ctx.device_id() != device_id) {
        ErrorMapper::write_error(res, 403, "PERMISSION_DENIED", "Access forbidden to update device cursor", request_id);
        return;
    }

    nlohmann::json body;
    try {
        body = nlohmann::json::parse(req.body);
    } catch (const std::exception&) {
        ErrorMapper::write_error(res, 400, "INVALID_ARGUMENT", "Invalid JSON body", request_id);
        return;
    }

    securecloud::messaging::v1::UpdateSyncCursorRequest grpc_req;
    auto* cursor = grpc_req.mutable_cursor();
    cursor->set_device_id(device_id);

    std::string conversation_id = body.value("conversation_id", "");
    if (conversation_id.empty() && body.contains("conversationId") && body["conversationId"].is_string()) {
        conversation_id = body["conversationId"].get<std::string>();
    }
    cursor->set_conversation_id(conversation_id);

    int64_t last_delivered_sequence = 0;
    if (body.contains("last_delivered_sequence") && body["last_delivered_sequence"].is_number_integer()) {
        last_delivered_sequence = body["last_delivered_sequence"].get<int64_t>();
    } else if (body.contains("sequence") && body["sequence"].is_number_integer()) {
        last_delivered_sequence = body["sequence"].get<int64_t>();
    }
    cursor->set_last_delivered_sequence(last_delivered_sequence);

    int64_t timestamp_ms = 0;
    if (body.contains("last_sync_timestamp_unix_ms") && body["last_sync_timestamp_unix_ms"].is_number_integer()) {
        timestamp_ms = body["last_sync_timestamp_unix_ms"].get<int64_t>();
    } else if (body.contains("checkpoint_timestamp_ms") && body["checkpoint_timestamp_ms"].is_number_integer()) {
        timestamp_ms = body["checkpoint_timestamp_ms"].get<int64_t>();
    } else {
        timestamp_ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
                .count();
    }
    cursor->set_last_sync_timestamp_unix_ms(timestamp_ms);

    const auto timeout = compute_timeout(req);
    grpc::ClientCallContext call_ctx(timeout);
    call_ctx.add_metadata("x-user-id", ctx.user_id());
    call_ctx.add_metadata("x-device-id", ctx.device_id());
    call_ctx.add_metadata("x-correlation-id", request_id);

    auto result = messaging_client_->update_sync_cursor(grpc_req, call_ctx);
    if (circuit_breaker_) {
        if (result.has_value()) {
            circuit_breaker_->record_success();
        } else if (result.error().kind == grpc::DependencyErrorKind::ServiceUnavailable ||
                   result.error().kind == grpc::DependencyErrorKind::Timeout) {
            circuit_breaker_->record_failure();
        }
    }

    if (result.has_error()) {
        write_grpc_error(res, result.error(), request_id);
        return;
    }

    const auto& resp = result.value();
    nlohmann::json response_body;
    response_body["success"] = resp.success();
    if (resp.has_cursor()) {
        response_body["cursor"] = sync_cursor_to_json(resp.cursor());
    } else {
        response_body["cursor"] = sync_cursor_to_json(*cursor);
    }

    res.status = 200;
    res.set_content(response_body.dump(), k_content_type_json);
}

} // namespace securecloud::gateway::http
