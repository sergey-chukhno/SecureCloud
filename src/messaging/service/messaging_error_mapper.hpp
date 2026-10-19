#pragma once

#include "securecloud/grpc/caller_context.hpp"
#include "securecloud/messaging/v1/messaging.grpc.pb.h"
#include "securecloud/messaging/v1/messaging.pb.h"

#include <grpcpp/grpcpp.h>
#include <map>
#include <optional>
#include <string>
#include <string_view>

namespace securecloud::messaging::service {

/// Re-export server cancellation and deadline helper from common::rpc
using common::rpc::check_deadline_and_cancellation;

/// Trailing metadata header key for serialized binary MessagingErrorDetail protobuf
inline constexpr std::string_view k_header_error_detail_bin = "x-error-detail-bin";

/// Returns canonical human-readable default reason for a MessagingErrorCode
[[nodiscard]] std::string_view default_error_reason(v1::MessagingErrorCode code) noexcept;

/// Converts a domain MessagingErrorCode to its canonical gRPC StatusCode
[[nodiscard]] ::grpc::StatusCode to_grpc_status_code(v1::MessagingErrorCode code) noexcept;

/// Creates a populated MessagingErrorDetail protobuf message
[[nodiscard]] v1::MessagingErrorDetail create_error_detail(v1::MessagingErrorCode code, std::string_view reason,
                                                           std::string_view correlation_id,
                                                           const std::map<std::string, std::string>& metadata = {});

/// Builds a canonical ::grpc::Status for a MessagingErrorCode.
/// If context is non-null, attaches serialized MessagingErrorDetail as trailing metadata.
[[nodiscard]] ::grpc::Status to_grpc_status(v1::MessagingErrorCode code, std::string_view reason,
                                            std::string_view correlation_id, ::grpc::ServerContext* context = nullptr,
                                            const std::map<std::string, std::string>& metadata = {});

/// Extracts and deserializes MessagingErrorDetail from gRPC trailing metadata multimap
[[nodiscard]] std::optional<v1::MessagingErrorDetail>
extract_error_detail(const std::multimap<::grpc::string_ref, ::grpc::string_ref>& trailing_metadata);

/// Extracts and deserializes MessagingErrorDetail from a ClientContext's trailing metadata
[[nodiscard]] std::optional<v1::MessagingErrorDetail> extract_error_detail(const ::grpc::ClientContext& context);

} // namespace securecloud::messaging::service
