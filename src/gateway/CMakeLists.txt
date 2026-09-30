add_library(securecloud_gateway_config STATIC
    gateway_config.cpp
)

add_library(securecloud::gateway_config ALIAS securecloud_gateway_config)

target_include_directories(securecloud_gateway_config PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(securecloud_gateway_config PUBLIC
    securecloud::common
    securecloud::compiler_flags
)

add_library(securecloud_gateway_tls STATIC
    tls/tls_handler.cpp
)

add_library(securecloud::gateway_tls ALIAS securecloud_gateway_tls)

target_include_directories(securecloud_gateway_tls PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/tls
)

target_link_libraries(securecloud_gateway_tls PUBLIC
    securecloud::gateway_config
    OpenSSL::SSL
    OpenSSL::Crypto
    securecloud::common
    securecloud::compiler_flags
)

add_library(securecloud_gateway_grpc STATIC
    grpc/channel_manager.cpp
    grpc/client_call_context.cpp
    grpc/auth_service_client.cpp
)

add_library(securecloud::gateway_grpc ALIAS securecloud_gateway_grpc)

target_include_directories(securecloud_gateway_grpc PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/grpc
)

target_link_libraries(securecloud_gateway_grpc PUBLIC
    securecloud::gateway_config
    securecloud::common
    securecloud::compiler_flags
)

add_library(securecloud_gateway_http STATIC
    http/server/http_server.cpp
    http/server/https_server.cpp
    http/server/http_redirect_server.cpp
    http/errors/error_mapper.cpp
    http/resilience/deadline_manager.cpp
    http/resilience/retry_policy.cpp
    http/resilience/bulkhead_manager.cpp
    http/resilience/circuit_breaker.cpp
    http/resilience/drain_manager.cpp
    http/routing/router.cpp
    http/routing/gateway_route_registrar.cpp
    http/middleware/middleware.cpp
    http/middleware/drain_middleware.cpp
    http/middleware/request_id_middleware.cpp
    http/middleware/logging_middleware.cpp
    http/middleware/resource_limiter_middleware.cpp
    http/middleware/rate_limiter_middleware.cpp
    http/auth/bearer_token_extractor.cpp
    http/auth/authenticated_context.cpp
    http/auth/auth_service_token_validator.cpp
    http/auth/scope_matcher.cpp
    http/auth/gateway_security_policy.cpp
    http/auth/header_sanitizer.cpp
    http/auth/request_context.cpp
    http/auth/authentication_middleware.cpp
    http/auth/authorization_middleware.cpp
    http/proxy/auth_proxy_handler.cpp
)

add_library(securecloud::gateway_http ALIAS securecloud_gateway_http)

target_include_directories(securecloud_gateway_http PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/http
    ${CMAKE_CURRENT_SOURCE_DIR}/http/middleware
    ${CMAKE_CURRENT_SOURCE_DIR}/http/auth
    ${CMAKE_CURRENT_SOURCE_DIR}/http/proxy
    ${CMAKE_CURRENT_SOURCE_DIR}/http/resilience
    ${CMAKE_CURRENT_SOURCE_DIR}/http/server
    ${CMAKE_CURRENT_SOURCE_DIR}/http/routing
    ${CMAKE_CURRENT_SOURCE_DIR}/http/errors
)

target_link_libraries(securecloud_gateway_http PUBLIC
    securecloud::gateway_config
    securecloud::gateway_tls
    securecloud::gateway_grpc
    securecloud::httplib
    securecloud::json
    securecloud::common
    securecloud::compiler_flags
)

add_library(securecloud_gateway_health STATIC
    health/gateway_health_evaluator.cpp
)

add_library(securecloud::gateway_health ALIAS securecloud_gateway_health)

target_include_directories(securecloud_gateway_health PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/health
)

target_link_libraries(securecloud_gateway_health PUBLIC
    securecloud::gateway_grpc
    securecloud::common
    securecloud::compiler_flags
)

add_executable(securecloud-gateway
    main.cpp
)

target_link_libraries(securecloud-gateway PRIVATE
    securecloud::gateway_config
    securecloud::gateway_http
    securecloud::gateway_grpc
    securecloud::gateway_health
    securecloud::gateway_tls
    securecloud::common
    securecloud::compiler_flags
)
