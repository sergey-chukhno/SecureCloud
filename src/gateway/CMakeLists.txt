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

add_library(securecloud_gateway_http STATIC
    http/http_server.cpp
    http/https_server.cpp
    http/http_redirect_server.cpp
    http/error_mapper.cpp
    http/middleware.cpp
    http/request_id_middleware.cpp
    http/logging_middleware.cpp
    http/resource_limiter_middleware.cpp
    http/router.cpp
)

add_library(securecloud::gateway_http ALIAS securecloud_gateway_http)

target_include_directories(securecloud_gateway_http PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/http
)

target_link_libraries(securecloud_gateway_http PUBLIC
    securecloud::gateway_config
    securecloud::gateway_tls
    securecloud::httplib
    securecloud::json
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
