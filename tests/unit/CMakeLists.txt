add_executable(securecloud_unit_smoke_test
    smoke_test.cpp
)

target_link_libraries(securecloud_unit_smoke_test PRIVATE
    securecloud::common
    securecloud::compiler_flags
)

add_test(
    NAME unit_smoke_test
    COMMAND securecloud_unit_smoke_test
)

# Dependency Discovery Pipeline Smoke Test (SC002-T03)
add_executable(securecloud_dependency_smoke_test
    dependency_smoke_test.cpp
)

target_link_libraries(securecloud_dependency_smoke_test PRIVATE
    securecloud::common
    securecloud::compiler_flags
)

add_test(
    NAME dependency_smoke_test
    COMMAND securecloud_dependency_smoke_test
)

# GoogleTest Framework Integration Target (SC-003)
add_executable(securecloud_gtest_smoke_test
    gtest_smoke_test.cpp
)

target_link_libraries(securecloud_gtest_smoke_test PRIVATE
    GTest::gtest_main
    securecloud::compiler_flags
)

# Automatic CTest discovery for GoogleTest test cases
gtest_discover_tests(securecloud_gtest_smoke_test ${SECURECLOUD_TEST_PROPERTIES})

# Protobuf & gRPC Code Generation Pipeline Smoke Test
add_executable(securecloud_proto_smoke_test
    proto_smoke_test.cpp
)

target_link_libraries(securecloud_proto_smoke_test PRIVATE
    securecloud::common
    securecloud_proto
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_proto_smoke_test ${SECURECLOUD_TEST_PROPERTIES})

# Auth Service Protobuf & gRPC Contract Smoke Test (GW-003-T01)
add_executable(securecloud_auth_proto_smoke_test
    gateway/auth_proto_smoke_test.cpp
)

target_link_libraries(securecloud_auth_proto_smoke_test PRIVATE
    securecloud::common
    securecloud_proto
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_auth_proto_smoke_test ${SECURECLOUD_TEST_PROPERTIES})

# Custom target to explicitly execute generated contract verification
if(WIN32)
    # Ensure Windows runtime finds dependent DLLs from the active compiler toolchain
    set(_CONTRACTS_ENV_FLAGS "")
    if(CMAKE_CXX_COMPILER)
        get_filename_component(_COMPILER_BIN_DIR "${CMAKE_CXX_COMPILER}" DIRECTORY)
        if(EXISTS "${_COMPILER_BIN_DIR}")
            list(APPEND _CONTRACTS_ENV_FLAGS "--modify" "PATH=path_list_prepend:${_COMPILER_BIN_DIR}")
        endif()
    endif()

    add_custom_target(verify-contracts
        COMMAND ${CMAKE_COMMAND} -E env ${_CONTRACTS_ENV_FLAGS} $<TARGET_FILE:securecloud_proto_smoke_test>
        COMMAND ${CMAKE_COMMAND} -E env ${_CONTRACTS_ENV_FLAGS} $<TARGET_FILE:securecloud_auth_proto_smoke_test>
        DEPENDS securecloud_proto_smoke_test securecloud_auth_proto_smoke_test
        COMMENT "Executing Protobuf & gRPC generated-contracts validation smoke tests..."
        VERBATIM
    )
else()
    add_custom_target(verify-contracts
        COMMAND $<TARGET_FILE:securecloud_proto_smoke_test>
        COMMAND $<TARGET_FILE:securecloud_auth_proto_smoke_test>
        DEPENDS securecloud_proto_smoke_test securecloud_auth_proto_smoke_test
        COMMENT "Executing Protobuf & gRPC generated-contracts validation smoke tests..."
        VERBATIM
    )
endif()


# gRPC mTLS Configuration & Security Unit Test Suite
add_executable(securecloud_mtls_config_test
    security/mtls_config_test.cpp
)

target_link_libraries(securecloud_mtls_config_test PRIVATE
    securecloud::common
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_mtls_config_test ${SECURECLOUD_TEST_PROPERTIES})

# Configuration Primitives & Parser Unit Test Suite (SC12-T01)
add_executable(securecloud_config_parser_test
    configuration/config_parser_test.cpp
)

target_link_libraries(securecloud_config_parser_test PRIVATE
    securecloud::common
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_config_parser_test ${SECURECLOUD_TEST_PROPERTIES})

# Common Service Configuration Model Unit Test Suite (SC12-T02)
add_executable(securecloud_common_service_config_test
    configuration/common_service_config_test.cpp
)

target_link_libraries(securecloud_common_service_config_test PRIVATE
    securecloud::common
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_common_service_config_test ${SECURECLOUD_TEST_PROPERTIES})

# Service Configuration Boundaries Unit Test Suite (SC12-T03)
add_executable(securecloud_service_config_boundaries_test
    configuration/service_config_boundaries_test.cpp
)

target_link_libraries(securecloud_service_config_boundaries_test PRIVATE
    securecloud::gateway_config
    securecloud::auth_config
    securecloud::messaging_config
    securecloud::files_config
    securecloud::audit_config
    securecloud::common
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_service_config_boundaries_test ${SECURECLOUD_TEST_PROPERTIES})

# Health Status Manager & Service Unit Test Suite (SC13-T03)
add_executable(securecloud_health_status_manager_test
    health/health_status_manager_test.cpp
)

target_link_libraries(securecloud_health_status_manager_test PRIVATE
    securecloud::common
    securecloud_proto
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_health_status_manager_test ${SECURECLOUD_TEST_PROPERTIES})

# Transport Probe Unit Test Suite (SC13-T03)
add_executable(securecloud_transport_probe_test
    health/transport_probe_test.cpp
)

target_link_libraries(securecloud_transport_probe_test PRIVATE
    securecloud::common
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_transport_probe_test ${SECURECLOUD_TEST_PROPERTIES})

# Gateway HTTP & JSON Dependencies Smoke Test (GW-001-T01)
add_executable(securecloud_http_smoke_test
    gateway/http_smoke_test.cpp
)

target_link_libraries(securecloud_http_smoke_test PRIVATE
    securecloud::json
    securecloud::httplib
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_http_smoke_test ${SECURECLOUD_TEST_PROPERTIES})

# Gateway Configuration Model & Strict No-DB Invariant Test (GW-001-T02)
add_executable(securecloud_gateway_config_test
    gateway/gateway_config_test.cpp
)

target_link_libraries(securecloud_gateway_config_test PRIVATE
    securecloud::gateway_config
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_gateway_config_test ${SECURECLOUD_TEST_PROPERTIES})

# Gateway Modular HTTP Server Lifecycle Test (GW-001-T03)
add_executable(securecloud_http_server_lifecycle_test
    gateway/http_server_lifecycle_test.cpp
)

target_link_libraries(securecloud_http_server_lifecycle_test PRIVATE
    securecloud::gateway_http
    securecloud::httplib
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_http_server_lifecycle_test ${SECURECLOUD_TEST_PROPERTIES})

# Gateway Router, Middleware Pipeline & Error Mapper Test (GW-001-T04)
add_executable(securecloud_router_middleware_test
    gateway/router_middleware_test.cpp
)

target_link_libraries(securecloud_router_middleware_test PRIVATE
    securecloud::gateway_http
    securecloud::httplib
    securecloud::json
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_router_middleware_test ${SECURECLOUD_TEST_PROPERTIES})

# Gateway Downstream gRPC Channel Manager Test (GW-001-T05)
add_executable(securecloud_channel_manager_test
    gateway/channel_manager_test.cpp
)

target_link_libraries(securecloud_channel_manager_test PRIVATE
    securecloud::gateway_grpc
    securecloud::gateway_config
    securecloud::common
    securecloud::compiler_flags
    GTest::gtest
)

target_compile_definitions(securecloud_channel_manager_test PRIVATE
    SECURECLOUD_DEV_PKI_DIR="${CMAKE_SOURCE_DIR}/deploy/dev-pki"
)

gtest_discover_tests(securecloud_channel_manager_test ${SECURECLOUD_TEST_PROPERTIES})

# Gateway Channel Manager Lifecycle & Connection Health Test (GW-003-T03)
add_executable(securecloud_channel_manager_lifecycle_test
    gateway/channel_manager_lifecycle_test.cpp
)

target_link_libraries(securecloud_channel_manager_lifecycle_test PRIVATE
    securecloud::gateway_grpc
    securecloud::gateway_config
    securecloud::common
    securecloud::compiler_flags
    GTest::gtest
)

target_compile_definitions(securecloud_channel_manager_lifecycle_test PRIVATE
    SECURECLOUD_DEV_PKI_DIR="${CMAKE_SOURCE_DIR}/deploy/dev-pki"
)

gtest_discover_tests(securecloud_channel_manager_lifecycle_test ${SECURECLOUD_TEST_PROPERTIES})

# Gateway RPC Call Context, Deadline & Cancellation Test (GW-003-T02)
add_executable(securecloud_client_call_context_test
    gateway/client_call_context_test.cpp
)

target_link_libraries(securecloud_client_call_context_test PRIVATE
    securecloud::gateway_grpc
    securecloud::common
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_client_call_context_test ${SECURECLOUD_TEST_PROPERTIES})

# Gateway TLS & Transport Resource Configuration Model Test (GW-002-T01)

add_executable(securecloud_gateway_tls_config_test
    gateway/gateway_tls_config_test.cpp
)

target_link_libraries(securecloud_gateway_tls_config_test PRIVATE
    securecloud::gateway_config
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_gateway_tls_config_test ${SECURECLOUD_TEST_PROPERTIES})

# Gateway OpenSSL TLS Context & Certificate Pair Validator Test (GW-002-T02)
add_executable(securecloud_tls_handler_test
    gateway/tls_handler_test.cpp
)

target_link_libraries(securecloud_tls_handler_test PRIVATE
    securecloud::gateway_tls
    securecloud::compiler_flags
    GTest::gtest_main
)

target_compile_definitions(securecloud_tls_handler_test PRIVATE
    SECURECLOUD_DEV_PKI_DIR="${CMAKE_SOURCE_DIR}/deploy/dev-pki"
)

gtest_discover_tests(securecloud_tls_handler_test ${SECURECLOUD_TEST_PROPERTIES})

# Gateway HTTPS Server Engine Integration Test (GW-002-T03)
add_executable(securecloud_https_server_lifecycle_test
    gateway/https_server_lifecycle_test.cpp
)

target_link_libraries(securecloud_https_server_lifecycle_test PRIVATE
    securecloud::gateway_http
    securecloud::gateway_tls
    securecloud::httplib
    securecloud::compiler_flags
    GTest::gtest_main
)

target_compile_definitions(securecloud_https_server_lifecycle_test PRIVATE
    SECURECLOUD_DEV_PKI_DIR="${CMAKE_SOURCE_DIR}/deploy/dev-pki"
)

gtest_discover_tests(securecloud_https_server_lifecycle_test ${SECURECLOUD_TEST_PROPERTIES})

# Gateway Request & Resource Limiter Middleware Test (GW-002-T04)
add_executable(securecloud_resource_limiter_middleware_test
    gateway/resource_limiter_middleware_test.cpp
)

target_link_libraries(securecloud_resource_limiter_middleware_test PRIVATE
    securecloud::gateway_http
    securecloud::gateway_config
    securecloud::httplib
    securecloud::json
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_resource_limiter_middleware_test ${SECURECLOUD_TEST_PROPERTIES})

# Gateway Insecure Protocol Downgrade Rejection & HTTP Redirect Guard Test (GW-002-T05)
add_executable(securecloud_downgrade_guard_test
    gateway/downgrade_guard_test.cpp
)

target_link_libraries(securecloud_downgrade_guard_test PRIVATE
    securecloud::gateway_http
    securecloud::gateway_tls
    securecloud::httplib
    OpenSSL::SSL
    OpenSSL::Crypto
    securecloud::compiler_flags
    GTest::gtest_main
)

target_compile_definitions(securecloud_downgrade_guard_test PRIVATE
    SECURECLOUD_DEV_PKI_DIR="${CMAKE_SOURCE_DIR}/deploy/dev-pki"
)

gtest_discover_tests(securecloud_downgrade_guard_test ${SECURECLOUD_TEST_PROPERTIES})

# Files PostgreSQL Connection Pool Unit Test Suite (FILES-001-T02)
add_executable(securecloud_files_connection_pool_test
    files/files_connection_pool_test.cpp
)

target_link_libraries(securecloud_files_connection_pool_test PRIVATE
    securecloud::files_db
    securecloud::files_config
    securecloud::common
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_files_connection_pool_test ${SECURECLOUD_TEST_PROPERTIES})

# Files S3 Storage Client Unit Test Suite (FILES-001-T03)
add_executable(securecloud_s3_client_test
    files/s3_client_test.cpp
)

target_link_libraries(securecloud_s3_client_test PRIVATE
    securecloud::files_storage
    securecloud::files_config
    securecloud::common
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_s3_client_test ${SECURECLOUD_TEST_PROPERTIES})

# Files Service Implementation Unit Test Suite (FILES-001-T04)
add_executable(securecloud_files_service_impl_test
    files/files_service_impl_test.cpp
)

target_link_libraries(securecloud_files_service_impl_test PRIVATE
    securecloud::files_service
    securecloud::files_storage
    securecloud::files_db
    securecloud::files_config
    securecloud::common
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_files_service_impl_test ${SECURECLOUD_TEST_PROPERTIES})

# Files Dual-Dependency Health Evaluator Unit Test Suite (FILES-001-T05)
add_executable(securecloud_files_health_evaluator_test
    files/files_health_evaluator_test.cpp
)

target_link_libraries(securecloud_files_health_evaluator_test PRIVATE
    securecloud::files_health
    securecloud::files_storage
    securecloud::files_db
    securecloud::files_config
    securecloud::common
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_files_health_evaluator_test ${SECURECLOUD_TEST_PROPERTIES})
