# Auto-generate dev PKI certificates if missing and bash/openssl are available
find_program(BASH_EXECUTABLE NAMES bash)
if(BASH_EXECUTABLE AND NOT EXISTS "${CMAKE_SOURCE_DIR}/deploy/dev-pki/ca/ca.crt")
    execute_process(
            COMMAND ${BASH_EXECUTABLE} "scripts/generate-dev-pki.sh" --force
            WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
            RESULT_VARIABLE PKI_GEN_RES
    )
    if(NOT PKI_GEN_RES EQUAL 0)
        message(WARNING "Failed to generate development PKI certificates automatically")
    endif()
endif()

# gRPC mTLS Integration Test Suite (SC10-T03)
add_executable(securecloud_mtls_integration_test
        mtls_integration_test.cpp
)

target_link_libraries(securecloud_mtls_integration_test PRIVATE
        securecloud::common
        securecloud_proto
        securecloud::compiler_flags
        GTest::gtest
)

target_compile_definitions(securecloud_mtls_integration_test PRIVATE
        SECURECLOUD_DEV_PKI_DIR="${CMAKE_SOURCE_DIR}/deploy/dev-pki"
)

gtest_discover_tests(securecloud_mtls_integration_test ${SECURECLOUD_TEST_PROPERTIES})

# Health and Readiness Integration Test Suite (SC-013-T05)
add_executable(securecloud_health_integration_test
        health_integration_test.cpp
)

target_link_libraries(securecloud_health_integration_test PRIVATE
        securecloud::common
        securecloud_proto
        securecloud::compiler_flags
        GTest::gtest
)

target_compile_definitions(securecloud_health_integration_test PRIVATE
        SECURECLOUD_HEALTH_PROBE_BIN="$<TARGET_FILE:securecloud_health_probe>"
        SECURECLOUD_DEV_PKI_DIR="${CMAKE_SOURCE_DIR}/deploy/dev-pki"
)

add_dependencies(securecloud_health_integration_test securecloud_health_probe)

gtest_discover_tests(securecloud_health_integration_test ${SECURECLOUD_TEST_PROPERTIES})

# Dedicated Health & Readiness mTLS Probe Runner CLI (SC-013-T06)
add_executable(securecloud_health_probe
        health_probe_cli.cpp
)

target_link_libraries(securecloud_health_probe PRIVATE
        securecloud::common
        securecloud_proto
        securecloud::compiler_flags
)

# Auth Integration Test Suite (AUTH-001-T06)
add_executable(securecloud_auth_integration_test
        auth_integration_test.cpp
)

target_link_libraries(securecloud_auth_integration_test PRIVATE
        securecloud::auth
        securecloud::common
        securecloud_proto
        securecloud::compiler_flags
        GTest::gtest
)

target_compile_definitions(securecloud_auth_integration_test PRIVATE
        SECURECLOUD_DEV_PKI_DIR="${CMAKE_SOURCE_DIR}/deploy/dev-pki"
)

gtest_discover_tests(securecloud_auth_integration_test ${SECURECLOUD_TEST_PROPERTIES})

# Gateway Dual-Stack Integration Test Suite (GW-001-T06)
add_executable(securecloud_gateway_integration_test
    gateway_integration_test.cpp
)

target_link_libraries(securecloud_gateway_integration_test PRIVATE
    securecloud::gateway_config
    securecloud::gateway_http
    securecloud::gateway_grpc
    securecloud::gateway_health
    securecloud::common
    securecloud_proto
    securecloud::compiler_flags
    GTest::gtest
)

target_compile_definitions(securecloud_gateway_integration_test PRIVATE
    SECURECLOUD_HEALTH_PROBE_BIN="$<TARGET_FILE:securecloud_health_probe>"
    SECURECLOUD_DEV_PKI_DIR="${CMAKE_SOURCE_DIR}/deploy/dev-pki"
)

add_dependencies(securecloud_gateway_integration_test securecloud_health_probe)

gtest_discover_tests(securecloud_gateway_integration_test ${SECURECLOUD_TEST_PROPERTIES})

# Gateway HTTPS Security & Handshake Integration Test Suite (GW-002-T06)
add_executable(securecloud_gateway_https_integration_test
    gateway_https_integration_test.cpp
)

target_link_libraries(securecloud_gateway_https_integration_test PRIVATE
    securecloud::gateway_config
    securecloud::gateway_http
    securecloud::gateway_tls
    securecloud::common
    securecloud::httplib
    securecloud::json
    OpenSSL::SSL
    OpenSSL::Crypto
    securecloud::compiler_flags
    GTest::gtest_main
)

target_compile_definitions(securecloud_gateway_https_integration_test PRIVATE
    SECURECLOUD_DEV_PKI_DIR="${CMAKE_SOURCE_DIR}/deploy/dev-pki"
)

gtest_discover_tests(securecloud_gateway_https_integration_test ${SECURECLOUD_TEST_PROPERTIES})

# Gateway-to-Auth mTLS gRPC Integration Test Suite (GW-003-T05)
add_executable(securecloud_gateway_auth_grpc_integration_test
    gateway_auth_grpc_integration_test.cpp
)

target_link_libraries(securecloud_gateway_auth_grpc_integration_test PRIVATE
    securecloud::gateway_grpc
    securecloud::gateway_config
    securecloud_proto
    securecloud::common
    securecloud::compiler_flags
    GTest::gtest
)

target_compile_definitions(securecloud_gateway_auth_grpc_integration_test PRIVATE
    SECURECLOUD_DEV_PKI_DIR="${CMAKE_SOURCE_DIR}/deploy/dev-pki"
)

if(WIN32)
    target_link_libraries(securecloud_gateway_auth_grpc_integration_test PRIVATE ws2_32)
endif()

gtest_discover_tests(securecloud_gateway_auth_grpc_integration_test ${SECURECLOUD_TEST_PROPERTIES})

# Gateway HTTPS Authentication Middleware Integration Test Suite (GW-004-T06)
add_executable(securecloud_gateway_auth_middleware_integration_test
    gateway_auth_middleware_integration_test.cpp
)

target_link_libraries(securecloud_gateway_auth_middleware_integration_test PRIVATE
    securecloud::gateway_http
    securecloud::gateway_grpc
    securecloud::gateway_tls
    securecloud::gateway_config
    securecloud_proto
    securecloud::common
    securecloud::httplib
    securecloud::json
    OpenSSL::SSL
    OpenSSL::Crypto
    securecloud::compiler_flags
    GTest::gtest
)

target_compile_definitions(securecloud_gateway_auth_middleware_integration_test PRIVATE
    SECURECLOUD_DEV_PKI_DIR="${CMAKE_SOURCE_DIR}/deploy/dev-pki"
)

if(WIN32)
    target_link_libraries(securecloud_gateway_auth_middleware_integration_test PRIVATE ws2_32)
endif()

gtest_discover_tests(securecloud_gateway_auth_middleware_integration_test ${SECURECLOUD_TEST_PROPERTIES})

# Gateway Routing End-to-End Integration Test Suite (GW-006-T03)
add_executable(securecloud_gateway_routing_integration_test
    gateway_routing_integration_test.cpp
)

target_link_libraries(securecloud_gateway_routing_integration_test PRIVATE
    securecloud::gateway_http
    securecloud::gateway_grpc
    securecloud::gateway_tls
    securecloud::gateway_config
    securecloud_proto
    securecloud::common
    securecloud::httplib
    securecloud::json
    OpenSSL::SSL
    OpenSSL::Crypto
    securecloud::compiler_flags
    GTest::gtest
)

target_compile_definitions(securecloud_gateway_routing_integration_test PRIVATE
    SECURECLOUD_DEV_PKI_DIR="${CMAKE_SOURCE_DIR}/deploy/dev-pki"
)

if(WIN32)
    target_link_libraries(securecloud_gateway_routing_integration_test PRIVATE ws2_32)
endif()

gtest_discover_tests(securecloud_gateway_routing_integration_test ${SECURECLOUD_TEST_PROPERTIES})

# Gateway Route & Scope Authorization Integration Test Suite (GW-007-T04)
add_executable(securecloud_gateway_authorization_integration_test
    gateway_authorization_integration_test.cpp
)

target_link_libraries(securecloud_gateway_authorization_integration_test PRIVATE
    securecloud::gateway_http
    securecloud::gateway_grpc
    securecloud::gateway_tls
    securecloud::gateway_config
    securecloud_proto
    securecloud::common
    securecloud::httplib
    securecloud::json
    OpenSSL::SSL
    OpenSSL::Crypto
    securecloud::compiler_flags
    GTest::gtest
)

target_compile_definitions(securecloud_gateway_authorization_integration_test PRIVATE
    SECURECLOUD_DEV_PKI_DIR="${CMAKE_SOURCE_DIR}/deploy/dev-pki"
)

if(WIN32)
    target_link_libraries(securecloud_gateway_authorization_integration_test PRIVATE ws2_32)
endif()

gtest_discover_tests(securecloud_gateway_authorization_integration_test ${SECURECLOUD_TEST_PROPERTIES})

# Gateway Perimeter Resilience, Deadline & Cancellation Integration Test Suite (GW-008-T04)
add_executable(securecloud_gateway_resilience_integration_test
    gateway_resilience_integration_test.cpp
)

target_link_libraries(securecloud_gateway_resilience_integration_test PRIVATE
    securecloud::gateway_http
    securecloud::gateway_grpc
    securecloud::gateway_tls
    securecloud::gateway_config
    securecloud_proto
    securecloud::common
    securecloud::httplib
    securecloud::json
    OpenSSL::SSL
    OpenSSL::Crypto
    securecloud::compiler_flags
    GTest::gtest
)

target_compile_definitions(securecloud_gateway_resilience_integration_test PRIVATE
    SECURECLOUD_DEV_PKI_DIR="${CMAKE_SOURCE_DIR}/deploy/dev-pki"
)

if(WIN32)
    target_link_libraries(securecloud_gateway_resilience_integration_test PRIVATE ws2_32)
endif()

gtest_discover_tests(securecloud_gateway_resilience_integration_test ${SECURECLOUD_TEST_PROPERTIES})

# Gateway Resource Controls & Fault Tolerance Integration Test Suite (GW-009-T05)
add_executable(securecloud_gateway_resource_controls_integration_test
    gateway_resource_controls_integration_test.cpp
)

target_link_libraries(securecloud_gateway_resource_controls_integration_test PRIVATE
    securecloud::gateway_http
    securecloud::gateway_grpc
    securecloud::gateway_tls
    securecloud::gateway_config
    securecloud_proto
    securecloud::common
    securecloud::httplib
    securecloud::json
    OpenSSL::SSL
    OpenSSL::Crypto
    securecloud::compiler_flags
    GTest::gtest
)

target_compile_definitions(securecloud_gateway_resource_controls_integration_test PRIVATE
    SECURECLOUD_DEV_PKI_DIR="${CMAKE_SOURCE_DIR}/deploy/dev-pki"
)

if(WIN32)
    target_link_libraries(securecloud_gateway_resource_controls_integration_test PRIVATE ws2_32)
endif()

gtest_discover_tests(securecloud_gateway_resource_controls_integration_test ${SECURECLOUD_TEST_PROPERTIES})

# Files Service Integration Test Suite (FILES-001-T06)
add_executable(securecloud_files_integration_test
    files_integration_test.cpp
)

target_link_libraries(securecloud_files_integration_test PRIVATE
    securecloud::files_service
    securecloud::files_health
    securecloud::files_storage
    securecloud::files_db
    securecloud::files_config
    securecloud::common
    securecloud_proto
    securecloud::compiler_flags
    GTest::gtest
)

target_compile_definitions(securecloud_files_integration_test PRIVATE
    SECURECLOUD_DEV_PKI_DIR="${CMAKE_SOURCE_DIR}/deploy/dev-pki"
)

if(WIN32)
    target_link_libraries(securecloud_files_integration_test PRIVATE ws2_32)
endif()

gtest_discover_tests(securecloud_files_integration_test ${SECURECLOUD_TEST_PROPERTIES})

# Files PostgreSQL Persistence Integration Test Suite (FILES-002-T06)
add_executable(securecloud_files_postgres_persistence_integration_test
    files_postgres_persistence_integration_test.cpp
)

target_link_libraries(securecloud_files_postgres_persistence_integration_test PRIVATE
    securecloud::files_db
    securecloud::files_config
    securecloud::common
    securecloud::compiler_flags
    GTest::gtest
)

target_compile_definitions(securecloud_files_postgres_persistence_integration_test PRIVATE
    SECURECLOUD_DEV_PKI_DIR="${CMAKE_SOURCE_DIR}/deploy/dev-pki"
)

if(WIN32)
    target_link_libraries(securecloud_files_postgres_persistence_integration_test PRIVATE ws2_32)
endif()

gtest_discover_tests(securecloud_files_postgres_persistence_integration_test ${SECURECLOUD_TEST_PROPERTIES})

# Files MinIO Object Storage Integration Test Suite (FILES-003-T06)
add_executable(securecloud_files_minio_storage_integration_test
    files_minio_storage_integration_test.cpp
)

target_link_libraries(securecloud_files_minio_storage_integration_test PRIVATE
    securecloud::files_service
    securecloud::files_storage
    securecloud::files_config
    securecloud::common
    securecloud::compiler_flags
    GTest::gtest_main
)

target_compile_definitions(securecloud_files_minio_storage_integration_test PRIVATE
    SECURECLOUD_DEV_PKI_DIR="${CMAKE_SOURCE_DIR}/deploy/dev-pki"
)

if(WIN32)
    target_link_libraries(securecloud_files_minio_storage_integration_test PRIVATE ws2_32)
endif()

gtest_discover_tests(securecloud_files_minio_storage_integration_test ${SECURECLOUD_TEST_PROPERTIES})

# Files Lifecycle Integration Test Suite (FILES-004-T06)
add_executable(securecloud_files_lifecycle_integration_test
    files_lifecycle_integration_test.cpp
)

target_link_libraries(securecloud_files_lifecycle_integration_test PRIVATE
    securecloud::files_service
    securecloud::files_db
    securecloud::files_config
    securecloud::common
    securecloud_proto
    gRPC::grpc++
    securecloud::compiler_flags
    GTest::gtest_main
)

target_compile_definitions(securecloud_files_lifecycle_integration_test PRIVATE
    SECURECLOUD_DEV_PKI_DIR="${CMAKE_SOURCE_DIR}/deploy/dev-pki"
)

if(WIN32)
    target_link_libraries(securecloud_files_lifecycle_integration_test PRIVATE ws2_32)
endif()

gtest_discover_tests(securecloud_files_lifecycle_integration_test ${SECURECLOUD_TEST_PROPERTIES})

# Files Resumable Upload Integration Test Suite (FILES-005-T06)
add_executable(securecloud_files_resumable_upload_integration_test
    files_resumable_upload_integration_test.cpp
)

target_link_libraries(securecloud_files_resumable_upload_integration_test PRIVATE
    securecloud::files_service
    securecloud::files_storage
    securecloud::files_db
    securecloud::files_config
    securecloud::common
    securecloud_proto
    gRPC::grpc++
    securecloud::compiler_flags
    GTest::gtest_main
)

target_compile_definitions(securecloud_files_resumable_upload_integration_test PRIVATE
    SECURECLOUD_DEV_PKI_DIR="${CMAKE_SOURCE_DIR}/deploy/dev-pki"
)

if(WIN32)
    target_link_libraries(securecloud_files_resumable_upload_integration_test PRIVATE ws2_32)
endif()

gtest_discover_tests(securecloud_files_resumable_upload_integration_test ${SECURECLOUD_TEST_PROPERTIES})

# Files Whole-Object Finalization Integration Test Suite (FILES-006-T06)
add_executable(securecloud_files_finalization_integration_test
    files_finalization_integration_test.cpp
)

target_link_libraries(securecloud_files_finalization_integration_test PRIVATE
    securecloud::files_service
    securecloud::files_storage
    securecloud::files_db
    securecloud::files_config
    securecloud::common
    securecloud_proto
    gRPC::grpc++
    securecloud::compiler_flags
    GTest::gtest_main
)

target_compile_definitions(securecloud_files_finalization_integration_test PRIVATE
    SECURECLOUD_DEV_PKI_DIR="${CMAKE_SOURCE_DIR}/deploy/dev-pki"
)

if(WIN32)
    target_link_libraries(securecloud_files_finalization_integration_test PRIVATE ws2_32)
endif()

gtest_discover_tests(securecloud_files_finalization_integration_test ${SECURECLOUD_TEST_PROPERTIES})

# Files Authorized Chunked Download Integration Test Suite (FILES-007-T06)
add_executable(securecloud_files_download_integration_test
    files_download_integration_test.cpp
)

target_link_libraries(securecloud_files_download_integration_test PRIVATE
    securecloud::files_service
    securecloud::files_storage
    securecloud::files_db
    securecloud::files_config
    securecloud::common
    securecloud_proto
    gRPC::grpc++
    securecloud::compiler_flags
    GTest::gtest_main
)

target_compile_definitions(securecloud_files_download_integration_test PRIVATE
    SECURECLOUD_DEV_PKI_DIR="${CMAKE_SOURCE_DIR}/deploy/dev-pki"
)

if(WIN32)
    target_link_libraries(securecloud_files_download_integration_test PRIVATE ws2_32)
endif()

gtest_discover_tests(securecloud_files_download_integration_test ${SECURECLOUD_TEST_PROPERTIES})

# Files Capability-Based Access Authorization Integration Test Suite (FILES-008-T06)
add_executable(securecloud_files_capability_integration_test
    files_capability_integration_test.cpp
)

target_link_libraries(securecloud_files_capability_integration_test PRIVATE
    securecloud::files_service
    securecloud::files_storage
    securecloud::files_db
    securecloud::files_config
    securecloud::common
    securecloud::auth
    securecloud::json
    securecloud_proto
    gRPC::grpc++
    securecloud::compiler_flags
    GTest::gtest_main
)

target_compile_definitions(securecloud_files_capability_integration_test PRIVATE
    SECURECLOUD_DEV_PKI_DIR="${CMAKE_SOURCE_DIR}/deploy/dev-pki"
)

if(WIN32)
    target_link_libraries(securecloud_files_capability_integration_test PRIVATE ws2_32)
endif()

gtest_discover_tests(securecloud_files_capability_integration_test ${SECURECLOUD_TEST_PROPERTIES})

# Files Concurrency Bulkheads & Resource Controls Integration Test Suite (FILES-009-T06)
add_executable(securecloud_files_concurrency_integration_test
    files_concurrency_integration_test.cpp
)

target_link_libraries(securecloud_files_concurrency_integration_test PRIVATE
    securecloud::files_service
    securecloud::files_storage
    securecloud::files_db
    securecloud::files_config
    securecloud::common
    securecloud_proto
    gRPC::grpc++
    securecloud::compiler_flags
    GTest::gtest_main
)

target_compile_definitions(securecloud_files_concurrency_integration_test PRIVATE
    SECURECLOUD_DEV_PKI_DIR="${CMAKE_SOURCE_DIR}/deploy/dev-pki"
)

if(WIN32)
    target_link_libraries(securecloud_files_concurrency_integration_test PRIVATE ws2_32)
endif()

gtest_discover_tests(securecloud_files_concurrency_integration_test ${SECURECLOUD_TEST_PROPERTIES})

# Gateway Streaming TLS 1.3 / mTLS Integration Test Suite (GW-010-T04)
add_executable(securecloud_gateway_streaming_integration_test
    gateway_streaming_integration_test.cpp
)

target_link_libraries(securecloud_gateway_streaming_integration_test PRIVATE
    securecloud::gateway_http
    securecloud::gateway_grpc
    securecloud::gateway_tls
    securecloud::gateway_config
    securecloud_proto
    securecloud::common
    securecloud::httplib
    securecloud::json
    OpenSSL::SSL
    OpenSSL::Crypto
    securecloud::compiler_flags
    GTest::gtest
)

target_compile_definitions(securecloud_gateway_streaming_integration_test PRIVATE
    SECURECLOUD_DEV_PKI_DIR="${CMAKE_SOURCE_DIR}/deploy/dev-pki"
)

if(WIN32)
    target_link_libraries(securecloud_gateway_streaming_integration_test PRIVATE ws2_32)
endif()

gtest_discover_tests(securecloud_gateway_streaming_integration_test ${SECURECLOUD_TEST_PROPERTIES})

# Auth Persistence Integration Test Suite (AUTH-002-T06)
add_executable(securecloud_auth_persistence_integration_test
    auth_persistence_integration_test.cpp
)

target_link_libraries(securecloud_auth_persistence_integration_test PRIVATE
    securecloud::auth
    securecloud::common
    securecloud::compiler_flags
    GTest::gtest
)

if(WIN32)
    target_link_libraries(securecloud_auth_persistence_integration_test PRIVATE ws2_32)
endif()

gtest_discover_tests(securecloud_auth_persistence_integration_test ${SECURECLOUD_TEST_PROPERTIES})

# Auth Authentication End-to-End Integration Test Suite (AUTH-003-T06)
add_executable(securecloud_auth_authentication_integration_test
    auth_authentication_integration_test.cpp
)

target_link_libraries(securecloud_auth_authentication_integration_test PRIVATE
    securecloud::auth
    securecloud::common
    securecloud_proto
    OpenSSL::Crypto
    securecloud::compiler_flags
    GTest::gtest_main
)

if(WIN32)
    target_link_libraries(securecloud_auth_authentication_integration_test PRIVATE ws2_32)
endif()

gtest_discover_tests(securecloud_auth_authentication_integration_test ${SECURECLOUD_TEST_PROPERTIES})

# Auth Session End-to-End Integration Test Suite (AUTH-004-T06)
add_executable(securecloud_auth_session_integration_test
    auth_session_integration_test.cpp
)

target_link_libraries(securecloud_auth_session_integration_test PRIVATE
    securecloud::auth
    securecloud::common
    securecloud_proto
    OpenSSL::Crypto
    securecloud::compiler_flags
    GTest::gtest_main
)

if(WIN32)
    target_link_libraries(securecloud_auth_session_integration_test PRIVATE ws2_32)
endif()

gtest_discover_tests(securecloud_auth_session_integration_test ${SECURECLOUD_TEST_PROPERTIES})

# Auth Token End-to-End Integration Test Suite (AUTH-005-T06)
add_executable(securecloud_auth_token_integration_test
    auth_token_integration_test.cpp
)

target_link_libraries(securecloud_auth_token_integration_test PRIVATE
    securecloud::auth
    securecloud::gateway_http
    securecloud::common
    securecloud_proto
    OpenSSL::Crypto
    securecloud::compiler_flags
    GTest::gtest_main
    GTest::gmock_main
)

if(WIN32)
    target_link_libraries(securecloud_auth_token_integration_test PRIVATE ws2_32)
endif()

gtest_discover_tests(securecloud_auth_token_integration_test ${SECURECLOUD_TEST_PROPERTIES})

# Auth MFA End-to-End Integration Test Suite (AUTH-006-T06)
add_executable(securecloud_auth_mfa_integration_test
    auth_mfa_integration_test.cpp
)

target_link_libraries(securecloud_auth_mfa_integration_test PRIVATE
    securecloud::auth
    securecloud::gateway_http
    securecloud::common
    securecloud_proto
    OpenSSL::Crypto
    securecloud::compiler_flags
    GTest::gtest_main
    GTest::gmock_main
)

if(WIN32)
    target_link_libraries(securecloud_auth_mfa_integration_test PRIVATE ws2_32)
endif()

gtest_discover_tests(securecloud_auth_mfa_integration_test ${SECURECLOUD_TEST_PROPERTIES})

# Auth Device End-to-End Integration Test Suite (AUTH-007-T06)
add_executable(securecloud_auth_device_integration_test
    auth_device_integration_test.cpp
)

target_link_libraries(securecloud_auth_device_integration_test PRIVATE
    securecloud::auth
    securecloud::gateway_http
    securecloud::common
    securecloud_proto
    OpenSSL::Crypto
    securecloud::compiler_flags
    GTest::gtest_main
    GTest::gmock_main
)

if(WIN32)
    target_link_libraries(securecloud_auth_device_integration_test PRIVATE ws2_32)
endif()

gtest_discover_tests(securecloud_auth_device_integration_test ${SECURECLOUD_TEST_PROPERTIES})

# Auth Public Cryptographic Identity End-to-End Integration Test Suite (AUTH-008-T05)
add_executable(securecloud_auth_crypto_identity_integration_test
    auth_crypto_identity_integration_test.cpp
)

target_link_libraries(securecloud_auth_crypto_identity_integration_test PRIVATE
    securecloud::auth
    securecloud::gateway_http
    securecloud::common
    securecloud_proto
    OpenSSL::Crypto
    securecloud::compiler_flags
    GTest::gtest_main
    GTest::gmock_main
)

if(WIN32)
    target_link_libraries(securecloud_auth_crypto_identity_integration_test PRIVATE ws2_32)
endif()

gtest_discover_tests(securecloud_auth_crypto_identity_integration_test ${SECURECLOUD_TEST_PROPERTIES})

# Auth Prekey Concurrency & Stress Integration Test Suite (AUTH-009-T05)
add_executable(securecloud_auth_prekey_concurrency_integration_test
    auth_prekey_concurrency_integration_test.cpp
)

target_link_libraries(securecloud_auth_prekey_concurrency_integration_test PRIVATE
    securecloud::auth
    securecloud::common
    securecloud_proto
    OpenSSL::Crypto
    securecloud::compiler_flags
    GTest::gtest_main
    GTest::gmock_main
)

if(WIN32)
    target_link_libraries(securecloud_auth_prekey_concurrency_integration_test PRIVATE ws2_32)
endif()

gtest_discover_tests(securecloud_auth_prekey_concurrency_integration_test ${SECURECLOUD_TEST_PROPERTIES})

# Gateway Auth End-to-End Live Integration Test Suite (AUTH-010-T05)
add_executable(securecloud_gateway_auth_e2e_integration_test
    gateway_auth_e2e_integration_test.cpp
)

target_link_libraries(securecloud_gateway_auth_e2e_integration_test PRIVATE
    securecloud::auth
    securecloud::gateway_config
    securecloud::gateway_http
    securecloud::gateway_grpc
    securecloud::gateway_health
    securecloud::common
    securecloud_proto
    OpenSSL::Crypto
    OpenSSL::SSL
    securecloud::compiler_flags
    GTest::gtest_main
    GTest::gmock_main
)

target_compile_definitions(securecloud_gateway_auth_e2e_integration_test PRIVATE
    SECURECLOUD_DEV_PKI_DIR="${CMAKE_SOURCE_DIR}/deploy/dev-pki"
)

if(WIN32)
    target_link_libraries(securecloud_gateway_auth_e2e_integration_test PRIVATE ws2_32)
endif()

gtest_discover_tests(securecloud_gateway_auth_e2e_integration_test ${SECURECLOUD_TEST_PROPERTIES})

# Messaging Service Lifecycle & Foundation Integration Test Suite (MSG-001-T06)
add_executable(securecloud_messaging_service_lifecycle_integration_test
    messaging_service_lifecycle_integration_test.cpp
)

target_link_libraries(securecloud_messaging_service_lifecycle_integration_test PRIVATE
    securecloud::messaging
    securecloud::common
    securecloud_proto
    securecloud::compiler_flags
    GTest::gtest_main
    GTest::gmock_main
)

target_compile_definitions(securecloud_messaging_service_lifecycle_integration_test PRIVATE
    SECURECLOUD_DEV_PKI_DIR="${CMAKE_SOURCE_DIR}/deploy/dev-pki"
)

if(WIN32)
    target_link_libraries(securecloud_messaging_service_lifecycle_integration_test PRIVATE ws2_32)
endif()

gtest_discover_tests(securecloud_messaging_service_lifecycle_integration_test ${SECURECLOUD_TEST_PROPERTIES})

# Messaging Conversation & Membership Integration Test Suite (MSG-003-T06)
add_executable(securecloud_messaging_conversation_integration_test
    messaging_conversation_integration_test.cpp
)

target_link_libraries(securecloud_messaging_conversation_integration_test PRIVATE
    securecloud::messaging
    securecloud::gateway_http
    securecloud::gateway_grpc
    securecloud::gateway_config
    securecloud::common
    securecloud_proto
    securecloud::json
    OpenSSL::Crypto
    OpenSSL::SSL
    securecloud::compiler_flags
    GTest::gtest_main
    GTest::gmock_main
)

target_compile_definitions(securecloud_messaging_conversation_integration_test PRIVATE
    SECURECLOUD_DEV_PKI_DIR="${CMAKE_SOURCE_DIR}/deploy/dev-pki"
)

if(WIN32)
    target_link_libraries(securecloud_messaging_conversation_integration_test PRIVATE ws2_32)
endif()

gtest_discover_tests(securecloud_messaging_conversation_integration_test ${SECURECLOUD_TEST_PROPERTIES})

# Messaging ScyllaDB Persistence Integration Test Suite (MSG-004-T06)
add_executable(securecloud_messaging_persistence_integration_test
    messaging_persistence_integration_test.cpp
)

target_link_libraries(securecloud_messaging_persistence_integration_test PRIVATE
    securecloud::messaging
    securecloud::common
    securecloud_proto
    OpenSSL::Crypto
    securecloud::compiler_flags
    GTest::gtest_main
)

if(WIN32)
    target_link_libraries(securecloud_messaging_persistence_integration_test PRIVATE ws2_32)
endif()

gtest_discover_tests(securecloud_messaging_persistence_integration_test ${SECURECLOUD_TEST_PROPERTIES})

# Messaging End-to-End Submission & Idempotency Integration Test Suite (MSG-005-T06)
add_executable(securecloud_messaging_submission_integration_test
    messaging_submission_integration_test.cpp
)

target_link_libraries(securecloud_messaging_submission_integration_test PRIVATE
    securecloud::messaging
    securecloud::gateway_http
    securecloud::gateway_grpc
    securecloud::gateway_config
    securecloud::common
    securecloud_proto
    securecloud::json
    OpenSSL::Crypto
    OpenSSL::SSL
    securecloud::compiler_flags
    GTest::gtest_main
    GTest::gmock_main
)

target_compile_definitions(securecloud_messaging_submission_integration_test PRIVATE
    SECURECLOUD_DEV_PKI_DIR="${CMAKE_SOURCE_DIR}/deploy/dev-pki"
)

if(WIN32)
    target_link_libraries(securecloud_messaging_submission_integration_test PRIVATE ws2_32)
endif()

gtest_discover_tests(securecloud_messaging_submission_integration_test ${SECURECLOUD_TEST_PROPERTIES})

# Messaging E2E Envelope Integration Test Suite (MSG-006-T06)
add_executable(securecloud_messaging_e2e_envelope_integration_test
    messaging_e2e_envelope_integration_test.cpp
)

target_link_libraries(securecloud_messaging_e2e_envelope_integration_test PRIVATE
    securecloud::messaging
    securecloud::gateway_http
    securecloud::gateway_grpc
    securecloud::gateway_config
    securecloud::common
    securecloud_proto
    securecloud::json
    OpenSSL::Crypto
    OpenSSL::SSL
    securecloud::compiler_flags
    GTest::gtest_main
    GTest::gmock_main
)

target_compile_definitions(securecloud_messaging_e2e_envelope_integration_test PRIVATE
    SECURECLOUD_DEV_PKI_DIR="${CMAKE_SOURCE_DIR}/deploy/dev-pki"
)

if(WIN32)
    target_link_libraries(securecloud_messaging_e2e_envelope_integration_test PRIVATE ws2_32)
endif()

gtest_discover_tests(securecloud_messaging_e2e_envelope_integration_test ${SECURECLOUD_TEST_PROPERTIES})

# Messaging Delivery State & Read Receipts Integration Test Suite (MSG-008-T06)
add_executable(securecloud_msg_read_receipts_integration_test
    messaging_delivery_state_read_receipts_integration_test.cpp
)

set_target_properties(securecloud_msg_read_receipts_integration_test PROPERTIES
    OUTPUT_NAME "securecloud_messaging_delivery_state_read_receipts_integration_test"
)
add_executable(securecloud_messaging_delivery_state_read_receipts_integration_test ALIAS securecloud_msg_read_receipts_integration_test)

target_link_libraries(securecloud_msg_read_receipts_integration_test PRIVATE
    securecloud::messaging
    securecloud::gateway_http
    securecloud::gateway_grpc
    securecloud::gateway_config
    securecloud::common
    securecloud_proto
    securecloud::json
    OpenSSL::Crypto
    OpenSSL::SSL
    securecloud::compiler_flags
    GTest::gtest_main
    GTest::gmock_main
)

target_compile_definitions(securecloud_msg_read_receipts_integration_test PRIVATE
    SECURECLOUD_DEV_PKI_DIR="${CMAKE_SOURCE_DIR}/deploy/dev-pki"
)

if(WIN32)
    target_link_libraries(securecloud_msg_read_receipts_integration_test PRIVATE ws2_32)
endif()

gtest_discover_tests(securecloud_msg_read_receipts_integration_test ${SECURECLOUD_TEST_PROPERTIES})

# Audit Service Lifecycle & mTLS Health Probe Integration Test Suite (AUDIT-001-T05)
add_executable(securecloud_audit_service_lifecycle_integration_test
    audit_service_lifecycle_integration_test.cpp
)

target_link_libraries(securecloud_audit_service_lifecycle_integration_test PRIVATE
    securecloud::audit_server
    securecloud::audit_config
    securecloud::common
    securecloud_proto
    gRPC::grpc++
    securecloud::compiler_flags
    GTest::gtest_main
)

target_compile_definitions(securecloud_audit_service_lifecycle_integration_test PRIVATE
    SECURECLOUD_DEV_PKI_DIR="${CMAKE_SOURCE_DIR}/deploy/dev-pki"
)

if(WIN32)
    target_link_libraries(securecloud_audit_service_lifecycle_integration_test PRIVATE ws2_32)
endif()

gtest_discover_tests(securecloud_audit_service_lifecycle_integration_test ${SECURECLOUD_TEST_PROPERTIES})

# Messaging Online Sync Integration Test Suite (MSG-009-T06)
add_executable(securecloud_messaging_online_sync_integration_test
    messaging_online_sync_integration_test.cpp
)

target_link_libraries(securecloud_messaging_online_sync_integration_test PRIVATE
    securecloud::messaging
    securecloud::gateway_http
    securecloud::gateway_grpc
    securecloud::gateway_config
    securecloud::common
    securecloud_proto
    securecloud::json
    OpenSSL::Crypto
    OpenSSL::SSL
    securecloud::compiler_flags
    GTest::gtest_main
    GTest::gmock_main
)

target_compile_definitions(securecloud_messaging_online_sync_integration_test PRIVATE
    SECURECLOUD_DEV_PKI_DIR="${CMAKE_SOURCE_DIR}/deploy/dev-pki"
)

if(WIN32)
    target_link_libraries(securecloud_messaging_online_sync_integration_test PRIVATE ws2_32)
endif()

gtest_discover_tests(securecloud_messaging_online_sync_integration_test ${SECURECLOUD_TEST_PROPERTIES})

# Messaging Presence & Non-Conflation Invariant Integration Test Suite (MSG-010-T07)
add_executable(securecloud_messaging_presence_integration_test
    messaging_presence_integration_test.cpp
)

target_link_libraries(securecloud_messaging_presence_integration_test PRIVATE
    securecloud::messaging
    securecloud::gateway_http
    securecloud::gateway_grpc
    securecloud::gateway_config
    securecloud::common
    securecloud::httplib
    securecloud_proto
    securecloud::json
    OpenSSL::Crypto
    OpenSSL::SSL
    securecloud::compiler_flags
    GTest::gtest_main
    GTest::gmock
)

target_compile_definitions(securecloud_messaging_presence_integration_test PRIVATE
    SECURECLOUD_DEV_PKI_DIR="${CMAKE_SOURCE_DIR}/deploy/dev-pki"
)

if(WIN32)
    target_link_libraries(securecloud_messaging_presence_integration_test PRIVATE ws2_32)
endif()

gtest_discover_tests(securecloud_messaging_presence_integration_test ${SECURECLOUD_TEST_PROPERTIES})

# Messaging Multi-Device E2E Integration Test Suite (MSG-011-T06)
add_executable(securecloud_messaging_multi_device_integration_test
    messaging_multi_device_integration_test.cpp
)

target_link_libraries(securecloud_messaging_multi_device_integration_test PRIVATE
    securecloud::messaging
    securecloud::gateway_http
    securecloud::gateway_grpc
    securecloud::gateway_config
    securecloud::common
    securecloud::httplib
    securecloud_proto
    securecloud::json
    OpenSSL::Crypto
    OpenSSL::SSL
    securecloud::compiler_flags
    GTest::gtest_main
    GTest::gmock
)

target_compile_definitions(securecloud_messaging_multi_device_integration_test PRIVATE
    SECURECLOUD_DEV_PKI_DIR="${CMAKE_SOURCE_DIR}/deploy/dev-pki"
)

if(WIN32)
    target_link_libraries(securecloud_messaging_multi_device_integration_test PRIVATE ws2_32)
endif()

gtest_discover_tests(securecloud_messaging_multi_device_integration_test ${SECURECLOUD_TEST_PROPERTIES})

# Messaging Capacity, Multi-Device Fan-Out & ScyllaDB Access Pattern Load Test Suite (MSG-012-T03)
add_executable(securecloud_messaging_capacity_load_test
    messaging_capacity_load_test.cpp
)

target_link_libraries(securecloud_messaging_capacity_load_test PRIVATE
    securecloud::messaging
    securecloud::common
    securecloud_proto
    OpenSSL::Crypto
    securecloud::compiler_flags
    GTest::gtest_main
)

if(WIN32)
    target_link_libraries(securecloud_messaging_capacity_load_test PRIVATE ws2_32)
endif()

gtest_discover_tests(securecloud_messaging_capacity_load_test ${SECURECLOUD_TEST_PROPERTIES})

# Messaging Fault Recovery & Chaos Engineering Test Suite (MSG-012-T04)
add_executable(securecloud_messaging_fault_recovery_integration_test
    messaging_fault_recovery_integration_test.cpp
)

target_link_libraries(securecloud_messaging_fault_recovery_integration_test PRIVATE
    securecloud::messaging
    securecloud::common
    securecloud_proto
    OpenSSL::Crypto
    securecloud::compiler_flags
    GTest::gtest_main
)

if(WIN32)
    target_link_libraries(securecloud_messaging_fault_recovery_integration_test PRIVATE ws2_32)
endif()

gtest_discover_tests(securecloud_messaging_fault_recovery_integration_test ${SECURECLOUD_TEST_PROPERTIES})

# Files Gateway & Audit E2E Integration Test Suite (FILES-010-T05)
add_executable(securecloud_files_e2e_gateway_audit_integration_test
    files_e2e_gateway_audit_integration_test.cpp
)

target_link_libraries(securecloud_files_e2e_gateway_audit_integration_test PRIVATE
    securecloud::files_audit
    securecloud::files_db
    securecloud::files_config
    securecloud::gateway_http
    securecloud::gateway_grpc
    securecloud::gateway_config
    securecloud::common
    securecloud::httplib
    securecloud_proto
    securecloud::json
    OpenSSL::Crypto
    OpenSSL::SSL
    securecloud::compiler_flags
    GTest::gmock
    GTest::gtest
)

target_compile_definitions(securecloud_files_e2e_gateway_audit_integration_test PRIVATE
    SECURECLOUD_DEV_PKI_DIR="${CMAKE_SOURCE_DIR}/deploy/dev-pki"
)

if(WIN32)
    target_link_libraries(securecloud_files_e2e_gateway_audit_integration_test PRIVATE ws2_32)
endif()

gtest_discover_tests(securecloud_files_e2e_gateway_audit_integration_test ${SECURECLOUD_TEST_PROPERTIES})

# Audit Service ClickHouse 24.8 Live Integration Test Suite (AUDIT-003-T06)
add_executable(securecloud_audit_clickhouse_integration_test
    audit_clickhouse_integration_test.cpp
)

target_link_libraries(securecloud_audit_clickhouse_integration_test PRIVATE
    securecloud::audit_repository
    securecloud::audit_domain
    securecloud::common
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_audit_clickhouse_integration_test ${SECURECLOUD_TEST_PROPERTIES})
