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

