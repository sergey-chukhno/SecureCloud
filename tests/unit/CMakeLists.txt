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
        DEPENDS securecloud_proto_smoke_test
        COMMENT "Executing Protobuf & gRPC generated-contracts validation smoke test..."
        VERBATIM
    )
else()
    add_custom_target(verify-contracts
        COMMAND $<TARGET_FILE:securecloud_proto_smoke_test>
        DEPENDS securecloud_proto_smoke_test
        COMMENT "Executing Protobuf & gRPC generated-contracts validation smoke test..."
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

