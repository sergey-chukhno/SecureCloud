# gRPC mTLS Integration Test Suite (SC10-T03)
add_executable(securecloud_mtls_integration_test
    mtls_integration_test.cpp
)

target_link_libraries(securecloud_mtls_integration_test PRIVATE
    securecloud::common
    securecloud_proto
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_mtls_integration_test)

# Health and Readiness Integration Test Suite (SC-013-T05)
add_executable(securecloud_health_integration_test
    health_integration_test.cpp
)

target_link_libraries(securecloud_health_integration_test PRIVATE
    securecloud::common
    securecloud_proto
    securecloud::compiler_flags
    GTest::gtest_main
)

target_compile_definitions(securecloud_health_integration_test PRIVATE
    SECURECLOUD_HEALTH_PROBE_BIN="$<TARGET_FILE:securecloud_health_probe>"
)

add_dependencies(securecloud_health_integration_test securecloud_health_probe)

gtest_discover_tests(securecloud_health_integration_test)

# Dedicated Health & Readiness mTLS Probe Runner CLI (SC-013-T06)
add_executable(securecloud_health_probe
    health_probe_cli.cpp
)

target_link_libraries(securecloud_health_probe PRIVATE
    securecloud::common
    securecloud_proto
    securecloud::compiler_flags
)
