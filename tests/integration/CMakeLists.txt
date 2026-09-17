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
