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
gtest_discover_tests(securecloud_gtest_smoke_test)
