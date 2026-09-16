include_guard(GLOBAL)

# SecureCloud CMake Dependency Discovery Module
# Provides a modern, target-based dependency resolution pattern without global include/link pollution.

message(STATUS "[SecureCloud] Initializing dependency discovery pipeline...")

# Diagnostic verification of active CMake toolchain
if(DEFINED CMAKE_TOOLCHAIN_FILE)
    message(STATUS "[SecureCloud] CMake Toolchain File active: ${CMAKE_TOOLCHAIN_FILE}")
else()
    message(STATUS "[SecureCloud] Standard host toolchain discovery active")
endif()

# Discover testing dependencies when BUILD_TESTING is enabled
if(BUILD_TESTING)
    message(STATUS "[SecureCloud] Discovering GoogleTest testing framework...")
    find_package(GTest REQUIRED)
    include(GoogleTest)
    message(STATUS "[SecureCloud] GoogleTest framework discovered successfully (Targets: GTest::gtest, GTest::gtest_main, GTest::gmock)")
endif()

message(STATUS "[SecureCloud] Dependency discovery pipeline established successfully")
