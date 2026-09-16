cmake_minimum_required(VERSION 3.28)

project(SecureCloud
    VERSION 0.1.0
    DESCRIPTION "SecureCloud Enterprise E2EE Messaging, Storage & Audit Platform"
    LANGUAGES CXX
)

# Global standard enforcement for C++20 baseline
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Standard CMake test build option
option(BUILD_TESTING "Build test suite targets" ON)

if(BUILD_TESTING)
    enable_testing()
endif()

# Add cmake/modules to module lookup path
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules")

# Load compiler flags target definition
include(SecureCloudCompilerFlags)

# Load dependency discovery module
include(SecureCloudDependencies)

# Register production source tree
add_subdirectory(src)

# Register test suite directory only when testing is enabled
if(BUILD_TESTING)
    add_subdirectory(tests)
endif()
