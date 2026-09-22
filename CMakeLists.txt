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

# Enforce 64-bit architecture requirement across all platforms
if(CMAKE_SIZEOF_VOID_P EQUAL 4)
    message(FATAL_ERROR
        "[SecureCloud] Error: A 32-bit (x86) architecture or compiler was detected (${CMAKE_CXX_COMPILER}). "
        "SecureCloud strictly requires a 64-bit (x64) target architecture across all dependencies (e.g. VCPKG_TARGET_TRIPLET=x64-windows). "
        "On Windows MSVC, please launch the 'x64 Native Tools Command Prompt for VS' (or run 'vcvars64.bat') "
        "and clean the build directory before re-configuring."
    )
endif()

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

# Load Protobuf and gRPC code generation module
include(SecureCloudProtobuf)

# Load formatting and static analysis tooling module
include(SecureCloudFormatting)

# Register Protobuf and gRPC contracts target
add_subdirectory(proto)

# Register production source tree
add_subdirectory(src)

# Register test suite directory only when testing is enabled
if(BUILD_TESTING)
    add_subdirectory(tests)
endif()
