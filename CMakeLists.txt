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

# Enable CTest integration at root project level
enable_testing()

# Add cmake/modules to module lookup path
list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules")

# Load compiler flags target definition
include(SecureCloudCompilerFlags)

# Register project source tree and test suite directories
add_subdirectory(src)
add_subdirectory(tests)
