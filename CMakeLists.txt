cmake_minimum_required(VERSION 3.28)

if(WIN32)
    set(X_VCPKG_APPLOCAL_DEPS_SERIALIZED ON CACHE BOOL "Serialize vcpkg applocal dependency copying to prevent parallel link file-lock contention")
    # Target Windows 10 (0x0A00) baseline across all Windows toolchains (MSVC and MinGW-w64)
    add_compile_definitions(_WIN32_WINNT=0x0A00 WINVER=0x0A00)
    # Restrict parallel linker jobs under Ninja to 1 to eliminate MSVC LNK1102 (out of memory)
    # and prevent concurrent vcpkg z-applocal DLL file-lock collisions in shared directories
    set_property(GLOBAL PROPERTY JOB_POOLS link_pool=1)
    set(CMAKE_JOB_POOL_LINK link_pool)
endif()

project(SecureCloud
    VERSION 0.1.0
    DESCRIPTION "SecureCloud Enterprise E2EE Messaging, Storage & Audit Platform"
    LANGUAGES CXX
)

if(MSVC)
    # Optimize debug build disk footprint:
    # /DEBUG:FASTLINK indexes symbols in .obj files instead of duplicating into each .pdb (~20 GB saved)
    # /INCREMENTAL:NO eliminates .ilk database files across 150+ test binaries (~17.5 GB saved)
    add_link_options(
        "$<$<CONFIG:Debug>:/DEBUG:FASTLINK>"
        "$<$<CONFIG:Debug>:/INCREMENTAL:NO>"
    )
endif()

if(MINGW)
    # Prevent CMake from passing -isystem for imported targets. Under MinGW GCC,
    # passing toolchain system include paths (-isystem C:/msys64/mingw64/include)
    # alters the include search order and breaks GCC's standard library #include_next <stdlib.h>.
    set(CMAKE_NO_SYSTEM_FROM_IMPORTED ON)
    if(DEFINED ENV{MSYSTEM_PREFIX})
        list(APPEND CMAKE_CXX_IMPLICIT_INCLUDE_DIRECTORIES "$ENV{MSYSTEM_PREFIX}/include" "$ENV{MSYSTEM_PREFIX}/x86_64-w64-mingw32/include")
        list(APPEND CMAKE_C_IMPLICIT_INCLUDE_DIRECTORIES "$ENV{MSYSTEM_PREFIX}/include" "$ENV{MSYSTEM_PREFIX}/x86_64-w64-mingw32/include")
    endif()
    list(APPEND CMAKE_CXX_IMPLICIT_INCLUDE_DIRECTORIES
        "C:/msys64/mingw64/include"
        "C:/msys64/mingw64/x86_64-w64-mingw32/include"
        "C:/msys64/ucrt64/include"
        "C:/msys64/ucrt64/x86_64-w64-mingw32/include"
        "/mingw64/include"
        "/mingw64/x86_64-w64-mingw32/include"
        "/ucrt64/include"
        "/ucrt64/x86_64-w64-mingw32/include"
    )
    list(APPEND CMAKE_C_IMPLICIT_INCLUDE_DIRECTORIES
        "C:/msys64/mingw64/include"
        "C:/msys64/mingw64/x86_64-w64-mingw32/include"
        "C:/msys64/ucrt64/include"
        "C:/msys64/ucrt64/x86_64-w64-mingw32/include"
        "/mingw64/include"
        "/mingw64/x86_64-w64-mingw32/include"
        "/ucrt64/include"
        "/ucrt64/x86_64-w64-mingw32/include"
    )
endif()

# Global standard enforcement for C++20 baseline
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_SCAN_FOR_MODULES OFF)

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
