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

# Proactive discovery of compiler and MSYS2/MinGW prefixes on Windows
if(WIN32)
    # 1. Inspect compiler prefix if compiler is available
    if(CMAKE_CXX_COMPILER)
        get_filename_component(_COMPILER_BIN_DIR "${CMAKE_CXX_COMPILER}" DIRECTORY)
        get_filename_component(_COMPILER_PREFIX "${_COMPILER_BIN_DIR}" DIRECTORY)
        if(EXISTS "${_COMPILER_PREFIX}" AND NOT "${_COMPILER_PREFIX}" IN_LIST CMAKE_PREFIX_PATH)
            list(PREPEND CMAKE_PREFIX_PATH "${_COMPILER_PREFIX}")
            message(STATUS "[SecureCloud] Added compiler prefix to CMAKE_PREFIX_PATH: ${_COMPILER_PREFIX}")
        endif()
    endif()

    # 2. Inspect MSYSTEM_PREFIX if defined in environment
    if(DEFINED ENV{MSYSTEM_PREFIX} AND EXISTS "$ENV{MSYSTEM_PREFIX}" AND NOT "$ENV{MSYSTEM_PREFIX}" IN_LIST CMAKE_PREFIX_PATH)
        list(PREPEND CMAKE_PREFIX_PATH "$ENV{MSYSTEM_PREFIX}")
        message(STATUS "[SecureCloud] Added MSYSTEM_PREFIX to CMAKE_PREFIX_PATH: $ENV{MSYSTEM_PREFIX}")
    endif()

    # 3. Proactively discover well-known MSYS2 prefixes (mingw64, ucrt64, clang64)
    foreach(_CANDIDATE "C:/msys64/mingw64" "C:/msys64/ucrt64" "C:/msys64/clang64")
        if(EXISTS "${_CANDIDATE}" AND NOT "${_CANDIDATE}" IN_LIST CMAKE_PREFIX_PATH)
            list(APPEND CMAKE_PREFIX_PATH "${_CANDIDATE}")
            message(STATUS "[SecureCloud] Proactively discovered MSYS2 prefix: ${_CANDIDATE}")
        endif()
    endforeach()
endif()

# 1. Discover gRPC dependency (finds gRPC and its Protobuf dependency via CONFIG mode)
message(STATUS "[SecureCloud] Discovering gRPC framework...")
find_package(gRPC CONFIG QUIET)
if(NOT gRPC_FOUND)
    find_package(gRPC QUIET)
endif()
if(NOT gRPC_FOUND)
    message(FATAL_ERROR
        "[SecureCloud] gRPC package configuration file (gRPCConfig.cmake / grpc-config.cmake) was not found.\n"
        "  Active CMAKE_PREFIX_PATH: ${CMAKE_PREFIX_PATH}\n"
        "  Remediation:\n"
        "    - On MSYS2 MinGW64: Run 'pacman -S --needed mingw-w64-x86_64-grpc mingw-w64-x86_64-protobuf mingw-w64-x86_64-openssl mingw-w64-x86_64-gtest'\n"
        "    - On MSYS2 UCRT64:  Run 'pacman -S --needed mingw-w64-ucrt-x86_64-grpc mingw-w64-ucrt-x86_64-protobuf mingw-w64-ucrt-x86_64-openssl mingw-w64-ucrt-x86_64-gtest'\n"
        "    - On MSVC / vcpkg:  Ensure VCPKG_ROOT is set and pass -DCMAKE_TOOLCHAIN_FILE=\"$env:VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake\""
    )
endif()
if(TARGET gRPC::grpc++)
    message(STATUS "[SecureCloud] Discovered gRPC target: gRPC::grpc++")
else()
    message(FATAL_ERROR "[SecureCloud] gRPC package found but gRPC::grpc++ target is unavailable")
endif()

# Discover gRPC C++ plugin executable
if(TARGET gRPC::grpc_cpp_plugin)
    get_target_property(GRPC_CPP_PLUGIN_BIN gRPC::grpc_cpp_plugin LOCATION)
    message(STATUS "[SecureCloud] Discovered grpc_cpp_plugin target: gRPC::grpc_cpp_plugin (${GRPC_CPP_PLUGIN_BIN})")
else()
    find_program(GRPC_CPP_PLUGIN_BIN NAMES grpc_cpp_plugin
        HINTS
        ${CMAKE_PREFIX_PATH}
        "${_COMPILER_PREFIX}/bin"
        "$ENV{MSYSTEM_PREFIX}/bin"
        "C:/msys64/mingw64/bin"
        "C:/msys64/ucrt64/bin"
        "C:/msys64/clang64/bin"
        PATH_SUFFIXES bin
    )
    if(GRPC_CPP_PLUGIN_BIN)
        message(STATUS "[SecureCloud] Discovered grpc_cpp_plugin executable: ${GRPC_CPP_PLUGIN_BIN}")
    else()
        message(FATAL_ERROR "[SecureCloud] grpc_cpp_plugin compiler executable was not found")
    endif()
endif()

# 2. Discover Protobuf dependency
message(STATUS "[SecureCloud] Discovering Protobuf framework...")
find_package(Protobuf CONFIG QUIET)
if(NOT Protobuf_FOUND AND NOT protobuf_FOUND)
    find_package(Protobuf QUIET)
endif()
if(NOT Protobuf_FOUND AND NOT protobuf_FOUND)
    message(FATAL_ERROR
        "[SecureCloud] Protobuf package was not found.\n"
        "  Active CMAKE_PREFIX_PATH: ${CMAKE_PREFIX_PATH}\n"
        "  Remediation:\n"
        "    - On MSYS2 MinGW64: Run 'pacman -S --needed mingw-w64-x86_64-protobuf'\n"
        "    - On MSYS2 UCRT64:  Run 'pacman -S --needed mingw-w64-ucrt-x86_64-protobuf'\n"
        "    - On MSVC / vcpkg:  Ensure VCPKG_ROOT is set and pass -DCMAKE_TOOLCHAIN_FILE=\"$env:VCPKG_ROOT/scripts/buildsystems/vcpkg.cmake\""
    )
endif()
if(TARGET Protobuf::libprotobuf)
    message(STATUS "[SecureCloud] Discovered Protobuf target: Protobuf::libprotobuf")
elseif(TARGET protobuf::libprotobuf)
    add_library(Protobuf::libprotobuf ALIAS protobuf::libprotobuf)
    message(STATUS "[SecureCloud] Discovered Protobuf target: protobuf::libprotobuf (Aliased to Protobuf::libprotobuf)")
else()
    message(FATAL_ERROR "[SecureCloud] Protobuf package found but libprotobuf target is unavailable")
endif()

# Discover protoc compiler executable
if(TARGET protobuf::protoc)
    get_target_property(PROTOC_BIN protobuf::protoc LOCATION)
    message(STATUS "[SecureCloud] Discovered protoc target: protobuf::protoc (${PROTOC_BIN})")
else()
    find_program(PROTOC_BIN NAMES protoc
        HINTS
        ${CMAKE_PREFIX_PATH}
        "${_COMPILER_PREFIX}/bin"
        "$ENV{MSYSTEM_PREFIX}/bin"
        "C:/msys64/mingw64/bin"
        "C:/msys64/ucrt64/bin"
        "C:/msys64/clang64/bin"
        PATH_SUFFIXES bin
    )
    if(PROTOC_BIN)
        message(STATUS "[SecureCloud] Discovered protoc executable: ${PROTOC_BIN}")
    else()
        message(FATAL_ERROR "[SecureCloud] protoc compiler executable was not found")
    endif()
endif()

# 3. Discover testing dependencies when BUILD_TESTING is enabled
if(BUILD_TESTING)
    message(STATUS "[SecureCloud] Discovering GoogleTest testing framework...")
    find_package(GTest REQUIRED)
    include(GoogleTest)
    message(STATUS "[SecureCloud] GoogleTest framework discovered successfully (Targets: GTest::gtest, GTest::gtest_main, GTest::gmock)")
endif()

message(STATUS "[SecureCloud] Dependency discovery pipeline established successfully")
