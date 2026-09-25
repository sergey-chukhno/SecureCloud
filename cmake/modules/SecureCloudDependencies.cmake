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

    # 3. If no MSYS2 or compiler prefix was discovered, probe candidates (select first available, do not mix)
    if(NOT CMAKE_PREFIX_PATH)
        foreach(_CANDIDATE "C:/msys64/mingw64" "C:/msys64/ucrt64" "C:/msys64/clang64")
            if(EXISTS "${_CANDIDATE}")
                list(APPEND CMAKE_PREFIX_PATH "${_CANDIDATE}")
                message(STATUS "[SecureCloud] Proactively discovered MSYS2 prefix: ${_CANDIDATE}")
                break()
            endif()
        endforeach()
    endif()
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

# 4. Discover OpenSSL framework (needed for TLS transport and cpp-httplib HTTPS support)
if(APPLE AND NOT DEFINED OPENSSL_ROOT_DIR)
    if(EXISTS "/opt/homebrew/opt/openssl@3")
        set(OPENSSL_ROOT_DIR "/opt/homebrew/opt/openssl@3")
    elseif(EXISTS "/usr/local/opt/openssl@3")
        set(OPENSSL_ROOT_DIR "/usr/local/opt/openssl@3")
    endif()
endif()
find_package(OpenSSL QUIET)
if(TARGET OpenSSL::SSL AND TARGET OpenSSL::Crypto)
    message(STATUS "[SecureCloud] Discovered OpenSSL targets: OpenSSL::SSL, OpenSSL::Crypto (Version: ${OPENSSL_VERSION})")
endif()

# 5. Discover nlohmann_json serialization framework
message(STATUS "[SecureCloud] Discovering nlohmann_json...")
find_package(nlohmann_json CONFIG QUIET)
if(NOT nlohmann_json_FOUND)
    find_package(nlohmann_json QUIET)
endif()

if(TARGET nlohmann_json::nlohmann_json)
    if(NOT TARGET securecloud_json)
        add_library(securecloud_json INTERFACE)
        target_link_libraries(securecloud_json INTERFACE nlohmann_json::nlohmann_json)
        add_library(securecloud::json ALIAS securecloud_json)
    endif()
    message(STATUS "[SecureCloud] Discovered nlohmann_json target: securecloud::json")
else()
    message(FATAL_ERROR
        "[SecureCloud] nlohmann_json package was not found.\n"
        "  Active CMAKE_PREFIX_PATH: ${CMAKE_PREFIX_PATH}\n"
        "  Remediation:\n"
        "    - On macOS: Run 'brew install nlohmann-json'\n"
        "    - On MSYS2 MinGW64: Run 'pacman -S --needed mingw-w64-x86_64-nlohmann-json'\n"
        "    - On MSYS2 UCRT64:  Run 'pacman -S --needed mingw-w64-ucrt-x86_64-nlohmann-json'\n"
        "    - On MSVC / vcpkg:  Ensure vcpkg.json contains \"nlohmann-json\""
    )
endif()

# 6. Discover cpp-httplib HTTP runtime framework
message(STATUS "[SecureCloud] Discovering cpp-httplib...")
find_package(httplib CONFIG QUIET)
if(NOT httplib_FOUND)
    find_package(httplib QUIET)
endif()

if(NOT TARGET httplib::httplib AND NOT TARGET httplib)
    # Automatic fallback via FetchContent when system package is unavailable (e.g. MSYS2/MinGW)
    include(FetchContent)
    message(STATUS "[SecureCloud] cpp-httplib not found in system paths; fetching via FetchContent (v0.18.6)...")
    FetchContent_Declare(
        httplib
        GIT_REPOSITORY https://github.com/yhirose/cpp-httplib.git
        GIT_TAG v0.18.6
        GIT_SHALLOW TRUE
    )
    set(HTTPLIB_COMPILE OFF CACHE INTERNAL "")
    set(HTTPLIB_REQUIRE_OPENSSL OFF CACHE INTERNAL "")
    set(HTTPLIB_REQUIRE_ZLIB OFF CACHE INTERNAL "")
    set(HTTPLIB_REQUIRE_BROTLI OFF CACHE INTERNAL "")
    FetchContent_MakeAvailable(httplib)
endif()

if(TARGET httplib::httplib)
    set(_SECURECLOUD_HTTPLIB_UPSTREAM httplib::httplib)
elseif(TARGET httplib)
    set(_SECURECLOUD_HTTPLIB_UPSTREAM httplib)
else()
    set(_SECURECLOUD_HTTPLIB_UPSTREAM "")
endif()

if(_SECURECLOUD_HTTPLIB_UPSTREAM)
    if(NOT TARGET securecloud_httplib)
        add_library(securecloud_httplib INTERFACE)
        target_link_libraries(securecloud_httplib INTERFACE ${_SECURECLOUD_HTTPLIB_UPSTREAM})
        target_compile_definitions(securecloud_httplib INTERFACE CPPHTTPLIB_OPENSSL_SUPPORT)
        if(TARGET OpenSSL::SSL AND TARGET OpenSSL::Crypto)
            target_link_libraries(securecloud_httplib INTERFACE OpenSSL::SSL OpenSSL::Crypto)
        endif()
        if(WIN32)
            target_link_libraries(securecloud_httplib INTERFACE ws2_32 crypt32)
        endif()
        add_library(securecloud::httplib ALIAS securecloud_httplib)
    endif()
    message(STATUS "[SecureCloud] Discovered cpp-httplib target: securecloud::httplib")
else()
    message(FATAL_ERROR
        "[SecureCloud] cpp-httplib package was not found.\n"
        "  Active CMAKE_PREFIX_PATH: ${CMAKE_PREFIX_PATH}\n"
        "  Remediation:\n"
        "    - On macOS: Run 'brew install cpp-httplib'\n"
        "    - On MSVC / vcpkg: Ensure vcpkg.json contains \"cpp-httplib\""
    )
endif()

message(STATUS "[SecureCloud] Dependency discovery pipeline established successfully")
