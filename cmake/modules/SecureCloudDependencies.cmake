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

# 1. Discover gRPC dependency (finds gRPC and its Protobuf dependency via CONFIG mode)
message(STATUS "[SecureCloud] Discovering gRPC framework...")
find_package(gRPC REQUIRED)
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
    find_program(GRPC_CPP_PLUGIN_BIN NAMES grpc_cpp_plugin)
    if(GRPC_CPP_PLUGIN_BIN)
        message(STATUS "[SecureCloud] Discovered grpc_cpp_plugin executable: ${GRPC_CPP_PLUGIN_BIN}")
    else()
        message(FATAL_ERROR "[SecureCloud] grpc_cpp_plugin compiler executable was not found")
    endif()
endif()

# 2. Discover Protobuf dependency
message(STATUS "[SecureCloud] Discovering Protobuf framework...")
find_package(Protobuf REQUIRED CONFIG)
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
    find_program(PROTOC_BIN NAMES protoc)
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
