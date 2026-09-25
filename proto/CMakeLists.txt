# Register Protobuf and gRPC contracts for SecureCloud
securecloud_add_proto_library(securecloud_proto
    PROTO_FILES
        securecloud/common/v1/health.proto
        securecloud/files/v1/files.proto
)

if(WIN32 AND MSVC)
    file(TO_NATIVE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/proto_win32_compat.hpp" _WIN32_COMPAT_HDR)
    target_compile_options(securecloud_proto PUBLIC
        "/FI${_WIN32_COMPAT_HDR}"
    )
endif()

