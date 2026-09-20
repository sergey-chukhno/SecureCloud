add_library(securecloud_common STATIC
    src/version.cpp
    src/security/mtls_config.cpp
    src/configuration/configuration_source.cpp
    src/configuration/secret_string.cpp
    src/configuration/validation_error.cpp
    src/configuration/config_parser.cpp
    src/configuration/common_service_config.cpp
    src/health/health_status_manager.cpp
    src/health/health_service_impl.cpp
    src/health/transport_probe.cpp
)

add_library(securecloud::common ALIAS securecloud_common)

target_include_directories(securecloud_common PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

target_link_libraries(securecloud_common PUBLIC
    securecloud::compiler_flags
    securecloud_proto
    gRPC::grpc++
)
