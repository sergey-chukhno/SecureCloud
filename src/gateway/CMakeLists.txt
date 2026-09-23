add_library(securecloud_gateway_config STATIC
    gateway_config.cpp
)

add_library(securecloud::gateway_config ALIAS securecloud_gateway_config)

target_include_directories(securecloud_gateway_config PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(securecloud_gateway_config PUBLIC
    securecloud::common
    securecloud::compiler_flags
)

add_library(securecloud_gateway_http STATIC
    http/http_server.cpp
)

add_library(securecloud::gateway_http ALIAS securecloud_gateway_http)

target_include_directories(securecloud_gateway_http PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/http
)

target_link_libraries(securecloud_gateway_http PUBLIC
    securecloud::gateway_config
    securecloud::httplib
    securecloud::common
    securecloud::compiler_flags
)

add_executable(securecloud-gateway
    main.cpp
)

target_link_libraries(securecloud-gateway PRIVATE
    securecloud::gateway_config
    securecloud::gateway_http
    securecloud::common
    securecloud::compiler_flags
)
