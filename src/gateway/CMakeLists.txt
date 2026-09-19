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

add_executable(securecloud-gateway
    main.cpp
)

target_link_libraries(securecloud-gateway PRIVATE
    securecloud::gateway_config
    securecloud::common
    securecloud::compiler_flags
)
