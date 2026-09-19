add_library(securecloud_messaging_config STATIC
    messaging_config.cpp
)

add_library(securecloud::messaging_config ALIAS securecloud_messaging_config)

target_include_directories(securecloud_messaging_config PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(securecloud_messaging_config PUBLIC
    securecloud::common
    securecloud::compiler_flags
)

add_executable(securecloud-messaging
    main.cpp
)

target_link_libraries(securecloud-messaging PRIVATE
    securecloud::messaging_config
    securecloud::common
    securecloud::compiler_flags
)
