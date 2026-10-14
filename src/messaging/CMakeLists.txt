add_library(securecloud_messaging_config STATIC
    messaging_config.cpp
    concurrency/bounded_worker_pool.cpp
    service/messaging_service_impl.cpp
    service/messaging_caller_context.cpp
)


add_library(securecloud::messaging_config ALIAS securecloud_messaging_config)
add_library(securecloud::messaging ALIAS securecloud_messaging_config)

target_include_directories(securecloud_messaging_config PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/..
)

target_link_libraries(securecloud_messaging_config PUBLIC
    securecloud::common
    securecloud_proto
    securecloud::compiler_flags
)

add_dependencies(securecloud_messaging_config securecloud_proto)

add_executable(securecloud-messaging
    main.cpp
)

target_link_libraries(securecloud-messaging PRIVATE
    securecloud::messaging_config
    securecloud::common
    securecloud::compiler_flags
)
