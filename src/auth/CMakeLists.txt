add_library(securecloud_auth_config STATIC
        auth_config.cpp
        db/postgres_connection_pool.cpp
)

add_library(securecloud::auth_config ALIAS securecloud_auth_config)
add_library(securecloud::auth ALIAS securecloud_auth_config)

target_include_directories(securecloud_auth_config PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/..
)

target_link_libraries(securecloud_auth_config PUBLIC
        securecloud::common
        securecloud::libpqxx
        securecloud::compiler_flags
)

add_executable(securecloud-auth
        main.cpp
)

target_link_libraries(securecloud-auth PRIVATE
        securecloud::auth_config
        securecloud::common
        securecloud::compiler_flags
)
