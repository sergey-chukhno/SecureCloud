add_library(securecloud_audit_config STATIC
        audit_config.cpp
)

add_library(securecloud::audit_config ALIAS securecloud_audit_config)

target_include_directories(securecloud_audit_config PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(securecloud_audit_config PUBLIC
        securecloud::common
        securecloud::compiler_flags
)

add_library(securecloud_audit_server STATIC
        audit_server.cpp
)

add_library(securecloud::audit_server ALIAS securecloud_audit_server)

target_include_directories(securecloud_audit_server PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(securecloud_audit_server PUBLIC
        securecloud_audit_config
        securecloud::common
        securecloud::compiler_flags
)

add_executable(securecloud-audit
        main.cpp
)

target_link_libraries(securecloud-audit PRIVATE
        securecloud::audit_server
        securecloud::compiler_flags
)