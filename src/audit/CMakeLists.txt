add_library(securecloud_audit_domain STATIC
        domain/enums.cpp
        domain/event_id.cpp
        domain/validation_result.cpp
        domain/audit_event_validator.cpp
)

add_library(securecloud::audit_domain ALIAS securecloud_audit_domain)

target_include_directories(securecloud_audit_domain PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(securecloud_audit_domain PUBLIC
        securecloud::common
        securecloud::compiler_flags
        OpenSSL::Crypto
)

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
        securecloud_audit_domain
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