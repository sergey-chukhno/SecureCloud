add_library(securecloud_auth_config STATIC
        auth_config.cpp
        db/postgres_connection_pool.cpp
        db/migration_runner.cpp
        domain/mappers.cpp
        domain/token_claims.cpp
        repository/user_repository.cpp
        repository/device_repository.cpp
        repository/session_repository.cpp
        repository/refresh_token_repository.cpp
        repository/device_public_key_repository.cpp
        repository/mfa_repository.cpp
        crypto/argon2id_hasher.cpp
        crypto/token_crypto.cpp
        crypto/base32.cpp
        crypto/totp_engine.cpp
        crypto/mfa_secret_protector.cpp
        crypto/recovery_code_generator.cpp
        crypto/device_key_validator.cpp
        service/credential_verifier.cpp
        service/session_manager.cpp
        service/token_manager.cpp
        service/totp_authenticator.cpp
        service/mfa_manager.cpp
        service/audit_event_publisher.cpp
        service/auth_service_impl.cpp
)

add_library(securecloud::auth_config ALIAS securecloud_auth_config)
add_library(securecloud::auth ALIAS securecloud_auth_config)

target_include_directories(securecloud_auth_config PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/..
)

target_link_libraries(securecloud_auth_config PUBLIC
        securecloud::common
        securecloud::json
        securecloud::libpqxx
        OpenSSL::Crypto
        securecloud_proto
        securecloud::compiler_flags
)

add_dependencies(securecloud_auth_config securecloud_proto)

add_executable(securecloud-auth
        main.cpp
)

target_link_libraries(securecloud-auth PRIVATE
        securecloud::auth_config
        securecloud::common
        securecloud::compiler_flags
)
