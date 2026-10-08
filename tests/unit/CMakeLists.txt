add_executable(securecloud_unit_smoke_test
        smoke_test.cpp
)

target_link_libraries(securecloud_unit_smoke_test PRIVATE
        securecloud::common
        securecloud::compiler_flags
)

add_test(
        NAME unit_smoke_test
        COMMAND securecloud_unit_smoke_test
)

# Dependency Discovery Pipeline Smoke Test (SC002-T03)
add_executable(securecloud_dependency_smoke_test
        dependency_smoke_test.cpp
)

target_link_libraries(securecloud_dependency_smoke_test PRIVATE
        securecloud::common
        securecloud::compiler_flags
)

add_test(
        NAME dependency_smoke_test
        COMMAND securecloud_dependency_smoke_test
)

# GoogleTest Framework Integration Target (SC-003)
add_executable(securecloud_gtest_smoke_test
        gtest_smoke_test.cpp
)

target_link_libraries(securecloud_gtest_smoke_test PRIVATE
        GTest::gtest_main
        securecloud::compiler_flags
)

# Automatic CTest discovery for GoogleTest test cases
gtest_discover_tests(securecloud_gtest_smoke_test ${SECURECLOUD_TEST_PROPERTIES})

# Protobuf & gRPC Code Generation Pipeline Smoke Test
add_executable(securecloud_proto_smoke_test
        proto_smoke_test.cpp
)

target_link_libraries(securecloud_proto_smoke_test PRIVATE
        securecloud::common
        securecloud_proto
        securecloud::compiler_flags
        GTest::gtest_main
)

gtest_discover_tests(securecloud_proto_smoke_test ${SECURECLOUD_TEST_PROPERTIES})

# Auth Service Protobuf & gRPC Contract Smoke Test (GW-003-T01)
add_executable(securecloud_auth_proto_smoke_test
    gateway/auth_proto_smoke_test.cpp
)

target_link_libraries(securecloud_auth_proto_smoke_test PRIVATE
    securecloud::common
    securecloud_proto
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_auth_proto_smoke_test ${SECURECLOUD_TEST_PROPERTIES})

# Custom target to explicitly execute generated contract verification
if(WIN32)
    # Ensure Windows runtime finds dependent DLLs from the active compiler toolchain
    set(_CONTRACTS_ENV_FLAGS "")
    if(CMAKE_CXX_COMPILER)
        get_filename_component(_COMPILER_BIN_DIR "${CMAKE_CXX_COMPILER}" DIRECTORY)
        if(EXISTS "${_COMPILER_BIN_DIR}")
            list(APPEND _CONTRACTS_ENV_FLAGS "--modify" "PATH=path_list_prepend:${_COMPILER_BIN_DIR}")
        endif()
    endif()

    add_custom_target(verify-contracts
        COMMAND ${CMAKE_COMMAND} -E env ${_CONTRACTS_ENV_FLAGS} $<TARGET_FILE:securecloud_proto_smoke_test>
        COMMAND ${CMAKE_COMMAND} -E env ${_CONTRACTS_ENV_FLAGS} $<TARGET_FILE:securecloud_auth_proto_smoke_test>
        DEPENDS securecloud_proto_smoke_test securecloud_auth_proto_smoke_test
        COMMENT "Executing Protobuf & gRPC generated-contracts validation smoke tests..."
        VERBATIM
    )
else()
    add_custom_target(verify-contracts
        COMMAND $<TARGET_FILE:securecloud_proto_smoke_test>
        COMMAND $<TARGET_FILE:securecloud_auth_proto_smoke_test>
        DEPENDS securecloud_proto_smoke_test securecloud_auth_proto_smoke_test
        COMMENT "Executing Protobuf & gRPC generated-contracts validation smoke tests..."
        VERBATIM
    )
endif()


# gRPC mTLS Configuration & Security Unit Test Suite
add_executable(securecloud_mtls_config_test
        security/mtls_config_test.cpp
)

target_link_libraries(securecloud_mtls_config_test PRIVATE
        securecloud::common
        securecloud::compiler_flags
        GTest::gtest_main
)

gtest_discover_tests(securecloud_mtls_config_test ${SECURECLOUD_TEST_PROPERTIES})

# Configuration Primitives & Parser Unit Test Suite (SC12-T01)
add_executable(securecloud_config_parser_test
        configuration/config_parser_test.cpp
)

target_link_libraries(securecloud_config_parser_test PRIVATE
        securecloud::common
        securecloud::compiler_flags
        GTest::gtest_main
)

gtest_discover_tests(securecloud_config_parser_test ${SECURECLOUD_TEST_PROPERTIES})

# Common Service Configuration Model Unit Test Suite (SC12-T02)
add_executable(securecloud_common_service_config_test
        configuration/common_service_config_test.cpp
)

target_link_libraries(securecloud_common_service_config_test PRIVATE
        securecloud::common
        securecloud::compiler_flags
        GTest::gtest_main
)

gtest_discover_tests(securecloud_common_service_config_test ${SECURECLOUD_TEST_PROPERTIES})

# Service Configuration Boundaries Unit Test Suite (SC12-T03)
add_executable(securecloud_service_config_boundaries_test
        configuration/service_config_boundaries_test.cpp
)

target_link_libraries(securecloud_service_config_boundaries_test PRIVATE
        securecloud::gateway_config
        securecloud::auth_config
        securecloud::messaging_config
        securecloud::files_config
        securecloud::audit_config
        securecloud::common
        securecloud::compiler_flags
        GTest::gtest_main
)

gtest_discover_tests(securecloud_service_config_boundaries_test ${SECURECLOUD_TEST_PROPERTIES})

# Health Status Manager & Service Unit Test Suite (SC13-T03)
add_executable(securecloud_health_status_manager_test
        health/health_status_manager_test.cpp
)

target_link_libraries(securecloud_health_status_manager_test PRIVATE
        securecloud::common
        securecloud_proto
        securecloud::compiler_flags
        GTest::gtest_main
)

gtest_discover_tests(securecloud_health_status_manager_test ${SECURECLOUD_TEST_PROPERTIES})

# Transport Probe Unit Test Suite (SC13-T03)
add_executable(securecloud_transport_probe_test
        health/transport_probe_test.cpp
)

target_link_libraries(securecloud_transport_probe_test PRIVATE
        securecloud::common
        securecloud::compiler_flags
        GTest::gtest_main
)

gtest_discover_tests(securecloud_transport_probe_test ${SECURECLOUD_TEST_PROPERTIES})

# PostgreSQL C++ Driver (libpqxx) Integration Smoke Test (AUTH-001-T02)
add_executable(securecloud_pqxx_smoke_test
        pqxx_smoke_test.cpp
)

target_link_libraries(securecloud_pqxx_smoke_test PRIVATE
        securecloud::libpqxx
        securecloud::compiler_flags
        GTest::gtest_main
)

gtest_discover_tests(securecloud_pqxx_smoke_test ${SECURECLOUD_TEST_PROPERTIES})

# Auth PostgreSQL Connection Pool Unit Test Suite (AUTH-001-T03)
add_executable(securecloud_connection_pool_test
        auth/connection_pool_test.cpp
)

target_link_libraries(securecloud_connection_pool_test PRIVATE
        securecloud::auth
        securecloud::common
        securecloud::compiler_flags
        GTest::gtest_main
)

gtest_discover_tests(securecloud_connection_pool_test ${SECURECLOUD_TEST_PROPERTIES})

# Auth Service Implementation Unit Test Suite (AUTH-001-T06)
add_executable(securecloud_auth_service_test
        auth/auth_service_test.cpp
)

target_link_libraries(securecloud_auth_service_test PRIVATE
        securecloud::auth
        securecloud_proto
        securecloud::common
        securecloud::compiler_flags
        GTest::gtest_main
)

gtest_discover_tests(securecloud_auth_service_test ${SECURECLOUD_TEST_PROPERTIES})

# Auth Database Migration Runner Unit Test Suite (AUTH-002-T01)
add_executable(securecloud_auth_migration_runner_test
        auth/migration_runner_test.cpp
)

target_link_libraries(securecloud_auth_migration_runner_test PRIVATE
        securecloud::auth
        securecloud::common
        securecloud::compiler_flags
        GTest::gtest_main
)

gtest_discover_tests(securecloud_auth_migration_runner_test ${SECURECLOUD_TEST_PROPERTIES})

# Auth Persistence Domain Entities & Value Types Test Suite (AUTH-002-T02)
add_executable(securecloud_auth_domain_entities_test
        auth/domain_entities_test.cpp
)

target_link_libraries(securecloud_auth_domain_entities_test PRIVATE
        securecloud::auth
        securecloud::common
        securecloud::compiler_flags
        GTest::gtest_main
)

gtest_discover_tests(securecloud_auth_domain_entities_test ${SECURECLOUD_TEST_PROPERTIES})

# Auth User & Device Repositories Test Suite (AUTH-002-T03)
add_executable(securecloud_auth_user_device_repository_test
        auth/user_device_repository_test.cpp
)

target_link_libraries(securecloud_auth_user_device_repository_test PRIVATE
        securecloud::auth
        securecloud::common
        securecloud::compiler_flags
        GTest::gtest_main
)

gtest_discover_tests(securecloud_auth_user_device_repository_test ${SECURECLOUD_TEST_PROPERTIES})

# Auth Session & Refresh Token Repositories Test Suite (AUTH-002-T04)
add_executable(securecloud_auth_session_token_repository_test
        auth/session_token_repository_test.cpp
)

target_link_libraries(securecloud_auth_session_token_repository_test PRIVATE
        securecloud::auth
        securecloud::common
        securecloud::compiler_flags
        GTest::gtest_main
)

gtest_discover_tests(securecloud_auth_session_token_repository_test ${SECURECLOUD_TEST_PROPERTIES})

# Auth Device Public Key & MFA Repositories Test Suite (AUTH-002-T05)
add_executable(securecloud_auth_crypto_key_mfa_repository_test
        auth/crypto_key_mfa_repository_test.cpp
)

target_link_libraries(securecloud_auth_crypto_key_mfa_repository_test PRIVATE
        securecloud::auth
        securecloud::common
        securecloud::compiler_flags
        GTest::gtest_main
)

gtest_discover_tests(securecloud_auth_crypto_key_mfa_repository_test ${SECURECLOUD_TEST_PROPERTIES})

# Auth Argon2id Hasher Engine Test Suite (AUTH-003-T01)
add_executable(securecloud_auth_argon2id_hasher_test
        auth/argon2id_hasher_test.cpp
)

target_link_libraries(securecloud_auth_argon2id_hasher_test PRIVATE
        securecloud::auth
        securecloud::common
        OpenSSL::Crypto
        securecloud::compiler_flags
        GTest::gtest_main
)

gtest_discover_tests(securecloud_auth_argon2id_hasher_test ${SECURECLOUD_TEST_PROPERTIES})

# Auth Credentials Domain Types Test Suite (AUTH-003-T02)
add_executable(securecloud_auth_credentials_test
        auth/credentials_test.cpp
)

target_link_libraries(securecloud_auth_credentials_test PRIVATE
        securecloud::auth
        securecloud::common
        OpenSSL::Crypto
        securecloud::compiler_flags
        GTest::gtest_main
)

gtest_discover_tests(securecloud_auth_credentials_test ${SECURECLOUD_TEST_PROPERTIES})

# Auth Credential Verifier Domain Service Test Suite (AUTH-003-T03)
add_executable(securecloud_auth_credential_verifier_test
        auth/credential_verifier_test.cpp
)

target_link_libraries(securecloud_auth_credential_verifier_test PRIVATE
        securecloud::auth
        securecloud::common
        OpenSSL::Crypto
        securecloud::compiler_flags
        GTest::gtest_main
        GTest::gmock
)

gtest_discover_tests(securecloud_auth_credential_verifier_test ${SECURECLOUD_TEST_PROPERTIES})

# Auth Session Manager Service Test Suite (AUTH-003-T04)
add_executable(securecloud_auth_session_manager_test
        auth/session_manager_test.cpp
)

target_link_libraries(securecloud_auth_session_manager_test PRIVATE
        securecloud::auth
        securecloud::common
        OpenSSL::Crypto
        securecloud::compiler_flags
        GTest::gtest_main
        GTest::gmock
)

gtest_discover_tests(securecloud_auth_session_manager_test ${SECURECLOUD_TEST_PROPERTIES})

# Auth Audit Event Publisher Service Test Suite (AUTH-003-T05)
add_executable(securecloud_auth_audit_event_publisher_test
        auth/audit_event_publisher_test.cpp
)

target_link_libraries(securecloud_auth_audit_event_publisher_test PRIVATE
        securecloud::auth
        securecloud::common
        securecloud::json
        OpenSSL::Crypto
        securecloud::compiler_flags
        GTest::gtest_main
        GTest::gmock
)

gtest_discover_tests(securecloud_auth_audit_event_publisher_test ${SECURECLOUD_TEST_PROPERTIES})

# Auth Service Authenticate RPC Test Suite (AUTH-003-T06)
add_executable(securecloud_auth_service_authenticate_test
        auth/auth_service_authenticate_test.cpp
)

target_link_libraries(securecloud_auth_service_authenticate_test PRIVATE
        securecloud::auth
        securecloud::common
        securecloud_proto
        OpenSSL::Crypto
        securecloud::compiler_flags
        GTest::gtest_main
        GTest::gmock
)

gtest_discover_tests(securecloud_auth_service_authenticate_test ${SECURECLOUD_TEST_PROPERTIES})

# Auth Session Lifecycle Domain Model Test Suite (AUTH-004-T01)
add_executable(securecloud_auth_session_lifecycle_test
        auth/session_lifecycle_test.cpp
)

target_link_libraries(securecloud_auth_session_lifecycle_test PRIVATE
        securecloud::auth
        securecloud::common
        securecloud::compiler_flags
        GTest::gtest_main
)

gtest_discover_tests(securecloud_auth_session_lifecycle_test ${SECURECLOUD_TEST_PROPERTIES})

# Auth Enhanced Session Repository Test Suite (AUTH-004-T02)
add_executable(securecloud_auth_session_repository_test
        auth/session_repository_test.cpp
)

target_link_libraries(securecloud_auth_session_repository_test PRIVATE
        securecloud::auth
        securecloud::common
        securecloud::compiler_flags
        GTest::gtest_main
)

gtest_discover_tests(securecloud_auth_session_repository_test ${SECURECLOUD_TEST_PROPERTIES})

# Auth Session Validation & Device Association Engine Test Suite (AUTH-004-T03)
add_executable(securecloud_auth_session_validation_test
        auth/session_validation_test.cpp
)

target_link_libraries(securecloud_auth_session_validation_test PRIVATE
        securecloud::auth
        securecloud::common
        securecloud::compiler_flags
        GTest::gtest_main
        GTest::gmock
)

gtest_discover_tests(securecloud_auth_session_validation_test ${SECURECLOUD_TEST_PROPERTIES})

# Auth Session Revocation Engine & Concurrency Control Test Suite (AUTH-004-T04)
add_executable(securecloud_auth_session_revocation_test
        auth/session_revocation_test.cpp
)

target_link_libraries(securecloud_auth_session_revocation_test PRIVATE
        securecloud::auth
        securecloud::common
        securecloud::compiler_flags
        GTest::gtest_main
        GTest::gmock
)

gtest_discover_tests(securecloud_auth_session_revocation_test ${SECURECLOUD_TEST_PROPERTIES})

# Auth Security Audit Telemetry for Session Lifecycle Test Suite (AUTH-004-T05)
add_executable(securecloud_auth_session_audit_test
        auth/session_audit_test.cpp
)

target_link_libraries(securecloud_auth_session_audit_test PRIVATE
        securecloud::auth
        securecloud::common
        securecloud::json
        securecloud::compiler_flags
        GTest::gtest_main
        GTest::gmock
)

gtest_discover_tests(securecloud_auth_session_audit_test ${SECURECLOUD_TEST_PROPERTIES})

# Auth Service gRPC ValidateSession & RevokeSession Test Suite (AUTH-004-T06)
add_executable(securecloud_auth_service_session_test
        auth/auth_service_session_test.cpp
)

target_link_libraries(securecloud_auth_service_session_test PRIVATE
        securecloud::auth
        securecloud::common
        securecloud_proto
        securecloud::compiler_flags
        GTest::gtest_main
        GTest::gmock
)

gtest_discover_tests(securecloud_auth_service_session_test ${SECURECLOUD_TEST_PROPERTIES})

# Auth Cryptographic Token Signer & Secret Generator Test Suite (AUTH-005-T01)
add_executable(securecloud_auth_token_crypto_test
        auth/token_crypto_test.cpp
)

target_link_libraries(securecloud_auth_token_crypto_test PRIVATE
        securecloud::auth
        securecloud::common
        OpenSSL::Crypto
        securecloud::compiler_flags
        GTest::gtest_main
)

gtest_discover_tests(securecloud_auth_token_crypto_test ${SECURECLOUD_TEST_PROPERTIES})

# Auth Access Token Domain Model & Claims Engine Test Suite (AUTH-005-T02)
add_executable(securecloud_auth_token_claims_test
        auth/token_claims_test.cpp
)

target_link_libraries(securecloud_auth_token_claims_test PRIVATE
        securecloud::auth
        securecloud::common
        securecloud::json
        OpenSSL::Crypto
        securecloud::compiler_flags
        GTest::gtest_main
)

gtest_discover_tests(securecloud_auth_token_claims_test ${SECURECLOUD_TEST_PROPERTIES})

# Auth Stateful Refresh Token Rotation & Token Management Engine Test Suite (AUTH-005-T03)
add_executable(securecloud_auth_token_manager_test
        auth/token_manager_test.cpp
)

target_link_libraries(securecloud_auth_token_manager_test PRIVATE
        securecloud::auth
        securecloud::common
        securecloud::json
        OpenSSL::Crypto
        securecloud::compiler_flags
        GTest::gtest_main
        GTest::gmock
)

gtest_discover_tests(securecloud_auth_token_manager_test ${SECURECLOUD_TEST_PROPERTIES})

# Auth Token Compromise & Reuse Detection Engine Test Suite (AUTH-005-T04)
add_executable(securecloud_auth_token_reuse_test
        auth/token_reuse_test.cpp
)

target_link_libraries(securecloud_auth_token_reuse_test PRIVATE
        securecloud::auth
        securecloud::common
        securecloud::json
        OpenSSL::Crypto
        securecloud::compiler_flags
        GTest::gtest_main
        GTest::gmock
)

gtest_discover_tests(securecloud_auth_token_reuse_test ${SECURECLOUD_TEST_PROPERTIES})

# Auth Service Token & RefreshSession Handler Test Suite (AUTH-005-T06)
add_executable(securecloud_auth_service_token_test
        auth/auth_service_token_test.cpp
)

target_link_libraries(securecloud_auth_service_token_test PRIVATE
        securecloud::auth
        securecloud::common
        securecloud::json
        securecloud_proto
        OpenSSL::Crypto
        securecloud::compiler_flags
        GTest::gtest_main
        GTest::gmock
)

gtest_discover_tests(securecloud_auth_service_token_test ${SECURECLOUD_TEST_PROPERTIES})

# Auth RFC 6238 TOTP Engine, Base32 Codec & MFA Secret Protector Test Suite (AUTH-006-T01)
add_executable(securecloud_auth_totp_engine_test
        auth/totp_engine_test.cpp
)

target_link_libraries(securecloud_auth_totp_engine_test PRIVATE
        securecloud::auth
        securecloud::common
        OpenSSL::Crypto
        securecloud::compiler_flags
        GTest::gtest_main
)

gtest_discover_tests(securecloud_auth_totp_engine_test ${SECURECLOUD_TEST_PROPERTIES})

# Auth MFA Authenticator Abstraction & Recovery Code Test Suite (AUTH-006-T02)
add_executable(securecloud_auth_mfa_authenticator_test
        auth/mfa_authenticator_test.cpp
)

target_link_libraries(securecloud_auth_mfa_authenticator_test PRIVATE
        securecloud::auth
        securecloud::common
        OpenSSL::Crypto
        securecloud::compiler_flags
        GTest::gtest_main
)

gtest_discover_tests(securecloud_auth_mfa_authenticator_test ${SECURECLOUD_TEST_PROPERTIES})

# Auth MFA Stateful Lifecycle & Challenge Management Engine Test Suite (AUTH-006-T03)
add_executable(securecloud_auth_mfa_manager_test
        auth/mfa_manager_test.cpp
)

target_link_libraries(securecloud_auth_mfa_manager_test PRIVATE
        securecloud::auth
        securecloud::common
        OpenSSL::Crypto
        securecloud::compiler_flags
        GTest::gtest_main
        GTest::gmock
)

gtest_discover_tests(securecloud_auth_mfa_manager_test ${SECURECLOUD_TEST_PROPERTIES})

# Auth Service MFA Step-Up & VerifyMfaChallenge RPC Test Suite (AUTH-006-T04)
add_executable(securecloud_auth_service_mfa_test
        auth/auth_service_mfa_test.cpp
)

target_link_libraries(securecloud_auth_service_mfa_test PRIVATE
        securecloud::auth
        securecloud::common
        securecloud_proto
        OpenSSL::Crypto
        securecloud::compiler_flags
        GTest::gtest_main
        GTest::gmock
)

gtest_discover_tests(securecloud_auth_service_mfa_test ${SECURECLOUD_TEST_PROPERTIES})

# Auth Device Domain Models & Cryptographic Key Validator Test Suite (AUTH-007-T01)
add_executable(securecloud_auth_device_domain_test
        auth/device_domain_test.cpp
)

target_link_libraries(securecloud_auth_device_domain_test PRIVATE
        securecloud::auth
        securecloud::common
        OpenSSL::Crypto
        securecloud::compiler_flags
        GTest::gtest_main
)

gtest_discover_tests(securecloud_auth_device_domain_test ${SECURECLOUD_TEST_PROPERTIES})

# Auth Device Manager Test Suite (AUTH-007-T02)
add_executable(securecloud_auth_device_manager_test
        auth/device_manager_test.cpp
)

target_link_libraries(securecloud_auth_device_manager_test PRIVATE
        securecloud::auth
        securecloud::common
        OpenSSL::Crypto
        securecloud::compiler_flags
        GTest::gtest_main
        GTest::gmock
)

gtest_discover_tests(securecloud_auth_device_manager_test ${SECURECLOUD_TEST_PROPERTIES})

# Auth Device Revocation Test Suite (AUTH-007-T03)
add_executable(securecloud_auth_device_revocation_test
        auth/device_revocation_test.cpp
)

target_link_libraries(securecloud_auth_device_revocation_test PRIVATE
        securecloud::auth
        securecloud::common
        OpenSSL::Crypto
        securecloud::compiler_flags
        GTest::gtest_main
        GTest::gmock
)

gtest_discover_tests(securecloud_auth_device_revocation_test ${SECURECLOUD_TEST_PROPERTIES})

# Auth Service Device Lifecycle & gRPC RPCs Test Suite (AUTH-007-T04)
add_executable(securecloud_auth_service_device_test
        auth/auth_service_device_test.cpp
)

target_link_libraries(securecloud_auth_service_device_test PRIVATE
        securecloud::auth
        securecloud::common
        securecloud_proto
        OpenSSL::Crypto
        securecloud::compiler_flags
        GTest::gtest_main
        GTest::gmock
)

gtest_discover_tests(securecloud_auth_service_device_test ${SECURECLOUD_TEST_PROPERTIES})

# Auth Key Fingerprint Test Suite (AUTH-008-T01)
add_executable(securecloud_auth_key_fingerprint_test
        auth/key_fingerprint_test.cpp
)

target_link_libraries(securecloud_auth_key_fingerprint_test PRIVATE
        securecloud::auth
        securecloud::common
        OpenSSL::Crypto
        securecloud::compiler_flags
        GTest::gtest_main
)

gtest_discover_tests(securecloud_auth_key_fingerprint_test ${SECURECLOUD_TEST_PROPERTIES})

# Auth Prekey Signature Verifier Test Suite (AUTH-008-T01)
add_executable(securecloud_auth_prekey_signature_verifier_test
        auth/prekey_signature_verifier_test.cpp
)

target_link_libraries(securecloud_auth_prekey_signature_verifier_test PRIVATE
        securecloud::auth
        securecloud::common
        OpenSSL::Crypto
        securecloud::compiler_flags
        GTest::gtest_main
)

gtest_discover_tests(securecloud_auth_prekey_signature_verifier_test ${SECURECLOUD_TEST_PROPERTIES})

# Auth Device Public Key Repository Extensions Test Suite (AUTH-008-T01)
add_executable(securecloud_auth_public_key_repository_test
        auth/device_public_key_repository_test.cpp
)

target_link_libraries(securecloud_auth_public_key_repository_test PRIVATE
        securecloud::auth
        securecloud::common
        OpenSSL::Crypto
        securecloud::compiler_flags
        GTest::gtest_main
)

gtest_discover_tests(securecloud_auth_public_key_repository_test ${SECURECLOUD_TEST_PROPERTIES})

# Auth Crypto Directory Manager Test Suite (AUTH-008-T02)
add_executable(securecloud_auth_crypto_directory_manager_test
        auth/crypto_directory_manager_test.cpp
)

target_link_libraries(securecloud_auth_crypto_directory_manager_test PRIVATE
        securecloud::auth
        securecloud::common
        OpenSSL::Crypto
        securecloud::compiler_flags
        GTest::gtest_main
        GTest::gmock
)

gtest_discover_tests(securecloud_auth_crypto_directory_manager_test ${SECURECLOUD_TEST_PROPERTIES})

# Gateway HTTP & JSON Dependencies Smoke Test (GW-001-T01)
add_executable(securecloud_http_smoke_test
    gateway/http_smoke_test.cpp
)

target_link_libraries(securecloud_http_smoke_test PRIVATE
    securecloud::json
    securecloud::httplib
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_http_smoke_test ${SECURECLOUD_TEST_PROPERTIES})

# Gateway Configuration Model & Strict No-DB Invariant Test (GW-001-T02)
add_executable(securecloud_gateway_config_test
    gateway/gateway_config_test.cpp
)

target_link_libraries(securecloud_gateway_config_test PRIVATE
    securecloud::gateway_config
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_gateway_config_test ${SECURECLOUD_TEST_PROPERTIES})

# Gateway Modular HTTP Server Lifecycle Test (GW-001-T03)
add_executable(securecloud_http_server_lifecycle_test
    gateway/http_server_lifecycle_test.cpp
)

target_link_libraries(securecloud_http_server_lifecycle_test PRIVATE
    securecloud::gateway_http
    securecloud::httplib
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_http_server_lifecycle_test ${SECURECLOUD_TEST_PROPERTIES})

# Gateway Router, Middleware Pipeline & Error Mapper Test (GW-001-T04)
add_executable(securecloud_router_middleware_test
    gateway/router_middleware_test.cpp
)

target_link_libraries(securecloud_router_middleware_test PRIVATE
    securecloud::gateway_http
    securecloud::httplib
    securecloud::json
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_router_middleware_test ${SECURECLOUD_TEST_PROPERTIES})

# Gateway Bearer Token Extractor Test (GW-004-T01)
add_executable(securecloud_bearer_token_extractor_test
    gateway/bearer_token_extractor_test.cpp
)

target_link_libraries(securecloud_bearer_token_extractor_test PRIVATE
    securecloud::gateway_http
    securecloud::httplib
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_bearer_token_extractor_test ${SECURECLOUD_TEST_PROPERTIES})

# Gateway Authenticated Context Domain Model Test (GW-004-T02)
add_executable(securecloud_authenticated_context_test
    gateway/authenticated_context_test.cpp
)

target_link_libraries(securecloud_authenticated_context_test PRIVATE
    securecloud::gateway_http
    securecloud_proto
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_authenticated_context_test ${SECURECLOUD_TEST_PROPERTIES})

# Gateway Token Validator Test (GW-004-T03)
add_executable(securecloud_token_validator_test
    gateway/token_validator_test.cpp
)

target_link_libraries(securecloud_token_validator_test PRIVATE
    securecloud::gateway_http
    securecloud::gateway_grpc
    securecloud_proto
    securecloud::compiler_flags
    GTest::gmock
    GTest::gtest_main
)

gtest_discover_tests(securecloud_token_validator_test ${SECURECLOUD_TEST_PROPERTIES})

# Gateway Local Token Verifier Test (AUTH-005-T05)
add_executable(securecloud_gateway_local_token_verifier_test
    gateway/local_token_verifier_test.cpp
)

target_link_libraries(securecloud_gateway_local_token_verifier_test PRIVATE
    securecloud::gateway_http
    securecloud::auth
    securecloud_proto
    securecloud::compiler_flags
    GTest::gmock
    GTest::gtest_main
)

gtest_discover_tests(securecloud_gateway_local_token_verifier_test ${SECURECLOUD_TEST_PROPERTIES})

# Gateway Security Policy Test (GW-004-T04)
add_executable(securecloud_gateway_security_policy_test
    gateway/gateway_security_policy_test.cpp
)

target_link_libraries(securecloud_gateway_security_policy_test PRIVATE
    securecloud::gateway_http
    securecloud_proto
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_gateway_security_policy_test ${SECURECLOUD_TEST_PROPERTIES})

# Gateway Authentication Middleware Test (GW-004-T05)
add_executable(securecloud_authentication_middleware_test
    gateway/authentication_middleware_test.cpp
)

target_link_libraries(securecloud_authentication_middleware_test PRIVATE
    securecloud::gateway_http
    securecloud_proto
    securecloud::json
    securecloud::compiler_flags
    GTest::gmock
    GTest::gtest_main
)

gtest_discover_tests(securecloud_authentication_middleware_test ${SECURECLOUD_TEST_PROPERTIES})

# Gateway Perimeter Header Sanitizer Test (GW-005-T01)
add_executable(securecloud_header_sanitizer_test
    gateway/header_sanitizer_test.cpp
)

target_link_libraries(securecloud_header_sanitizer_test PRIVATE
    securecloud::gateway_http
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_header_sanitizer_test ${SECURECLOUD_TEST_PROPERTIES})

# Gateway RequestContext Lifecycle & Scope Test (GW-005-T02)
add_executable(securecloud_request_context_test
    gateway/request_context_test.cpp
)

target_link_libraries(securecloud_request_context_test PRIVATE
    securecloud::gateway_http
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_request_context_test ${SECURECLOUD_TEST_PROPERTIES})

# Gateway AuthenticatedContext Lifecycle & Accessor Test (GW-005-T03)
add_executable(securecloud_authenticated_context_lifecycle_test
    gateway/authenticated_context_lifecycle_test.cpp
)

target_link_libraries(securecloud_authenticated_context_lifecycle_test PRIVATE
    securecloud::gateway_http
    securecloud_proto
    securecloud::json
    securecloud::compiler_flags
    GTest::gmock
    GTest::gtest_main
)

gtest_discover_tests(securecloud_authenticated_context_lifecycle_test ${SECURECLOUD_TEST_PROPERTIES})

# Gateway Auth Microservice HTTP Proxy Handler Test (GW-006-T01)
add_executable(securecloud_auth_proxy_handler_test
    gateway/auth_proxy_handler_test.cpp
)

target_link_libraries(securecloud_auth_proxy_handler_test PRIVATE
    securecloud::gateway_http
    securecloud_proto
    securecloud::json
    securecloud::compiler_flags
    GTest::gmock
    GTest::gtest_main
)

gtest_discover_tests(securecloud_auth_proxy_handler_test ${SECURECLOUD_TEST_PROPERTIES})

# Gateway Files Microservice HTTP Streaming Proxy Handler Test (GW-010-T03)
add_executable(securecloud_files_proxy_handler_test
    gateway/files_proxy_handler_test.cpp
)

target_link_libraries(securecloud_files_proxy_handler_test PRIVATE
    securecloud::gateway_http
    securecloud_proto
    securecloud::json
    securecloud::common
    securecloud::compiler_flags
    GTest::gmock
    GTest::gtest
)

gtest_discover_tests(securecloud_files_proxy_handler_test ${SECURECLOUD_TEST_PROPERTIES})


# Gateway Route Registrar & Main Pipeline Assembly Test (GW-006-T02)
add_executable(securecloud_gateway_route_registrar_test
    gateway/gateway_route_registrar_test.cpp
)

target_link_libraries(securecloud_gateway_route_registrar_test PRIVATE
    securecloud::gateway_http
    securecloud_proto
    securecloud::json
    securecloud::common
    securecloud::compiler_flags
    GTest::gmock
    GTest::gtest_main
)

gtest_discover_tests(securecloud_gateway_route_registrar_test ${SECURECLOUD_TEST_PROPERTIES})

# Gateway Scope Matcher Test (GW-007-T01)
add_executable(securecloud_scope_matcher_test
    gateway/scope_matcher_test.cpp
)

target_link_libraries(securecloud_scope_matcher_test PRIVATE
    securecloud::gateway_http
    securecloud_proto
    securecloud::json
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_scope_matcher_test ${SECURECLOUD_TEST_PROPERTIES})

# Gateway Authorization Middleware Test (GW-007-T03)
add_executable(securecloud_authorization_middleware_test
    gateway/authorization_middleware_test.cpp
)

target_link_libraries(securecloud_authorization_middleware_test PRIVATE
    securecloud::gateway_http
    securecloud_proto
    securecloud::json
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_authorization_middleware_test ${SECURECLOUD_TEST_PROPERTIES})

# Gateway MFA Assurance Policy Unit Test Suite (AUTH-006-T05)
add_executable(securecloud_gateway_mfa_assurance_policy_test
    gateway/gateway_mfa_assurance_policy_test.cpp
)

target_link_libraries(securecloud_gateway_mfa_assurance_policy_test PRIVATE
    securecloud::gateway_http
    securecloud_proto
    securecloud::json
    securecloud::httplib
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_gateway_mfa_assurance_policy_test ${SECURECLOUD_TEST_PROPERTIES})

# Gateway Device Perimeter Assurance Policy Unit Test Suite (AUTH-007-T05)
add_executable(securecloud_gateway_device_assurance_policy_test
    gateway/gateway_device_assurance_policy_test.cpp
)

target_link_libraries(securecloud_gateway_device_assurance_policy_test PRIVATE
    securecloud::gateway_http
    securecloud_proto
    securecloud::json
    securecloud::httplib
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_gateway_device_assurance_policy_test ${SECURECLOUD_TEST_PROPERTIES})

# Gateway Error Mapper & RFC 7807 Problem Details Test (GW-008-T01)
add_executable(securecloud_gateway_error_mapper_test
    gateway/error_mapper_test.cpp
)

target_link_libraries(securecloud_gateway_error_mapper_test PRIVATE
    securecloud::gateway_http
    securecloud_proto
    securecloud::json
    securecloud::httplib
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_gateway_error_mapper_test ${SECURECLOUD_TEST_PROPERTIES})

# Gateway Deadline Manager & Strict Budget Propagation Test (GW-008-T02)
add_executable(securecloud_gateway_deadline_manager_test
    gateway/deadline_manager_test.cpp
)

target_link_libraries(securecloud_gateway_deadline_manager_test PRIVATE
    securecloud::gateway_http
    securecloud::gateway_config
    securecloud::httplib
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_gateway_deadline_manager_test ${SECURECLOUD_TEST_PROPERTIES})

# Gateway Retry Policy Engine & Idempotency Evaluator Test (GW-008-T03)
add_executable(securecloud_gateway_retry_policy_test
    gateway/retry_policy_test.cpp
)

target_link_libraries(securecloud_gateway_retry_policy_test PRIVATE
    securecloud::gateway_http
    securecloud::gateway_config
    securecloud::httplib
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_gateway_retry_policy_test ${SECURECLOUD_TEST_PROPERTIES})

# Gateway Workload Bulkhead Manager Test (GW-009-T01)
add_executable(securecloud_gateway_bulkhead_manager_test
    gateway/bulkhead_manager_test.cpp
)

target_link_libraries(securecloud_gateway_bulkhead_manager_test PRIVATE
    securecloud::gateway_http
    securecloud::gateway_config
    securecloud::httplib
    securecloud_proto
    securecloud::json
    securecloud::common
    securecloud::compiler_flags
    GTest::gmock
    GTest::gtest_main
)

gtest_discover_tests(securecloud_gateway_bulkhead_manager_test ${SECURECLOUD_TEST_PROPERTIES})

# Gateway Token-Bucket Rate Limiter Middleware Test (GW-009-T02)
add_executable(securecloud_gateway_rate_limiter_middleware_test
    gateway/rate_limiter_middleware_test.cpp
)

target_link_libraries(securecloud_gateway_rate_limiter_middleware_test PRIVATE
    securecloud::gateway_http
    securecloud::gateway_config
    securecloud::httplib
    securecloud::json
    securecloud::common
    securecloud::compiler_flags
    GTest::gmock
    GTest::gtest_main
)

gtest_discover_tests(securecloud_gateway_rate_limiter_middleware_test ${SECURECLOUD_TEST_PROPERTIES})

# Gateway Downstream Service Circuit Breaker Engine Test (GW-009-T03)
add_executable(securecloud_gateway_circuit_breaker_test
    gateway/circuit_breaker_test.cpp
)

target_link_libraries(securecloud_gateway_circuit_breaker_test PRIVATE
    securecloud::gateway_http
    securecloud::gateway_config
    securecloud::httplib
    securecloud_proto
    securecloud::json
    securecloud::common
    securecloud::compiler_flags
    GTest::gmock
    GTest::gtest_main
)

gtest_discover_tests(securecloud_gateway_circuit_breaker_test ${SECURECLOUD_TEST_PROPERTIES})

# Gateway Downstream gRPC Channel Manager Test (GW-001-T05)
add_executable(securecloud_channel_manager_test
    gateway/channel_manager_test.cpp
)

target_link_libraries(securecloud_channel_manager_test PRIVATE
    securecloud::gateway_grpc
    securecloud::gateway_config
    securecloud::common
    securecloud::compiler_flags
    GTest::gtest
)

target_compile_definitions(securecloud_channel_manager_test PRIVATE
    SECURECLOUD_DEV_PKI_DIR="${CMAKE_SOURCE_DIR}/deploy/dev-pki"
)

gtest_discover_tests(securecloud_channel_manager_test ${SECURECLOUD_TEST_PROPERTIES})

# Gateway Channel Manager Lifecycle & Connection Health Test (GW-003-T03)
add_executable(securecloud_channel_manager_lifecycle_test
    gateway/channel_manager_lifecycle_test.cpp
)

target_link_libraries(securecloud_channel_manager_lifecycle_test PRIVATE
    securecloud::gateway_grpc
    securecloud::gateway_config
    securecloud::common
    securecloud::compiler_flags
    GTest::gtest
)

target_compile_definitions(securecloud_channel_manager_lifecycle_test PRIVATE
    SECURECLOUD_DEV_PKI_DIR="${CMAKE_SOURCE_DIR}/deploy/dev-pki"
)

gtest_discover_tests(securecloud_channel_manager_lifecycle_test ${SECURECLOUD_TEST_PROPERTIES})

# Gateway RPC Call Context, Deadline & Cancellation Test (GW-003-T02)
add_executable(securecloud_client_call_context_test
    gateway/client_call_context_test.cpp
)

target_link_libraries(securecloud_client_call_context_test PRIVATE
    securecloud::gateway_grpc
    securecloud::common
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_client_call_context_test ${SECURECLOUD_TEST_PROPERTIES})

# Gateway Typed AuthServiceClient Test (GW-003-T04)
add_executable(securecloud_auth_service_client_test
    gateway/auth_service_client_test.cpp
)

target_link_libraries(securecloud_auth_service_client_test PRIVATE
    securecloud::gateway_grpc
    securecloud_proto
    securecloud::common
    securecloud::compiler_flags
    GTest::gtest
)

gtest_discover_tests(securecloud_auth_service_client_test ${SECURECLOUD_TEST_PROPERTIES})

# Gateway Typed FilesServiceClient Test (GW-010-T01)
add_executable(securecloud_files_service_client_test
    gateway/files_service_client_test.cpp
)

target_link_libraries(securecloud_files_service_client_test PRIVATE
    securecloud::gateway_grpc
    securecloud_proto
    securecloud::common
    securecloud::compiler_flags
    GTest::gtest
)

gtest_discover_tests(securecloud_files_service_client_test ${SECURECLOUD_TEST_PROPERTIES})

# Gateway Bounded Streaming Buffer & Backpressure Test (GW-010-T02)
add_executable(securecloud_streaming_buffer_test
    gateway/streaming_buffer_test.cpp
)

target_link_libraries(securecloud_streaming_buffer_test PRIVATE
    securecloud::gateway_http
    securecloud::common
    OpenSSL::Crypto
    securecloud::compiler_flags
    GTest::gtest
)

gtest_discover_tests(securecloud_streaming_buffer_test ${SECURECLOUD_TEST_PROPERTIES})



# Gateway TLS & Transport Resource Configuration Model Test (GW-002-T01)

add_executable(securecloud_gateway_tls_config_test
    gateway/gateway_tls_config_test.cpp
)

target_link_libraries(securecloud_gateway_tls_config_test PRIVATE
    securecloud::gateway_config
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_gateway_tls_config_test ${SECURECLOUD_TEST_PROPERTIES})

# Gateway OpenSSL TLS Context & Certificate Pair Validator Test (GW-002-T02)
add_executable(securecloud_tls_handler_test
    gateway/tls_handler_test.cpp
)

target_link_libraries(securecloud_tls_handler_test PRIVATE
    securecloud::gateway_tls
    securecloud::compiler_flags
    GTest::gtest_main
)

target_compile_definitions(securecloud_tls_handler_test PRIVATE
    SECURECLOUD_DEV_PKI_DIR="${CMAKE_SOURCE_DIR}/deploy/dev-pki"
)

gtest_discover_tests(securecloud_tls_handler_test ${SECURECLOUD_TEST_PROPERTIES})

# Gateway HTTPS Server Engine Integration Test (GW-002-T03)
add_executable(securecloud_https_server_lifecycle_test
    gateway/https_server_lifecycle_test.cpp
)

target_link_libraries(securecloud_https_server_lifecycle_test PRIVATE
    securecloud::gateway_http
    securecloud::gateway_tls
    securecloud::httplib
    securecloud::compiler_flags
    GTest::gtest_main
)

target_compile_definitions(securecloud_https_server_lifecycle_test PRIVATE
    SECURECLOUD_DEV_PKI_DIR="${CMAKE_SOURCE_DIR}/deploy/dev-pki"
)

gtest_discover_tests(securecloud_https_server_lifecycle_test ${SECURECLOUD_TEST_PROPERTIES})

# Gateway Request & Resource Limiter Middleware Test (GW-002-T04)
add_executable(securecloud_resource_limiter_middleware_test
    gateway/resource_limiter_middleware_test.cpp
)

target_link_libraries(securecloud_resource_limiter_middleware_test PRIVATE
    securecloud::gateway_http
    securecloud::gateway_config
    securecloud::httplib
    securecloud::json
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_resource_limiter_middleware_test ${SECURECLOUD_TEST_PROPERTIES})

# Gateway Insecure Protocol Downgrade Rejection & HTTP Redirect Guard Test (GW-002-T05)
add_executable(securecloud_downgrade_guard_test
    gateway/downgrade_guard_test.cpp
)

target_link_libraries(securecloud_downgrade_guard_test PRIVATE
    securecloud::gateway_http
    securecloud::gateway_tls
    securecloud::httplib
    OpenSSL::SSL
    OpenSSL::Crypto
    securecloud::compiler_flags
    GTest::gtest_main
)

target_compile_definitions(securecloud_downgrade_guard_test PRIVATE
    SECURECLOUD_DEV_PKI_DIR="${CMAKE_SOURCE_DIR}/deploy/dev-pki"
)

gtest_discover_tests(securecloud_downgrade_guard_test ${SECURECLOUD_TEST_PROPERTIES})

# Files PostgreSQL Connection Pool Unit Test Suite (FILES-001-T02)
add_executable(securecloud_files_connection_pool_test
    files/files_connection_pool_test.cpp
)

target_link_libraries(securecloud_files_connection_pool_test PRIVATE
    securecloud::files_db
    securecloud::files_config
    securecloud::common
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_files_connection_pool_test ${SECURECLOUD_TEST_PROPERTIES})

# Files S3 Storage Client Unit Test Suite (FILES-001-T03)
add_executable(securecloud_s3_client_test
    files/s3_client_test.cpp
)

target_link_libraries(securecloud_s3_client_test PRIVATE
    securecloud::files_storage
    securecloud::files_config
    securecloud::common
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_s3_client_test ${SECURECLOUD_TEST_PROPERTIES})

# Files Service Implementation Unit Test Suite (FILES-001-T04)
add_executable(securecloud_files_service_impl_test
    files/files_service_impl_test.cpp
)

target_link_libraries(securecloud_files_service_impl_test PRIVATE
    securecloud::files_service
    securecloud::files_storage
    securecloud::files_db
    securecloud::files_config
    securecloud::common
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_files_service_impl_test ${SECURECLOUD_TEST_PROPERTIES})

# Files Dual-Dependency Health Evaluator Unit Test Suite (FILES-001-T05)
add_executable(securecloud_files_health_evaluator_test
    files/files_health_evaluator_test.cpp
)

target_link_libraries(securecloud_files_health_evaluator_test PRIVATE
    securecloud::files_health
    securecloud::files_storage
    securecloud::files_db
    securecloud::files_config
    securecloud::common
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_files_health_evaluator_test ${SECURECLOUD_TEST_PROPERTIES})
