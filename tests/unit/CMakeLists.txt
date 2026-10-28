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
if(WIN32 AND DEFINED _TEST_ENV_MODS)
    set_tests_properties(unit_smoke_test PROPERTIES ENVIRONMENT_MODIFICATION "${_TEST_ENV_MODS}")
endif()

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
if(WIN32 AND DEFINED _TEST_ENV_MODS)
    set_tests_properties(dependency_smoke_test PROPERTIES ENVIRONMENT_MODIFICATION "${_TEST_ENV_MODS}")
endif()

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
    # Ensure Windows runtime finds dependent DLLs from the active compiler toolchain and vcpkg
    set(_CONTRACTS_ENV_FLAGS "")
    if(CMAKE_CXX_COMPILER)
        get_filename_component(_COMPILER_BIN_DIR "${CMAKE_CXX_COMPILER}" DIRECTORY)
        if(EXISTS "${_COMPILER_BIN_DIR}")
            list(APPEND _CONTRACTS_ENV_FLAGS "--modify" "PATH=path_list_prepend:${_COMPILER_BIN_DIR}")
        endif()
    endif()
    if(EXISTS "${CMAKE_BINARY_DIR}/vcpkg_installed/x64-windows/debug/bin")
        list(APPEND _CONTRACTS_ENV_FLAGS "--modify" "PATH=path_list_prepend:${CMAKE_BINARY_DIR}/vcpkg_installed/x64-windows/debug/bin")
    endif()
    if(EXISTS "${CMAKE_BINARY_DIR}/vcpkg_installed/x64-windows/bin")
        list(APPEND _CONTRACTS_ENV_FLAGS "--modify" "PATH=path_list_prepend:${CMAKE_BINARY_DIR}/vcpkg_installed/x64-windows/bin")
    endif()
    if(DEFINED VCPKG_TARGET_TRIPLET)
        if(EXISTS "${CMAKE_BINARY_DIR}/vcpkg_installed/${VCPKG_TARGET_TRIPLET}/debug/bin")
            list(APPEND _CONTRACTS_ENV_FLAGS "--modify" "PATH=path_list_prepend:${CMAKE_BINARY_DIR}/vcpkg_installed/${VCPKG_TARGET_TRIPLET}/debug/bin")
        endif()
        if(EXISTS "${CMAKE_BINARY_DIR}/vcpkg_installed/${VCPKG_TARGET_TRIPLET}/bin")
            list(APPEND _CONTRACTS_ENV_FLAGS "--modify" "PATH=path_list_prepend:${CMAKE_BINARY_DIR}/vcpkg_installed/${VCPKG_TARGET_TRIPLET}/bin")
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

# Auth Prekey Batch Validator Test Suite (AUTH-009-T01)
add_executable(securecloud_auth_prekey_validator_test
        auth/prekey_validator_test.cpp
)

target_link_libraries(securecloud_auth_prekey_validator_test PRIVATE
        securecloud::auth
        securecloud::common
        OpenSSL::Crypto
        securecloud::compiler_flags
        GTest::gtest_main
        GTest::gmock
)

gtest_discover_tests(securecloud_auth_prekey_validator_test ${SECURECLOUD_TEST_PROPERTIES})

# Auth Prekey Manager Test Suite (AUTH-009-T02)
add_executable(securecloud_auth_prekey_manager_test
        auth/prekey_manager_test.cpp
)

target_link_libraries(securecloud_auth_prekey_manager_test PRIVATE
        securecloud::auth
        securecloud::common
        OpenSSL::Crypto
        securecloud::compiler_flags
        GTest::gtest_main
        GTest::gmock
)

gtest_discover_tests(securecloud_auth_prekey_manager_test ${SECURECLOUD_TEST_PROPERTIES})

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

# Auth Service Crypto RPCs Test Suite (AUTH-008-T03)
add_executable(securecloud_auth_service_crypto_test
        auth/auth_service_crypto_test.cpp
)

target_link_libraries(securecloud_auth_service_crypto_test PRIVATE
        securecloud::auth
        securecloud::common
        securecloud_proto
        OpenSSL::Crypto
        securecloud::compiler_flags
        GTest::gtest_main
        GTest::gmock
)

gtest_discover_tests(securecloud_auth_service_crypto_test ${SECURECLOUD_TEST_PROPERTIES})

# Auth Service Prekey RPC Handlers Test Suite (AUTH-009-T03)
add_executable(securecloud_auth_service_prekey_test
        auth/auth_service_prekey_test.cpp
)

target_link_libraries(securecloud_auth_service_prekey_test PRIVATE
        securecloud::auth
        securecloud::common
        securecloud_proto
        securecloud::compiler_flags
        GTest::gtest_main
        GTest::gmock
)

gtest_discover_tests(securecloud_auth_service_prekey_test ${SECURECLOUD_TEST_PROPERTIES})

# Auth Service Public Signing Key Distribution Test Suite (AUTH-010-T01)
add_executable(securecloud_auth_service_public_key_test
        auth/auth_service_public_key_test.cpp
)

target_link_libraries(securecloud_auth_service_public_key_test PRIVATE
        securecloud::auth
        securecloud::gateway_http
        securecloud::common
        securecloud_proto
        OpenSSL::Crypto
        securecloud::compiler_flags
        GTest::gtest_main
        GTest::gmock
)

gtest_discover_tests(securecloud_auth_service_public_key_test ${SECURECLOUD_TEST_PROPERTIES})

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

# Gateway Auth Microservice MFA HTTP Proxy Handler Test (AUTH-010-T02)
add_executable(securecloud_auth_proxy_handler_mfa_test
    gateway/auth_proxy_handler_mfa_test.cpp
)

target_link_libraries(securecloud_auth_proxy_handler_mfa_test PRIVATE
    securecloud::gateway_http
    securecloud_proto
    securecloud::json
    securecloud::compiler_flags
    GTest::gmock
    GTest::gtest_main
)

gtest_discover_tests(securecloud_auth_proxy_handler_mfa_test ${SECURECLOUD_TEST_PROPERTIES})

# Gateway Auth Microservice Device Lifecycle HTTP Proxy Handler Test (AUTH-010-T03)
add_executable(securecloud_auth_proxy_handler_device_lifecycle_test
    gateway/auth_proxy_handler_device_lifecycle_test.cpp
)

target_link_libraries(securecloud_auth_proxy_handler_device_lifecycle_test PRIVATE
    securecloud::gateway_http
    securecloud_proto
    securecloud::json
    securecloud::compiler_flags
    GTest::gmock
    GTest::gtest_main
)

gtest_discover_tests(securecloud_auth_proxy_handler_device_lifecycle_test ${SECURECLOUD_TEST_PROPERTIES})

# Gateway Auth Microservice Perimeter Resilience & RFC 7807 Error Mapping Test (AUTH-010-T04)
add_executable(securecloud_auth_proxy_resilience_test
    gateway/auth_proxy_resilience_test.cpp
)

target_link_libraries(securecloud_auth_proxy_resilience_test PRIVATE
    securecloud::gateway_http
    securecloud_proto
    securecloud::json
    securecloud::compiler_flags
    GTest::gmock
    GTest::gtest_main
)

if(WIN32)
    target_link_libraries(securecloud_auth_proxy_resilience_test PRIVATE ws2_32)
endif()

gtest_discover_tests(securecloud_auth_proxy_resilience_test ${SECURECLOUD_TEST_PROPERTIES})

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

# Gateway Crypto Directory Perimeter Policy Unit Test Suite (AUTH-008-T04)
add_executable(securecloud_gateway_crypto_directory_policy_test
    gateway/gateway_crypto_directory_policy_test.cpp
)

target_link_libraries(securecloud_gateway_crypto_directory_policy_test PRIVATE
    securecloud::gateway_http
    securecloud_proto
    securecloud::json
    securecloud::httplib
    securecloud::compiler_flags
    GTest::gmock
    GTest::gtest_main
)

gtest_discover_tests(securecloud_gateway_crypto_directory_policy_test ${SECURECLOUD_TEST_PROPERTIES})

# Gateway Prekey Inventory & Claim Perimeter Policy Unit Test Suite (AUTH-009-T04)
add_executable(securecloud_gateway_prekey_inventory_policy_test
    gateway/gateway_prekey_inventory_policy_test.cpp
)

target_link_libraries(securecloud_gateway_prekey_inventory_policy_test PRIVATE
    securecloud::gateway_http
    securecloud_proto
    securecloud::json
    securecloud::httplib
    securecloud::compiler_flags
    GTest::gmock
    GTest::gtest_main
)

gtest_discover_tests(securecloud_gateway_prekey_inventory_policy_test ${SECURECLOUD_TEST_PROPERTIES})

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

# Files Storage Engine Unit Test Suite (FILES-003-T05)
add_executable(securecloud_storage_engine_test
    files/storage_engine_test.cpp
)

target_link_libraries(securecloud_storage_engine_test PRIVATE
    securecloud::files_service
    securecloud::files_storage
    securecloud::files_config
    securecloud::common
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_storage_engine_test ${SECURECLOUD_TEST_PROPERTIES})

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
# Files Schema Migration Unit Test Suite (FILES-002-T01)
add_executable(securecloud_files_schema_migration_test
    files/schema_migration_test.cpp
)

target_link_libraries(securecloud_files_schema_migration_test PRIVATE
    securecloud::files_db
    securecloud::files_config
    securecloud::common
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_files_schema_migration_test ${SECURECLOUD_TEST_PROPERTIES})

# Files Domain Entities & Type Mappers Unit Test Suite (FILES-002-T02)
add_executable(securecloud_domain_entities_test
    files/domain_entities_test.cpp
)

target_link_libraries(securecloud_domain_entities_test PRIVATE
    securecloud::files_db
    securecloud::files_config
    securecloud::common
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_domain_entities_test ${SECURECLOUD_TEST_PROPERTIES})

# Files File & Version Repositories Unit Test Suite (FILES-002-T03)
add_executable(securecloud_file_repository_test
    files/file_repository_test.cpp
)

target_link_libraries(securecloud_file_repository_test PRIVATE
    securecloud::files_db
    securecloud::files_config
    securecloud::common
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_file_repository_test ${SECURECLOUD_TEST_PROPERTIES})

# Files Resumable Transfer & Idempotent Chunk Repositories Unit Test Suite (FILES-002-T04)
add_executable(securecloud_transfer_chunk_repository_test
    files/transfer_chunk_repository_test.cpp
)

target_link_libraries(securecloud_transfer_chunk_repository_test PRIVATE
    securecloud::files_db
    securecloud::files_config
    securecloud::common
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_transfer_chunk_repository_test ${SECURECLOUD_TEST_PROPERTIES})

# Files Access Control & Transactional Outbox Repositories Unit Test Suite (FILES-002-T05)
add_executable(securecloud_access_outbox_repository_test
    files/access_outbox_repository_test.cpp
)

target_link_libraries(securecloud_access_outbox_repository_test PRIVATE
    securecloud::files_db
    securecloud::files_config
    securecloud::common
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_access_outbox_repository_test ${SECURECLOUD_TEST_PROPERTIES})

# Files Lifecycle State Machine Unit Test Suite (FILES-004-T01)
add_executable(securecloud_files_lifecycle_state_machine_test
    files/lifecycle_state_machine_test.cpp
)

target_link_libraries(securecloud_files_lifecycle_state_machine_test PRIVATE
    securecloud::files_db
    securecloud::files_config
    securecloud::common
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_files_lifecycle_state_machine_test ${SECURECLOUD_TEST_PROPERTIES})

# Files Metadata Validator Unit Test Suite (FILES-004-T02)
add_executable(securecloud_files_metadata_validator_test
    files/metadata_validator_test.cpp
)

target_link_libraries(securecloud_files_metadata_validator_test PRIVATE
    securecloud::files_db
    securecloud::files_config
    securecloud::common
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_files_metadata_validator_test ${SECURECLOUD_TEST_PROPERTIES})

# Files Chunk Validator Unit Test Suite (FILES-005-T01)
add_executable(securecloud_files_chunk_validator_test
    files/chunk_validator_test.cpp
)

target_link_libraries(securecloud_files_chunk_validator_test PRIVATE
    securecloud::files_db
    securecloud::files_config
    securecloud::common
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_files_chunk_validator_test ${SECURECLOUD_TEST_PROPERTIES})

# Files Upload Session Manager Unit Test Suite (FILES-005-T02)
add_executable(securecloud_files_upload_session_manager_test
    files/upload_session_manager_test.cpp
)

target_link_libraries(securecloud_files_upload_session_manager_test PRIVATE
    securecloud::files_service
    securecloud::files_db
    securecloud::files_config
    securecloud::common
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_files_upload_session_manager_test ${SECURECLOUD_TEST_PROPERTIES})

# Files Chunk Storage Service Unit Test Suite (FILES-005-T03)
add_executable(securecloud_files_chunk_storage_service_test
    files/chunk_storage_service_test.cpp
)

target_link_libraries(securecloud_files_chunk_storage_service_test PRIVATE
    securecloud::files_service
    securecloud::files_storage
    securecloud::files_db
    securecloud::files_config
    securecloud::common
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_files_chunk_storage_service_test ${SECURECLOUD_TEST_PROPERTIES})

# Files Finalization Precondition Validator Unit Test Suite (FILES-006-T01)
add_executable(securecloud_files_finalization_validator_test
    files/finalization_validator_test.cpp
)

target_link_libraries(securecloud_files_finalization_validator_test PRIVATE
    securecloud::files_db
    securecloud::files_config
    securecloud::common
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_files_finalization_validator_test ${SECURECLOUD_TEST_PROPERTIES})

# Files Object Assembly Engine Unit Test Suite (FILES-006-T02)
add_executable(securecloud_files_object_assembly_engine_test
    files/object_assembly_engine_test.cpp
)

target_link_libraries(securecloud_files_object_assembly_engine_test PRIVATE
    securecloud::files_service
    securecloud::files_storage
    securecloud::files_db
    securecloud::files_config
    securecloud::common
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_files_object_assembly_engine_test ${SECURECLOUD_TEST_PROPERTIES})

# Files Finalization Service Unit Test Suite (FILES-006-T03)
add_executable(securecloud_files_finalization_service_test
    files/file_finalization_service_test.cpp
)

target_link_libraries(securecloud_files_finalization_service_test PRIVATE
    securecloud::files_service
    securecloud::files_storage
    securecloud::files_db
    securecloud::files_config
    securecloud::common
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_files_finalization_service_test ${SECURECLOUD_TEST_PROPERTIES})

# Files Download Validator Unit Test Suite (FILES-007-T01)
add_executable(securecloud_files_download_validator_test
    files/download_validator_test.cpp
)

target_link_libraries(securecloud_files_download_validator_test PRIVATE
    securecloud::files_db
    securecloud::files_config
    securecloud::common
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_files_download_validator_test ${SECURECLOUD_TEST_PROPERTIES})

# Files Chunk Download Engine Unit Test Suite (FILES-007-T02)
add_executable(securecloud_files_chunk_download_engine_test
    files/chunk_download_engine_test.cpp
)

target_link_libraries(securecloud_files_chunk_download_engine_test PRIVATE
    securecloud::files_service
    securecloud::files_storage
    securecloud::files_db
    securecloud::files_config
    securecloud::common
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_files_chunk_download_engine_test ${SECURECLOUD_TEST_PROPERTIES})

# Files Download Manager Unit Test Suite (FILES-007-T03)
add_executable(securecloud_files_download_manager_test
    files/download_manager_test.cpp
)

target_link_libraries(securecloud_files_download_manager_test PRIVATE
    securecloud::files_service
    securecloud::files_storage
    securecloud::files_db
    securecloud::files_config
    securecloud::common
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_files_download_manager_test ${SECURECLOUD_TEST_PROPERTIES})

# Files Capability Serializer Unit Test Suite (FILES-008-T01)
add_executable(securecloud_files_file_capability_serializer_test
    files/file_capability_serializer_test.cpp
)

target_link_libraries(securecloud_files_file_capability_serializer_test PRIVATE
    securecloud::files_db
    securecloud::files_config
    securecloud::common
    securecloud::auth
    securecloud::json
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_files_file_capability_serializer_test ${SECURECLOUD_TEST_PROPERTIES})

# Files Capability Validator Unit Test Suite (FILES-008-T02)
add_executable(securecloud_files_capability_validator_test
    files/capability_validator_test.cpp
)

target_link_libraries(securecloud_files_capability_validator_test PRIVATE
    securecloud::files_db
    securecloud::files_config
    securecloud::common
    securecloud::auth
    securecloud::json
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_files_capability_validator_test ${SECURECLOUD_TEST_PROPERTIES})

# Files Resource Config Unit Test Suite (FILES-009-T01)
add_executable(securecloud_files_resource_config_test
    files/resource_config_test.cpp
)

target_link_libraries(securecloud_files_resource_config_test PRIVATE
    securecloud::files_config
    securecloud::common
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_files_resource_config_test ${SECURECLOUD_TEST_PROPERTIES})

# Files Concurrency Bulkhead Unit Test Suite (FILES-009-T02)
add_executable(securecloud_files_concurrency_bulkhead_test
    files/concurrency_bulkhead_test.cpp
)

target_link_libraries(securecloud_files_concurrency_bulkhead_test PRIVATE
    securecloud::files_config
    securecloud::common
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_files_concurrency_bulkhead_test ${SECURECLOUD_TEST_PROPERTIES})

# Files Bounded Storage Engine Unit Test Suite (FILES-009-T03)
add_executable(securecloud_files_bounded_storage_engine_test
    files/bounded_storage_engine_test.cpp
)

target_link_libraries(securecloud_files_bounded_storage_engine_test PRIVATE
    securecloud::files_storage
    securecloud::files_config
    securecloud::common
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_files_bounded_storage_engine_test ${SECURECLOUD_TEST_PROPERTIES})

# Files Memory Buffer Tracker Unit Test Suite (FILES-009-T04)
add_executable(securecloud_files_memory_buffer_tracker_test
    files/memory_buffer_tracker_test.cpp
)

target_link_libraries(securecloud_files_memory_buffer_tracker_test PRIVATE
    securecloud::files_config
    securecloud::common
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_files_memory_buffer_tracker_test ${SECURECLOUD_TEST_PROPERTIES})

# Files Device Revocation Provider Unit Test Suite (FILES-008-T03)
add_executable(securecloud_files_device_revocation_provider_test
    files/device_revocation_provider_test.cpp
)

target_link_libraries(securecloud_files_device_revocation_provider_test PRIVATE
    securecloud::files_db
    securecloud::files_config
    securecloud::common
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_files_device_revocation_provider_test ${SECURECLOUD_TEST_PROPERTIES})

# Files Capability Manager Unit Test Suite (FILES-008-T04)
add_executable(securecloud_files_file_capability_manager_test
    files/file_capability_manager_test.cpp
)

target_link_libraries(securecloud_files_file_capability_manager_test PRIVATE
    securecloud::files_service
    securecloud::files_db
    securecloud::files_config
    securecloud::common
    securecloud::auth
    securecloud::json
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_files_file_capability_manager_test ${SECURECLOUD_TEST_PROPERTIES})

# Files Lifecycle Service Unit Test Suite (FILES-004-T05)
add_executable(securecloud_files_lifecycle_service_test
    files/file_lifecycle_service_test.cpp
)

target_link_libraries(securecloud_files_lifecycle_service_test PRIVATE
    securecloud::files_service
    securecloud::files_db
    securecloud::files_config
    securecloud::common
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_files_lifecycle_service_test ${SECURECLOUD_TEST_PROPERTIES})


# Messaging Service Configuration Unit Test Suite (MSG-001-T02)
add_executable(securecloud_messaging_config_test
    messaging/messaging_config_test.cpp
)

target_link_libraries(securecloud_messaging_config_test PRIVATE
    securecloud::messaging_config
    securecloud::common
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_messaging_config_test ${SECURECLOUD_TEST_PROPERTIES})

# Messaging Bounded Worker Pool Unit Test Suite (MSG-001-T03)
add_executable(securecloud_bounded_worker_pool_test
    messaging/bounded_worker_pool_test.cpp
)

target_link_libraries(securecloud_bounded_worker_pool_test PRIVATE
    securecloud::messaging
    securecloud::common
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_bounded_worker_pool_test ${SECURECLOUD_TEST_PROPERTIES})

# Messaging Service Implementation Unit Test Suite (MSG-001-T04)
add_executable(securecloud_messaging_service_test
    messaging/messaging_service_test.cpp
)

target_link_libraries(securecloud_messaging_service_test PRIVATE
    securecloud::messaging
    securecloud::common
    securecloud_proto
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_messaging_service_test ${SECURECLOUD_TEST_PROPERTIES})

# Common Caller Context & Canonical UUID Unit Test Suite (MSG-002-T02)
add_executable(securecloud_caller_context_test
    common/caller_context_test.cpp
)

target_link_libraries(securecloud_caller_context_test PRIVATE
    securecloud::common
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_caller_context_test ${SECURECLOUD_TEST_PROPERTIES})

# Messaging Caller Context & Idempotency Token Unit Test Suite (MSG-002-T02)
add_executable(securecloud_messaging_caller_context_test
    messaging/messaging_caller_context_test.cpp
)

target_link_libraries(securecloud_messaging_caller_context_test PRIVATE
    securecloud::messaging
    securecloud::common
    securecloud_proto
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_messaging_caller_context_test ${SECURECLOUD_TEST_PROPERTIES})

# Messaging Contract Semantics & Delivery Lifecycle Unit Test Suite (MSG-002-T03)
add_executable(securecloud_messaging_contract_semantics_test
    messaging/messaging_contract_semantics_test.cpp
)

target_link_libraries(securecloud_messaging_contract_semantics_test PRIVATE
    securecloud::messaging
    securecloud::common
    securecloud_proto
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_messaging_contract_semantics_test ${SECURECLOUD_TEST_PROPERTIES})

# Messaging Error Mapper, Deadlines & Cancellation Unit Test Suite (MSG-002-T04)
add_executable(securecloud_messaging_error_mapper_test
    messaging/messaging_error_mapper_test.cpp
)

target_link_libraries(securecloud_messaging_error_mapper_test PRIVATE
    securecloud::messaging
    securecloud::common
    securecloud_proto
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_messaging_error_mapper_test ${SECURECLOUD_TEST_PROPERTIES})

# Gateway Typed MessagingServiceClient Test (MSG-002-T05)
add_executable(securecloud_messaging_service_client_test
    gateway/messaging_service_client_test.cpp
)

target_link_libraries(securecloud_messaging_service_client_test PRIVATE
    securecloud::gateway_grpc
    securecloud_proto
    securecloud::common
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_messaging_service_client_test ${SECURECLOUD_TEST_PROPERTIES})

# Conversation Domain Model, Value Objects & Lifecycle Unit Test Suite (MSG-003-T01)
add_executable(securecloud_conversation_domain_test
    messaging/conversation_domain_test.cpp
)

target_link_libraries(securecloud_conversation_domain_test PRIVATE
    securecloud::messaging
    securecloud::common
    securecloud::compiler_flags
    OpenSSL::Crypto
    GTest::gtest_main
)

gtest_discover_tests(securecloud_conversation_domain_test ${SECURECLOUD_TEST_PROPERTIES})

# Conversation and Membership Repository Unit Test Suite (MSG-003-T02)
add_executable(securecloud_conversation_repository_test
    messaging/conversation_repository_test.cpp
)

target_link_libraries(securecloud_conversation_repository_test PRIVATE
    securecloud::messaging
    securecloud::common
    securecloud::compiler_flags
    OpenSSL::Crypto
    GTest::gtest_main
)

gtest_discover_tests(securecloud_conversation_repository_test ${SECURECLOUD_TEST_PROPERTIES})

# Conversation Authorization Service Unit Test Suite (MSG-003-T03)
add_executable(securecloud_conversation_authorization_service_test
    messaging/conversation_authorization_service_test.cpp
)

target_link_libraries(securecloud_conversation_authorization_service_test PRIVATE
    securecloud::messaging
    securecloud::common
    securecloud::compiler_flags
    OpenSSL::Crypto
    GTest::gtest_main
)

gtest_discover_tests(securecloud_conversation_authorization_service_test ${SECURECLOUD_TEST_PROPERTIES})

# Conversation Domain Service Unit Test Suite (MSG-003-T04)
add_executable(securecloud_conversation_service_test
    messaging/conversation_service_test.cpp
)

target_link_libraries(securecloud_conversation_service_test PRIVATE
    securecloud::messaging
    securecloud::common
    securecloud::compiler_flags
    OpenSSL::Crypto
    GTest::gtest_main
)

gtest_discover_tests(securecloud_conversation_service_test ${SECURECLOUD_TEST_PROPERTIES})

# Gateway Conversation Routing Test (MSG-003-T05)
add_executable(securecloud_gateway_conversation_routing_test
    gateway/gateway_conversation_routing_test.cpp
)

target_link_libraries(securecloud_gateway_conversation_routing_test PRIVATE
    securecloud::gateway_http
    securecloud::gateway_grpc
    securecloud_proto
    securecloud::json
    securecloud::common
    securecloud::compiler_flags
    GTest::gmock
    GTest::gtest_main
)

gtest_discover_tests(securecloud_gateway_conversation_routing_test ${SECURECLOUD_TEST_PROPERTIES})

# ScyllaDB Migration Runner Test Suite (MSG-004-T01)
add_executable(securecloud_scylla_migration_runner_test
    messaging/scylla_migration_runner_test.cpp
)

target_link_libraries(securecloud_scylla_migration_runner_test PRIVATE
    securecloud::messaging
    securecloud::common
    securecloud::compiler_flags
    OpenSSL::Crypto
    GTest::gtest_main
)

gtest_discover_tests(securecloud_scylla_migration_runner_test ${SECURECLOUD_TEST_PROPERTIES})

# ScyllaDB Client Session & Connection Pool Test Suite (MSG-004-T02)
add_executable(securecloud_scylla_session_test
    messaging/scylla_session_test.cpp
)

target_link_libraries(securecloud_scylla_session_test PRIVATE
    securecloud::messaging
    securecloud::common
    securecloud::compiler_flags
    OpenSSL::Crypto
    GTest::gtest_main
)

gtest_discover_tests(securecloud_scylla_session_test ${SECURECLOUD_TEST_PROPERTIES})

# ScyllaDB Conversation & Membership Repository Test Suite (MSG-004-T03)
add_executable(securecloud_scylla_conversation_repository_test
    messaging/scylla_conversation_repository_test.cpp
)

target_link_libraries(securecloud_scylla_conversation_repository_test PRIVATE
    securecloud::messaging
    securecloud::common
    securecloud::compiler_flags
    OpenSSL::Crypto
    GTest::gtest_main
)

gtest_discover_tests(securecloud_scylla_conversation_repository_test ${SECURECLOUD_TEST_PROPERTIES})

# Message Bucket Calculation & Validation Test Suite (MSG-004-T04)
add_executable(securecloud_message_bucket_test
    messaging/message_bucket_test.cpp
)

target_link_libraries(securecloud_message_bucket_test PRIVATE
    securecloud::messaging
    securecloud::common
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_message_bucket_test ${SECURECLOUD_TEST_PROPERTIES})

# ScyllaDB Message & Outbox Repository Test Suite (MSG-004-T04)
add_executable(securecloud_scylla_message_repository_test
    messaging/scylla_message_repository_test.cpp
)

target_link_libraries(securecloud_scylla_message_repository_test PRIVATE
    securecloud::messaging
    securecloud::common
    securecloud::compiler_flags
    OpenSSL::Crypto
    GTest::gtest_main
)

gtest_discover_tests(securecloud_scylla_message_repository_test ${SECURECLOUD_TEST_PROPERTIES})

# ScyllaDB Delivery State Repository Test Suite (MSG-004-T05)
add_executable(securecloud_scylla_delivery_repository_test
    messaging/scylla_delivery_repository_test.cpp
)

target_link_libraries(securecloud_scylla_delivery_repository_test PRIVATE
    securecloud::messaging
    securecloud::common
    securecloud::compiler_flags
    OpenSSL::Crypto
    GTest::gtest_main
)

gtest_discover_tests(securecloud_scylla_delivery_repository_test ${SECURECLOUD_TEST_PROPERTIES})

# ScyllaDB Sync Cursor Repository Test Suite (MSG-004-T05)
add_executable(securecloud_scylla_sync_cursor_repository_test
    messaging/scylla_sync_cursor_repository_test.cpp
)

target_link_libraries(securecloud_scylla_sync_cursor_repository_test PRIVATE
    securecloud::messaging
    securecloud::common
    securecloud::compiler_flags
    OpenSSL::Crypto
    GTest::gtest_main
)

gtest_discover_tests(securecloud_scylla_sync_cursor_repository_test ${SECURECLOUD_TEST_PROPERTIES})

# ScyllaDB Idempotency Repository Test Suite (MSG-004-T05)
add_executable(securecloud_scylla_idempotency_repository_test
    messaging/scylla_idempotency_repository_test.cpp
)

target_link_libraries(securecloud_scylla_idempotency_repository_test PRIVATE
    securecloud::messaging
    securecloud::common
    securecloud::compiler_flags
    OpenSSL::Crypto
    GTest::gtest_main
)

gtest_discover_tests(securecloud_scylla_idempotency_repository_test ${SECURECLOUD_TEST_PROPERTIES})

# Submission Payload Fingerprinting Unit Test Suite (MSG-005-T01)
add_executable(securecloud_submission_fingerprint_test
    messaging/submission_fingerprint_test.cpp
)

target_link_libraries(securecloud_submission_fingerprint_test PRIVATE
    securecloud::messaging
    securecloud::common
    securecloud::compiler_flags
    OpenSSL::Crypto
    GTest::gtest_main
)

gtest_discover_tests(securecloud_submission_fingerprint_test ${SECURECLOUD_TEST_PROPERTIES})

# Message Submission Validator Unit Test Suite (MSG-005-T01)
add_executable(securecloud_submission_validator_test
    messaging/submission_validator_test.cpp
)

target_link_libraries(securecloud_submission_validator_test PRIVATE
    securecloud::messaging
    securecloud::common
    securecloud::compiler_flags
    OpenSSL::Crypto
    GTest::gtest_main
)

gtest_discover_tests(securecloud_submission_validator_test ${SECURECLOUD_TEST_PROPERTIES})

# Sequence Allocator & Partition Rollover Unit Test Suite (MSG-005-T02)
add_executable(securecloud_sequence_allocator_test
    messaging/sequence_allocator_test.cpp
)

target_link_libraries(securecloud_sequence_allocator_test PRIVATE
    securecloud::messaging
    securecloud::common
    securecloud::compiler_flags
    OpenSSL::Crypto
    GTest::gtest_main
)

gtest_discover_tests(securecloud_sequence_allocator_test ${SECURECLOUD_TEST_PROPERTIES})

# Idempotency Guard & Conflict Resolution Unit Test Suite (MSG-005-T03)
add_executable(securecloud_idempotency_guard_test
    messaging/idempotency_guard_test.cpp
)

target_link_libraries(securecloud_idempotency_guard_test PRIVATE
    securecloud::messaging
    securecloud::common
    securecloud::compiler_flags
    OpenSSL::Crypto
    GTest::gtest_main
)

gtest_discover_tests(securecloud_idempotency_guard_test ${SECURECLOUD_TEST_PROPERTIES})

# Message Submission Application Service Unit Test Suite (MSG-005-T04)
add_executable(securecloud_message_submission_service_test
    messaging/message_submission_service_test.cpp
)

target_link_libraries(securecloud_message_submission_service_test PRIVATE
    securecloud::messaging
    securecloud::common
    securecloud::compiler_flags
    OpenSSL::Crypto
    GTest::gtest_main
)

gtest_discover_tests(securecloud_message_submission_service_test ${SECURECLOUD_TEST_PROPERTIES})

# gRPC SendMessage Handler Unit Test Suite (MSG-005-T05)
add_executable(securecloud_messaging_service_submission_test
    messaging/messaging_service_submission_test.cpp
)

target_link_libraries(securecloud_messaging_service_submission_test PRIVATE
    securecloud::messaging
    securecloud::common
    securecloud::compiler_flags
    OpenSSL::Crypto
    GTest::gtest_main
)

gtest_discover_tests(securecloud_messaging_service_submission_test ${SECURECLOUD_TEST_PROPERTIES})

# Gateway Messaging Proxy Handler Unit Test Suite (MSG-005-T05)
add_executable(securecloud_messaging_proxy_handler_test
    gateway/messaging_proxy_handler_test.cpp
)

target_link_libraries(securecloud_messaging_proxy_handler_test PRIVATE
    securecloud::gateway_http
    securecloud::gateway_grpc
    securecloud_proto
    securecloud::json
    securecloud::common
    securecloud::compiler_flags
    GTest::gmock
    GTest::gtest_main
)

gtest_discover_tests(securecloud_messaging_proxy_handler_test ${SECURECLOUD_TEST_PROPERTIES})

# E2E Message Envelope Domain Types Unit Test Suite (MSG-006-T01)
add_executable(securecloud_envelope_types_test
    messaging/envelope_types_test.cpp
)

target_link_libraries(securecloud_envelope_types_test PRIVATE
    securecloud::messaging
    securecloud::common
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_envelope_types_test ${SECURECLOUD_TEST_PROPERTIES})

# Protocol Version & Crypto Policy Unit Test Suite (MSG-006-T01)
add_executable(securecloud_protocol_version_policy_test
    messaging/protocol_version_policy_test.cpp
)

target_link_libraries(securecloud_protocol_version_policy_test PRIVATE
    securecloud::messaging
    securecloud::common
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_protocol_version_policy_test ${SECURECLOUD_TEST_PROPERTIES})

# Recipient Device Resolution & Target Validation Unit Test Suite (MSG-006-T02)
add_executable(securecloud_recipient_device_resolution_service_test
    messaging/recipient_device_resolution_service_test.cpp
)

target_link_libraries(securecloud_recipient_device_resolution_service_test PRIVATE
    securecloud::messaging
    securecloud::common
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_recipient_device_resolution_service_test ${SECURECLOUD_TEST_PROPERTIES})

# Strict Envelope Security & Anti-Plaintext Guard Unit Test Suite (MSG-006-T03)
add_executable(securecloud_e2e_envelope_validator_test
    messaging/e2e_envelope_validator_test.cpp
)

target_link_libraries(securecloud_e2e_envelope_validator_test PRIVATE
    securecloud::messaging
    securecloud::common
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_e2e_envelope_validator_test ${SECURECLOUD_TEST_PROPERTIES})

# ScyllaDB Delivery Repository Per-Device Envelope Test Suite (MSG-006-T04)
add_executable(securecloud_scylla_delivery_repository_envelope_test
    messaging/scylla_delivery_repository_envelope_test.cpp
)

target_link_libraries(securecloud_scylla_delivery_repository_envelope_test PRIVATE
    securecloud::messaging
    securecloud::common
    securecloud::compiler_flags
    OpenSSL::Crypto
    GTest::gtest_main
)

gtest_discover_tests(securecloud_scylla_delivery_repository_envelope_test ${SECURECLOUD_TEST_PROPERTIES})

# Zero-Plaintext Guard Test Suite (MSG-006-T05)
add_executable(securecloud_zero_plaintext_guard_test
    messaging/zero_plaintext_guard_test.cpp
)

target_link_libraries(securecloud_zero_plaintext_guard_test PRIVATE
    securecloud::messaging
    securecloud::common
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_zero_plaintext_guard_test ${SECURECLOUD_TEST_PROPERTIES})

# Message Submission Service Envelope Integration Test Suite (MSG-006-T05)
add_executable(securecloud_message_submission_envelope_integration_test
    messaging/message_submission_envelope_integration_test.cpp
)

target_link_libraries(securecloud_message_submission_envelope_integration_test PRIVATE
    securecloud::messaging
    securecloud::common
    securecloud::compiler_flags
    OpenSSL::Crypto
    GTest::gtest_main
)

gtest_discover_tests(securecloud_message_submission_envelope_integration_test ${SECURECLOUD_TEST_PROPERTIES})

# Delivery Retry Policy & Decorrelated Jitter Unit Test Suite (MSG-007-T01)
add_executable(securecloud_delivery_retry_policy_test
    messaging/delivery_retry_policy_test.cpp
)

target_link_libraries(securecloud_delivery_retry_policy_test PRIVATE
    securecloud::messaging
    securecloud::common
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_delivery_retry_policy_test ${SECURECLOUD_TEST_PROPERTIES})

# Delivery Lifecycle State Machine & Domain Transition Test Suite (MSG-007-T01)
add_executable(securecloud_delivery_lifecycle_test
    messaging/delivery_lifecycle_test.cpp
)

target_link_libraries(securecloud_delivery_lifecycle_test PRIVATE
    securecloud::messaging
    securecloud::common
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_delivery_lifecycle_test ${SECURECLOUD_TEST_PROPERTIES})

# Device Connection Registry & Channel Routing Port Test Suite (MSG-007-T02)
add_executable(securecloud_device_connection_registry_test
    messaging/device_connection_registry_test.cpp
)

target_link_libraries(securecloud_device_connection_registry_test PRIVATE
    securecloud::messaging
    securecloud::common
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_device_connection_registry_test ${SECURECLOUD_TEST_PROPERTIES})

# Bounded In-Memory Delivery Scheduler & Per-Device Fairness Queue Test Suite (MSG-007-T03)
add_executable(securecloud_bounded_delivery_scheduler_test
    messaging/bounded_delivery_scheduler_test.cpp
)

target_link_libraries(securecloud_bounded_delivery_scheduler_test PRIVATE
    securecloud::messaging
    securecloud::common
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_bounded_delivery_scheduler_test ${SECURECLOUD_TEST_PROPERTIES})

# Delivery Worker Pipeline & Retry Scheduling Test Suite (MSG-007-T04)
add_executable(securecloud_delivery_worker_test
    messaging/delivery_worker_test.cpp
)

target_link_libraries(securecloud_delivery_worker_test PRIVATE
    securecloud::messaging
    securecloud::common
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_delivery_worker_test ${SECURECLOUD_TEST_PROPERTIES})

# Outbox Delivery Consumer & Online Device Dispatch Test Suite (MSG-007-T04)
add_executable(securecloud_outbox_delivery_consumer_test
    messaging/outbox_delivery_consumer_test.cpp
)

target_link_libraries(securecloud_outbox_delivery_consumer_test PRIVATE
    securecloud::messaging
    securecloud::common
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_outbox_delivery_consumer_test ${SECURECLOUD_TEST_PROPERTIES})

# Delivery Service & AcknowledgeDelivery RPC Test Suite (MSG-007-T05)
add_executable(securecloud_delivery_service_test
    messaging/delivery_service_test.cpp
)

target_link_libraries(securecloud_delivery_service_test PRIVATE
    securecloud::messaging
    securecloud::common
    securecloud_proto
    securecloud::json
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_delivery_service_test ${SECURECLOUD_TEST_PROPERTIES})

# Gateway Messaging Proxy Delivery Acknowledgement Route Test Suite (MSG-007-T05)
add_executable(securecloud_messaging_proxy_ack_test
    gateway/messaging_proxy_ack_test.cpp
)

target_link_libraries(securecloud_messaging_proxy_ack_test PRIVATE
    securecloud::gateway_http
    securecloud::gateway_grpc
    securecloud_proto
    securecloud::json
    securecloud::common
    securecloud::compiler_flags
    GTest::gmock
    GTest::gtest_main
)

gtest_discover_tests(securecloud_messaging_proxy_ack_test ${SECURECLOUD_TEST_PROPERTIES})

# Durable Delivery Recovery Engine Test Suite (MSG-007-T06)
add_executable(securecloud_durable_delivery_recovery_service_test
    messaging/durable_delivery_recovery_service_test.cpp
)

target_link_libraries(securecloud_durable_delivery_recovery_service_test PRIVATE
    securecloud::messaging
    securecloud::common
    securecloud_proto
    securecloud::json
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_durable_delivery_recovery_service_test ${SECURECLOUD_TEST_PROPERTIES})

# Comprehensive Online Delivery Pipeline 10-Scenario Integration Test Suite (MSG-007-T06)
add_executable(securecloud_online_delivery_pipeline_test
    messaging/online_delivery_pipeline_test.cpp
)

target_link_libraries(securecloud_online_delivery_pipeline_test PRIVATE
    securecloud::messaging
    securecloud::common
    securecloud_proto
    securecloud::json
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_online_delivery_pipeline_test ${SECURECLOUD_TEST_PROPERTIES})

# Delivery State Transition Guard & Regression Test Suite (MSG-008-T01)
add_executable(securecloud_delivery_state_transition_guard_test
    messaging/delivery_state_transition_guard_test.cpp
)

target_link_libraries(securecloud_delivery_state_transition_guard_test PRIVATE
    securecloud::messaging
    securecloud::common
    securecloud_proto
    securecloud::json
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_delivery_state_transition_guard_test ${SECURECLOUD_TEST_PROPERTIES})

# Read Receipt Domain Service & Group Read Semantics Test Suite (MSG-008-T02)
add_executable(securecloud_read_receipt_service_test
    messaging/read_receipt_service_test.cpp
)

target_link_libraries(securecloud_read_receipt_service_test PRIVATE
    securecloud::messaging
    securecloud::common
    securecloud_proto
    securecloud::json
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_read_receipt_service_test ${SECURECLOUD_TEST_PROPERTIES})

# MessagingService Delivery State & Read Receipt RPCs Test Suite (MSG-008-T04)
add_executable(securecloud_messaging_service_impl_delivery_state_test
    messaging/messaging_service_impl_delivery_state_test.cpp
)

target_link_libraries(securecloud_messaging_service_impl_delivery_state_test PRIVATE
    securecloud::messaging
    securecloud::common
    securecloud_proto
    securecloud::json
    securecloud::compiler_flags
    gRPC::grpc++
    GTest::gtest_main
)

gtest_discover_tests(securecloud_messaging_service_impl_delivery_state_test ${SECURECLOUD_TEST_PROPERTIES})

# Audit Service Configuration Models & Boundary Validation Test Suite (AUDIT-001-T04)
add_executable(securecloud_audit_config_test
    audit/audit_config_test.cpp
)

target_link_libraries(securecloud_audit_config_test PRIVATE
    securecloud::audit_config
    securecloud::common
    securecloud::compiler_flags
    GTest::gtest_main
)

gtest_discover_tests(securecloud_audit_config_test ${SECURECLOUD_TEST_PROPERTIES})

# Audit Service Lifecycle Engine & State Progression Test Suite (AUDIT-001-T04)
add_executable(securecloud_audit_server_lifecycle_test
    audit/audit_server_lifecycle_test.cpp
)

target_link_libraries(securecloud_audit_server_lifecycle_test PRIVATE
    securecloud::audit_server
    securecloud::common
    securecloud::compiler_flags
    GTest::gtest_main
)

if(WIN32)
    target_link_libraries(securecloud_audit_server_lifecycle_test PRIVATE ws2_32)
endif()

gtest_discover_tests(securecloud_audit_server_lifecycle_test ${SECURECLOUD_TEST_PROPERTIES})

# Messaging Online Synchronization Domain Types & Protobuf Contracts Test Suite (MSG-009-T01)
add_executable(securecloud_messaging_sync_types_test
    messaging/sync_types_test.cpp
)

target_link_libraries(securecloud_messaging_sync_types_test PRIVATE
    securecloud::messaging
    securecloud::common
    securecloud_proto
    securecloud::compiler_flags
    OpenSSL::Crypto
    GTest::gtest_main
)

gtest_discover_tests(securecloud_messaging_sync_types_test ${SECURECLOUD_TEST_PROPERTIES})

# Messaging Online Synchronization Cursor Manager Test Suite (MSG-009-T02)
add_executable(securecloud_sync_cursor_manager_test
    messaging/sync_cursor_manager_test.cpp
)

target_link_libraries(securecloud_sync_cursor_manager_test PRIVATE
    securecloud::messaging
    securecloud::common
    securecloud_proto
    securecloud::compiler_flags
    OpenSSL::Crypto
    GTest::gtest_main
)

gtest_discover_tests(securecloud_sync_cursor_manager_test ${SECURECLOUD_TEST_PROPERTIES})

# Messaging Online Message Synchronization Service Test Suite (MSG-009-T03)
add_executable(securecloud_message_sync_service_test
    messaging/message_sync_service_test.cpp
)

target_link_libraries(securecloud_message_sync_service_test PRIVATE
    securecloud::messaging
    securecloud::common
    securecloud_proto
    securecloud::compiler_flags
    OpenSSL::Crypto
    GTest::gtest_main
)

gtest_discover_tests(securecloud_message_sync_service_test ${SECURECLOUD_TEST_PROPERTIES})

# Gateway Messaging Proxy Message Synchronization & Cursor Management Test Suite (MSG-009-T04)
add_executable(securecloud_messaging_proxy_sync_test
    gateway/messaging_proxy_sync_test.cpp
)

target_link_libraries(securecloud_messaging_proxy_sync_test PRIVATE
    securecloud::gateway_http
    securecloud::gateway_grpc
    securecloud_proto
    securecloud::json
    securecloud::common
    securecloud::compiler_flags
    GTest::gmock
    GTest::gtest_main
)

gtest_discover_tests(securecloud_messaging_proxy_sync_test ${SECURECLOUD_TEST_PROPERTIES})

# MessagingService Implementation Sync RPCs Test Suite (MSG-009-T05)
add_executable(securecloud_messaging_service_impl_sync_test
    messaging/messaging_service_impl_sync_test.cpp
)

target_link_libraries(securecloud_messaging_service_impl_sync_test PRIVATE
    securecloud::messaging
    securecloud::common
    securecloud_proto
    securecloud::compiler_flags
    OpenSSL::Crypto
    GTest::gmock
    GTest::gtest_main
)

gtest_discover_tests(securecloud_messaging_service_impl_sync_test ${SECURECLOUD_TEST_PROPERTIES})

# Device Anti-Impersonation Perimeter Guard Unit Test Suite (MSG-011-T02)
add_executable(securecloud_device_anti_impersonation_test
    messaging/device_anti_impersonation_test.cpp
)

target_link_libraries(securecloud_device_anti_impersonation_test PRIVATE
    securecloud::messaging
    securecloud::common
    securecloud_proto
    securecloud::compiler_flags
    OpenSSL::Crypto
    GTest::gmock
    GTest::gtest_main
)

gtest_discover_tests(securecloud_device_anti_impersonation_test ${SECURECLOUD_TEST_PROPERTIES})

# Fail-Closed Device Revocation Quarantine Unit Test Suite (MSG-011-T03)
add_executable(securecloud_device_revocation_quarantine_test
    messaging/device_revocation_quarantine_test.cpp
)

target_link_libraries(securecloud_device_revocation_quarantine_test PRIVATE
    securecloud::messaging
    securecloud::common
    securecloud_proto
    securecloud::compiler_flags
    OpenSSL::Crypto
    GTest::gmock
    GTest::gtest_main
)

gtest_discover_tests(securecloud_device_revocation_quarantine_test ${SECURECLOUD_TEST_PROPERTIES})

# Per-Device Envelope Retrieval & Newly Enrolled Device Sync Boundary Unit Test Suite (MSG-011-T04)
add_executable(securecloud_new_device_sync_boundary_test
    messaging/new_device_sync_boundary_test.cpp
)

target_link_libraries(securecloud_new_device_sync_boundary_test PRIVATE
    securecloud::messaging
    securecloud::common
    securecloud_proto
    securecloud::compiler_flags
    OpenSSL::Crypto
    GTest::gmock
    GTest::gtest_main
)

gtest_discover_tests(securecloud_new_device_sync_boundary_test ${SECURECLOUD_TEST_PROPERTIES})

# Audit Service Domain Event Model Unit Test Suite (AUDIT-002-T06)
add_executable(securecloud_audit_event_model_test
        audit/audit_event_model_test.cpp
)

target_link_libraries(securecloud_audit_event_model_test PRIVATE
        securecloud::audit_domain
        securecloud::common
        securecloud::compiler_flags
        GTest::gtest_main
)

gtest_discover_tests(securecloud_audit_event_model_test ${SECURECLOUD_TEST_PROPERTIES})

# Audit Service Domain Validator Unit Test Suite (AUDIT-002-T06)
add_executable(securecloud_audit_event_validator_test
        audit/audit_event_validator_test.cpp
)

target_link_libraries(securecloud_audit_event_validator_test PRIVATE
        securecloud::audit_domain
        securecloud::common
        securecloud::compiler_flags
        GTest::gtest_main
)

gtest_discover_tests(securecloud_audit_event_validator_test ${SECURECLOUD_TEST_PROPERTIES})

# Audit Service Security Guard Unit Test Suite (AUDIT-002-T06)
add_executable(securecloud_audit_security_guard_test
        audit/sensitive_data_guard_test.cpp
)

target_link_libraries(securecloud_audit_security_guard_test PRIVATE
        securecloud::audit_domain
        securecloud::common
        securecloud::compiler_flags
        GTest::gtest_main
)

gtest_discover_tests(securecloud_audit_security_guard_test ${SECURECLOUD_TEST_PROPERTIES})

# Audit Service Producer Identity Validator Unit Test Suite (AUDIT-002-T06)
add_executable(securecloud_audit_producer_identity_validator_test
        audit/producer_identity_validator_test.cpp
)

target_link_libraries(securecloud_audit_producer_identity_validator_test PRIVATE
        securecloud::audit_domain
        securecloud::common
        securecloud::compiler_flags
        GTest::gtest_main
)

gtest_discover_tests(securecloud_audit_producer_identity_validator_test ${SECURECLOUD_TEST_PROPERTIES})

# Audit Service Protobuf Domain Mapper Unit Test Suite (AUDIT-002-T06)
add_executable(securecloud_audit_event_mapper_test
        audit/audit_event_mapper_test.cpp
)

target_link_libraries(securecloud_audit_event_mapper_test PRIVATE
        securecloud::audit_domain
        securecloud_proto
        securecloud::common
        securecloud::compiler_flags
        GTest::gtest_main
)

gtest_discover_tests(securecloud_audit_event_mapper_test ${SECURECLOUD_TEST_PROPERTIES})

# Messaging Presence & Connection Session Domain Types Test Suite (MSG-010-T01)
add_executable(securecloud_messaging_presence_types_test
    messaging/presence_types_test.cpp
)

target_link_libraries(securecloud_messaging_presence_types_test PRIVATE
    securecloud::messaging
    securecloud::common
    securecloud_proto
    securecloud::compiler_flags
    OpenSSL::Crypto
    GTest::gtest_main
)

gtest_discover_tests(securecloud_messaging_presence_types_test ${SECURECLOUD_TEST_PROPERTIES})

# Messaging Multi-Device Presence Coordinator Test Suite (MSG-010-T02)
add_executable(securecloud_presence_coordinator_test
    messaging/presence_coordinator_test.cpp
)

target_link_libraries(securecloud_presence_coordinator_test PRIVATE
    securecloud::messaging
    securecloud::common
    securecloud_proto
    securecloud::compiler_flags
    OpenSSL::Crypto
    GTest::gtest_main
)

gtest_discover_tests(securecloud_presence_coordinator_test ${SECURECLOUD_TEST_PROPERTIES})

# Messaging Connection Lifecycle Manager & Reaper Test Suite (MSG-010-T03)
add_executable(securecloud_connection_lifecycle_manager_test
    messaging/connection_lifecycle_manager_test.cpp
)

target_link_libraries(securecloud_connection_lifecycle_manager_test PRIVATE
    securecloud::messaging
    securecloud::common
    securecloud_proto
    securecloud::compiler_flags
    OpenSSL::Crypto
    GTest::gtest_main
)

gtest_discover_tests(securecloud_connection_lifecycle_manager_test ${SECURECLOUD_TEST_PROPERTIES})

# Messaging Realtime Delivery Accelerator Test Suite (MSG-010-T04)
add_executable(securecloud_realtime_delivery_accelerator_test
    messaging/realtime_delivery_accelerator_test.cpp
)

target_link_libraries(securecloud_realtime_delivery_accelerator_test PRIVATE
    securecloud::messaging
    securecloud::common
    securecloud_proto
    securecloud::compiler_flags
    OpenSSL::Crypto
    GTest::gtest_main
)

gtest_discover_tests(securecloud_realtime_delivery_accelerator_test ${SECURECLOUD_TEST_PROPERTIES})

# Messaging Service Presence RPCs & Mutual-Conversation Privacy Guard Test Suite (MSG-010-T05)
add_executable(securecloud_messaging_service_presence_test
    messaging/messaging_service_presence_test.cpp
)

target_link_libraries(securecloud_messaging_service_presence_test PRIVATE
    securecloud::messaging
    securecloud::common
    securecloud_proto
    securecloud::compiler_flags
    OpenSSL::Crypto
    GTest::gtest_main
)

gtest_discover_tests(securecloud_messaging_service_presence_test ${SECURECLOUD_TEST_PROPERTIES})

# Gateway Messaging Proxy Presence Endpoints Test Suite (MSG-010-T06)
add_executable(securecloud_messaging_proxy_presence_test
    gateway/messaging_proxy_presence_test.cpp
)

target_link_libraries(securecloud_messaging_proxy_presence_test PRIVATE
    securecloud::gateway_http
    securecloud::gateway_grpc
    securecloud_proto
    securecloud::json
    securecloud::common
    securecloud::compiler_flags
    GTest::gmock
    GTest::gtest_main
)

gtest_discover_tests(securecloud_messaging_proxy_presence_test ${SECURECLOUD_TEST_PROPERTIES})

# Messaging Presence Privacy Guard & Telemetry Test Suite (MSG-010-T07)
add_executable(securecloud_presence_privacy_guard_test
    messaging/presence_privacy_guard_test.cpp
)

target_link_libraries(securecloud_presence_privacy_guard_test PRIVATE
    securecloud::messaging
    securecloud::common
    securecloud_proto
    securecloud::compiler_flags
    OpenSSL::Crypto
    GTest::gmock
    GTest::gtest_main
)

gtest_discover_tests(securecloud_presence_privacy_guard_test ${SECURECLOUD_TEST_PROPERTIES})
