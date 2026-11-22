add_library(securecloud_files_config STATIC
        files_config.cpp
        concurrency/resource_config.cpp
        concurrency/concurrency_bulkhead.cpp
        concurrency/memory_buffer_tracker.cpp
)

add_library(securecloud::files_config ALIAS securecloud_files_config)

target_include_directories(securecloud_files_config PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(securecloud_files_config PUBLIC
        securecloud::common
        securecloud::compiler_flags
)

find_package(OpenSSL REQUIRED)

set(SECURECLOUD_FILES_DB_SOURCES
        db/files_connection_pool.cpp
        db/migration_runner.cpp
        db/pqxx_mappers.cpp
        domain/lifecycle_state_machine.cpp
        domain/metadata_validator.cpp
        domain/chunk_validator.cpp
        domain/finalization_validator.cpp
        domain/download_validator.cpp
        domain/file_capability_serializer.cpp
        domain/capability_validator.cpp
        repository/file_repository.cpp
        repository/file_version_repository.cpp
        repository/file_transfer_repository.cpp
        repository/file_chunk_repository.cpp
        repository/file_access_repository.cpp
        repository/device_revocation_provider.cpp
        repository/files_outbox_repository.cpp
)

add_library(securecloud_files_db STATIC ${SECURECLOUD_FILES_DB_SOURCES})

add_library(securecloud::files_db ALIAS securecloud_files_db)

target_include_directories(securecloud_files_db PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/src
)

target_compile_definitions(securecloud_files_db PUBLIC
        SECURECLOUD_FILES_USE_REAL_PQXX
)

target_link_libraries(securecloud_files_db PUBLIC
        securecloud::files_config
        securecloud::common
        securecloud::compiler_flags
        securecloud_proto
        OpenSSL::Crypto
        securecloud::json
        securecloud::auth
        securecloud::libpqxx
)

# Unit tests that exercise the in-memory pqxx compatibility layer need the
# Files DB sources compiled without SECURECLOUD_FILES_USE_REAL_PQXX. Keep this
# as a separate library so mock pqxx types never cross the production ABI.
if(BUILD_TESTING)
    add_library(securecloud_files_db_test STATIC ${SECURECLOUD_FILES_DB_SOURCES})
    add_library(securecloud::files_db_test ALIAS securecloud_files_db_test)

    target_include_directories(securecloud_files_db_test PUBLIC
            ${CMAKE_CURRENT_SOURCE_DIR}
            ${CMAKE_SOURCE_DIR}/src
    )

    target_compile_definitions(securecloud_files_db_test PUBLIC
            SECURECLOUD_FILES_TEST_PQXX
    )

    target_link_libraries(securecloud_files_db_test PUBLIC
            securecloud::files_config
            securecloud::common
            securecloud::compiler_flags
            securecloud_proto
            OpenSSL::Crypto
            securecloud::json
            securecloud::auth
    )
endif()

add_library(securecloud_files_storage STATIC
        storage/s3_client.cpp
        storage/bounded_storage_engine.cpp
)

add_library(securecloud::files_storage ALIAS securecloud_files_storage)

target_include_directories(securecloud_files_storage PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(securecloud_files_storage PUBLIC
        securecloud::files_config
        securecloud::common
        securecloud::compiler_flags
        OpenSSL::Crypto
        OpenSSL::SSL
)

if(WIN32)
    target_link_libraries(securecloud_files_storage PUBLIC ws2_32)
endif()

set(SECURECLOUD_FILES_SERVICE_SOURCES
        service/files_service_impl.cpp
        service/storage_engine.cpp
        service/file_lifecycle_service.cpp
        service/upload_session_manager.cpp
        service/chunk_storage_service.cpp
        service/object_assembly_engine.cpp
        service/file_finalization_service.cpp
        service/chunk_download_engine.cpp
        service/download_manager.cpp
        service/file_capability_manager.cpp
        service/files_audit_event_publisher.cpp
)

add_library(securecloud_files_service STATIC ${SECURECLOUD_FILES_SERVICE_SOURCES})

add_library(securecloud::files_service ALIAS securecloud_files_service)

target_include_directories(securecloud_files_service PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(securecloud_files_service PUBLIC
        securecloud::files_storage
        securecloud::files_db
        securecloud::files_config
        securecloud::common
        securecloud::compiler_flags
)

if(BUILD_TESTING)
    add_library(securecloud_files_service_test STATIC ${SECURECLOUD_FILES_SERVICE_SOURCES})
    add_library(securecloud::files_service_test ALIAS securecloud_files_service_test)

    target_include_directories(securecloud_files_service_test PUBLIC
            ${CMAKE_CURRENT_SOURCE_DIR}
            ${CMAKE_SOURCE_DIR}/src
    )

    target_link_libraries(securecloud_files_service_test PUBLIC
            securecloud::files_storage
            securecloud::files_db_test
            securecloud::files_config
            securecloud::common
            securecloud::compiler_flags
    )
endif()

# Thin Pimpl wrapper isolating `securecloud::audit_domain` from `src/files/` include paths
# so `src/auth/domain/audit_event.hpp` and `src/audit/domain/audit_event.hpp` never collide.
add_library(securecloud_files_audit_validator STATIC
        audit/files_audit_proto_validator.cpp
)

add_library(securecloud::files_audit_validator ALIAS securecloud_files_audit_validator)

target_include_directories(securecloud_files_audit_validator PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(securecloud_files_audit_validator
        PUBLIC
        securecloud_proto
        securecloud::compiler_flags
        PRIVATE
        securecloud::audit_domain
)

set(SECURECLOUD_FILES_AUDIT_SOURCES
        audit/grpc_audit_client.cpp
        audit/files_audit_mapper.cpp
        audit/files_outbox_relay.cpp
)

# `securecloud_files_audit` MUST NEVER link `securecloud::files_db` or `securecloud::auth`
# (which exports `src/auth/domain/audit_event.hpp` and `src/auth/domain/enums.hpp`).
add_library(securecloud_files_audit STATIC ${SECURECLOUD_FILES_AUDIT_SOURCES})

add_library(securecloud::files_audit ALIAS securecloud_files_audit)

target_include_directories(securecloud_files_audit PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/src
)

target_compile_definitions(securecloud_files_audit PUBLIC
        SECURECLOUD_FILES_USE_REAL_PQXX
)

target_link_libraries(securecloud_files_audit
        PUBLIC
        securecloud::files_config
        securecloud::common
        securecloud::compiler_flags
        securecloud_proto
        securecloud::json
        securecloud::libpqxx
        PRIVATE
        securecloud::files_audit_validator
)

add_library(securecloud_files_health STATIC
        health/files_health_evaluator.cpp
)

add_library(securecloud::files_health ALIAS securecloud_files_health)

target_include_directories(securecloud_files_health PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(securecloud_files_health PUBLIC
        securecloud::files_storage
        securecloud::files_db
        securecloud::files_config
        securecloud::common
        securecloud::compiler_flags
)

add_executable(securecloud-files
        main.cpp
)

target_link_libraries(securecloud-files PRIVATE
        securecloud::files_audit
        securecloud::files_health
        securecloud::files_service
        securecloud::files_storage
        securecloud::files_db
        securecloud::files_config
        securecloud::common
        securecloud::compiler_flags
)
