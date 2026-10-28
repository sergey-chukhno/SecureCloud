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

add_library(securecloud_files_db STATIC
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

add_library(securecloud::files_db ALIAS securecloud_files_db)

target_include_directories(securecloud_files_db PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(securecloud_files_db PUBLIC
    securecloud::files_config
    securecloud::common
    securecloud::compiler_flags
    securecloud_proto
    OpenSSL::Crypto
    securecloud::json
    securecloud::auth
)

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

add_library(securecloud_files_service STATIC
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
)

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

add_library(securecloud_files_audit STATIC
    audit/grpc_audit_client.cpp
    audit/files_audit_mapper.cpp
)

add_library(securecloud::files_audit ALIAS securecloud_files_audit)

target_include_directories(securecloud_files_audit PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_SOURCE_DIR}/src
)

target_link_libraries(securecloud_files_audit PUBLIC
    securecloud::files_db
    securecloud::files_config
    securecloud::common
    securecloud::compiler_flags
    securecloud_proto
    securecloud::json
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
    securecloud::files_health
    securecloud::files_service
    securecloud::files_storage
    securecloud::files_db
    securecloud::files_config
    securecloud::common
    securecloud::compiler_flags
)


