add_library(securecloud_audit_domain STATIC
        domain/enums.cpp
        domain/event_id.cpp
        domain/validation_result.cpp
        domain/audit_event_validator.cpp
        domain/sensitive_data_guard.cpp
        domain/producer_identity_validator.cpp
        domain/audit_event_mapper.cpp
)

add_library(securecloud::audit_domain ALIAS securecloud_audit_domain)

target_include_directories(securecloud_audit_domain PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(securecloud_audit_domain PUBLIC
        securecloud::common
        securecloud_proto
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

add_library(securecloud_audit_repository STATIC
        repository/schema_initializer.cpp
        repository/clickhouse_client.cpp
        repository/clickhouse_event_serializer.cpp
        repository/clickhouse_audit_event_repository.cpp
)

add_library(securecloud::audit_repository ALIAS securecloud_audit_repository)

target_include_directories(securecloud_audit_repository PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(securecloud_audit_repository PUBLIC
        securecloud_audit_config
        securecloud::common
        securecloud::httplib
        securecloud::compiler_flags
)

add_library(securecloud_audit_service STATIC
        ingestion/bounded_ingestion_queue.cpp
        ingestion/validation_worker_pool.cpp
        ingestion/batch_aggregator.cpp
        service/audit_proto_mapper.cpp
        service/audit_ingestion_service.cpp
        service/audit_service_impl.cpp
        security/grpc_producer_identity_validator.cpp
)

add_library(securecloud::audit_service ALIAS securecloud_audit_service)

target_include_directories(securecloud_audit_service PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
)

target_link_libraries(securecloud_audit_service PUBLIC
        securecloud_audit_domain
        securecloud_proto
        securecloud::common
        securecloud::compiler_flags
        gRPC::grpc++
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
        securecloud_audit_repository
        securecloud_audit_service
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