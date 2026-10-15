add_library(securecloud_messaging_config STATIC
    messaging_config.cpp
    concurrency/bounded_worker_pool.cpp
    service/messaging_service_impl.cpp
    service/messaging_caller_context.cpp
    service/delivery_lifecycle.cpp
    service/messaging_error_mapper.cpp
    domain/conversation_lifecycle.cpp
    domain/message_bucket.cpp
    repository/in_memory_conversation_repository.cpp
    repository/in_memory_membership_repository.cpp
    repository/scylla_conversation_repository.cpp
    repository/scylla_membership_repository.cpp
    repository/scylla_message_repository.cpp
    repository/scylla_outbox_repository.cpp
    service/conversation_authorization_service.cpp
    service/conversation_service.cpp
    db/migration_runner.cpp
    db/scylla_types.cpp
    db/scylla_error_mapper.cpp
    db/mock_scylla_session.cpp
    db/scylla_session.cpp
    db/scylla_session_pool.cpp
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
    OpenSSL::Crypto
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
