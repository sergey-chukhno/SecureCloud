add_library(securecloud_files_config STATIC
    files_config.cpp
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

add_library(securecloud_files_db STATIC
    db/files_connection_pool.cpp
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
)

find_package(OpenSSL REQUIRED)

add_library(securecloud_files_storage STATIC
    storage/s3_client.cpp
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

add_executable(securecloud-files
    main.cpp
)

target_link_libraries(securecloud-files PRIVATE
    securecloud::files_service
    securecloud::files_storage
    securecloud::files_db
    securecloud::files_config
    securecloud::common
    securecloud::compiler_flags
)


