if(Qt6_FOUND)
    # 1. Domain Layer (Pure C++20, zero Qt GUI/Network dependencies)
    add_library(securecloud_client_domain STATIC
        domain/session_state.cpp
        domain/user_id.cpp
        domain/device_id.cpp
        domain/conversation_id.cpp
        domain/message_id.cpp
        domain/delivery_state.cpp
        domain/crypto_identity.cpp
        domain/device.cpp
        domain/user.cpp
        domain/contact.cpp
        domain/conversation.cpp
        domain/message.cpp
    )
    add_library(securecloud::client_domain ALIAS securecloud_client_domain)
    target_include_directories(securecloud_client_domain PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
    )
    target_link_libraries(securecloud_client_domain PUBLIC
        securecloud::compiler_flags
    )

    # 2. Infrastructure Layer (Adapters, Networking via Gateway, Persistence)
    add_library(securecloud_client_infra STATIC
        infrastructure/gateway_adapter_stub.cpp
        infrastructure/client_logger.cpp
    )
    add_library(securecloud::client_infra ALIAS securecloud_client_infra)
    target_include_directories(securecloud_client_infra PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
    )
    target_link_libraries(securecloud_client_infra PUBLIC
        securecloud_client_domain
        securecloud::common
        securecloud::compiler_flags
        Qt6::Core
        Qt6::Network
    )

    # 3. Application Layer (Use Cases, Lifecycle, Context)
    add_library(securecloud_client_app STATIC
        application/client_app_service.cpp
        application/client_config.cpp
        application/client_error.cpp
    )
    add_library(securecloud::client_app ALIAS securecloud_client_app)
    set_target_properties(securecloud_client_app PROPERTIES
        AUTOMOC ON
    )
    target_include_directories(securecloud_client_app PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
    )
    target_link_libraries(securecloud_client_app PUBLIC
        securecloud_client_domain
        securecloud_client_infra
        securecloud::common
        securecloud::compiler_flags
        Qt6::Core
    )

    # 4. UI Layer (ViewModels, Presentation, QML Bindings)
    add_library(securecloud_client_ui STATIC
        ui/ui_controller.cpp
    )
    add_library(securecloud::client_ui ALIAS securecloud_client_ui)
    set_target_properties(securecloud_client_ui PROPERTIES
        AUTOMOC ON
    )
    target_include_directories(securecloud_client_ui PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}
    )
    target_link_libraries(securecloud_client_ui PUBLIC
        securecloud_client_app
        securecloud::compiler_flags
        Qt6::Core
        Qt6::Gui
        Qt6::Qml
        Qt6::Quick
        Qt6::QuickControls2
    )

    # 5. Desktop Client Executable Target
    add_executable(securecloud-client
        main.cpp
    )
    set_target_properties(securecloud-client PROPERTIES
        AUTOMOC ON
    )
    target_include_directories(securecloud-client PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
    )
    target_link_libraries(securecloud-client PRIVATE
        securecloud_client_ui
        securecloud_client_app
        securecloud_client_infra
        securecloud_client_domain
        securecloud::common
        securecloud::compiler_flags
        Qt6::Core
        Qt6::Gui
        Qt6::Quick
    )
else()
    message(WARNING "[SecureCloud Client] Qt 6 is not available; desktop client targets are omitted.")
endif()
