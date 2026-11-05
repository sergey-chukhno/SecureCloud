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
        infrastructure/adapters/default_gateway_client.cpp
        infrastructure/adapters/memory_local_store.cpp
        infrastructure/adapters/memory_secure_storage.cpp
        infrastructure/adapters/stub_crypto_provider.cpp
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
        application/client_bootstrap.cpp
        application/client_application.cpp
        application/managers/auth_manager.cpp
        application/managers/messaging_manager.cpp
        application/managers/contact_manager.cpp
        application/managers/device_manager.cpp
        application/managers/file_manager.cpp
        application/managers/emergency_manager.cpp
        application/managers/sync_manager.cpp
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
        ui/navigation_controller.cpp
        ui/app_view_model.cpp
        ui/workspace_view_model.cpp
        ui/ui_theme.cpp
        ui/window_state_manager.cpp
        ui/qml.qrc
    )
    add_library(securecloud::client_ui ALIAS securecloud_client_ui)
    set_target_properties(securecloud_client_ui PROPERTIES
        AUTOMOC ON
        AUTORCC ON
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
        ui/qml.qrc
    )
    set_target_properties(securecloud-client PROPERTIES
        AUTOMOC ON
        AUTORCC ON
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
        Qt6::Qml
        Qt6::Quick
        Qt6::QuickControls2
    )
else()
    message(WARNING "[SecureCloud Client] Qt 6 is not available; desktop client targets are omitted.")
endif()
