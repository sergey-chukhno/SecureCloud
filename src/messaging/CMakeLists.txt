add_executable(securecloud-messaging
    main.cpp
)

target_link_libraries(securecloud-messaging PRIVATE
    securecloud::common
    securecloud::compiler_flags
)
