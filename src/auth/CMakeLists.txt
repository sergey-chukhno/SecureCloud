add_executable(securecloud-auth
    main.cpp
)

target_link_libraries(securecloud-auth PRIVATE
    securecloud::common
    securecloud::compiler_flags
)
