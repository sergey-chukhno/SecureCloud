add_executable(securecloud-client
    main.cpp
)

target_link_libraries(securecloud-client PRIVATE
    securecloud::common
    securecloud::compiler_flags
)
