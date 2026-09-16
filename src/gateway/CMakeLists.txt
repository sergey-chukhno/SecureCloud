add_executable(securecloud-gateway
    main.cpp
)

target_link_libraries(securecloud-gateway PRIVATE
    securecloud::common
    securecloud::compiler_flags
)
