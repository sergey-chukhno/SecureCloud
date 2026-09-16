add_executable(securecloud-audit
    main.cpp
)

target_link_libraries(securecloud-audit PRIVATE
    securecloud::common
    securecloud::compiler_flags
)
