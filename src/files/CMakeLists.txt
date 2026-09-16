add_executable(securecloud-files
    main.cpp
)

target_link_libraries(securecloud-files PRIVATE
    securecloud::common
    securecloud::compiler_flags
)
