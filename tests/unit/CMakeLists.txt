add_executable(securecloud_unit_smoke_test
    smoke_test.cpp
)

target_link_libraries(securecloud_unit_smoke_test PRIVATE
    securecloud::common
    securecloud::compiler_flags
)

add_test(
    NAME unit_smoke_test
    COMMAND securecloud_unit_smoke_test
)
