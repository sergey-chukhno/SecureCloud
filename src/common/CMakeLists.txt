add_library(securecloud_common STATIC
    src/version.cpp
)

add_library(securecloud::common ALIAS securecloud_common)

target_include_directories(securecloud_common PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

target_link_libraries(securecloud_common PUBLIC
    securecloud::compiler_flags
    securecloud_proto
)
