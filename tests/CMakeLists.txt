enable_testing()

if(TARGET GTest::gmock AND NOT TARGET GTest::gmock_main)
    # Fallback for MSYS2/MinGW where GTestConfig.cmake omits GTest::gmock_main
    find_library(GMOCK_LIB NAMES gmock gmockd)
    find_library(GMOCK_MAIN_LIB NAMES gmock_main gmock_maind)

    if(GMOCK_LIB AND GMOCK_MAIN_LIB)
        add_library(GTest::gmock_main UNKNOWN IMPORTED)
        set_target_properties(GTest::gmock_main PROPERTIES
                IMPORTED_LOCATION "${GMOCK_MAIN_LIB}"
                INTERFACE_LINK_LIBRARIES "GTest::gmock;${GMOCK_LIB}"
        )
    endif()
endif()

set(CMAKE_GTEST_DISCOVER_TESTS_DISCOVERY_MODE PRE_TEST)

if(WIN32)
    get_filename_component(_COMPILER_BIN_DIR "${CMAKE_CXX_COMPILER}" DIRECTORY)
    set(_TEST_ENV_MODS "PATH=path_list_prepend:${_COMPILER_BIN_DIR}")
    list(APPEND _TEST_ENV_MODS
        "PATH=path_list_prepend:${CMAKE_BINARY_DIR}/vcpkg_installed/x64-windows/debug/bin"
        "PATH=path_list_prepend:${CMAKE_BINARY_DIR}/vcpkg_installed/x64-windows/bin"
    )
    if(DEFINED VCPKG_TARGET_TRIPLET)
        list(APPEND _TEST_ENV_MODS
            "PATH=path_list_prepend:${CMAKE_BINARY_DIR}/vcpkg_installed/${VCPKG_TARGET_TRIPLET}/debug/bin"
            "PATH=path_list_prepend:${CMAKE_BINARY_DIR}/vcpkg_installed/${VCPKG_TARGET_TRIPLET}/bin"
        )
    endif()
    set(SECURECLOUD_TEST_PROPERTIES
        DISCOVERY_MODE PRE_TEST
        DISCOVERY_TIMEOUT 30
        PROPERTIES
            TIMEOUT 60
            ENVIRONMENT_MODIFICATION "${_TEST_ENV_MODS}")
else()
    set(SECURECLOUD_TEST_PROPERTIES
        DISCOVERY_MODE PRE_TEST
        DISCOVERY_TIMEOUT 30
        PROPERTIES TIMEOUT 60)
endif()

add_subdirectory(unit)
add_subdirectory(integration)


