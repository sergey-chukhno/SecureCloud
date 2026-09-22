enable_testing()

if(WIN32)
    get_filename_component(_COMPILER_BIN_DIR "${CMAKE_CXX_COMPILER}" DIRECTORY)
    set(SECURECLOUD_TEST_PROPERTIES PROPERTIES
        TIMEOUT 60
        ENVIRONMENT_MODIFICATION "PATH=path_list_prepend:${_COMPILER_BIN_DIR}")
else()
    set(SECURECLOUD_TEST_PROPERTIES PROPERTIES TIMEOUT 60)
endif()

add_subdirectory(unit)
add_subdirectory(integration)


