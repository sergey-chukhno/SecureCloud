include_guard(GLOBAL)

# Modern target-based compiler flags and security hardening interface library
add_library(securecloud_compiler_flags INTERFACE)
add_library(securecloud::compiler_flags ALIAS securecloud_compiler_flags)

# Enforce strict C++20 standard target feature requirement
target_compile_features(securecloud_compiler_flags INTERFACE cxx_std_20)

# Position Independent Code (PIE) for security hardening
set_target_properties(securecloud_compiler_flags PROPERTIES
    INTERFACE_POSITION_INDEPENDENT_CODE ON
)

if(MSVC)
    target_compile_options(securecloud_compiler_flags INTERFACE
        /W4
        /WX
        /permissive-
        /volatile:iso
        /EHsc
    )
    target_compile_definitions(securecloud_compiler_flags INTERFACE
        _CRT_SECURE_NO_WARNINGS
        UNICODE
        _UNICODE
        WIN32_LEAN_AND_MEAN
        NOMINMAX
    )
else()
    # Clang / AppleClang / GCC compile options
    target_compile_options(securecloud_compiler_flags INTERFACE
        -Wall
        -Wextra
        -Werror
        -Wpedantic
        -Wshadow
        -Wnon-virtual-dtor
        -Wconversion
        -Wunused
        -Woverloaded-virtual
        -fstack-protector-strong
        -fvisibility=hidden
    )

    # Hardening preprocessor definitions
    target_compile_definitions(securecloud_compiler_flags INTERFACE
        _FORTIFY_SOURCE=3
    )
endif()

if(WIN32 AND NOT MSVC)
    target_compile_definitions(securecloud_compiler_flags INTERFACE
        WIN32_LEAN_AND_MEAN
        NOMINMAX
    )
endif()
