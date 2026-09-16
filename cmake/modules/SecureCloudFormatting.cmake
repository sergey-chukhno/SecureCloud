include_guard(GLOBAL)

# SecureCloud Formatting & Static Analysis Integration Module
# Provides custom targets for formatting and static analysis tooling.

message(STATUS "[SecureCloud] Initializing formatting and static analysis tooling...")

# Discover clang-format executable
find_program(CLANG_FORMAT_BIN NAMES clang-format clang-format-20 clang-format-19 clang-format-18 clang-format-17 HINTS /opt/homebrew/bin /opt/homebrew/opt/llvm/bin /usr/local/opt/llvm/bin)

# Authoritative tooling file selection mechanism
file(GLOB_RECURSE RAW_TOOLING_FILES CONFIGURE_DEPENDS
    "${CMAKE_SOURCE_DIR}/src/*.cpp"
    "${CMAKE_SOURCE_DIR}/src/*.hpp"
    "${CMAKE_SOURCE_DIR}/src/*.h"
    "${CMAKE_SOURCE_DIR}/tests/*.cpp"
    "${CMAKE_SOURCE_DIR}/tests/*.hpp"
    "${CMAKE_SOURCE_DIR}/tests/*.h"
)

# Filter out build artifacts, dependencies, and generated code
set(PROJECT_TOOLING_FILES "")
foreach(FILE IN LISTS RAW_TOOLING_FILES)
    if(NOT FILE MATCHES "/build/" AND
       NOT FILE MATCHES "/vcpkg_installed/" AND
       NOT FILE MATCHES "\\.pb\\.cc$" AND
       NOT FILE MATCHES "\\.pb\\.h$")
        list(APPEND PROJECT_TOOLING_FILES "${FILE}")
    endif()
endforeach()

if(CLANG_FORMAT_BIN)
    message(STATUS "[SecureCloud] Found clang-format: ${CLANG_FORMAT_BIN}")
    
    # Read-only formatting check target (returns non-zero exit code on formatting error)
    add_custom_target(check-format
        COMMAND "${CLANG_FORMAT_BIN}" --dry-run --Werror ${PROJECT_TOOLING_FILES}
        COMMENT "Checking project C++ formatting (read-only)..."
        VERBATIM
    )

    # In-place formatting convenience target
    add_custom_target(format
        COMMAND "${CLANG_FORMAT_BIN}" -i ${PROJECT_TOOLING_FILES}
        COMMENT "Applying clang-format to project C++ files in-place..."
        VERBATIM
    )
else()
    message(STATUS "[SecureCloud] clang-format not found; check-format and format targets will be unavailable")
endif()

# Optional static analysis via clang-tidy
option(ENABLE_CLANG_TIDY "Enable clang-tidy static analysis during build" OFF)

if(ENABLE_CLANG_TIDY)
    find_program(CLANG_TIDY_BIN NAMES clang-tidy clang-tidy-20 clang-tidy-19 clang-tidy-18 clang-tidy-17 HINTS /opt/homebrew/opt/llvm/bin /usr/local/opt/llvm/bin)
    if(CLANG_TIDY_BIN)
        message(STATUS "[SecureCloud] Enabling clang-tidy static analysis: ${CLANG_TIDY_BIN}")
        set(CMAKE_CXX_CLANG_TIDY "${CLANG_TIDY_BIN}")
    else()
        message(FATAL_ERROR "[SecureCloud] ENABLE_CLANG_TIDY is ON but clang-tidy executable was not found")
    endif()
endif()
