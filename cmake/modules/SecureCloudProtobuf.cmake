include_guard(GLOBAL)

# SecureCloud Protobuf & gRPC Code Generation Module
# Provides reusable CMake functions for generating C++ Protobuf and gRPC targets out-of-source.

message(STATUS "[SecureCloud] Initializing Protobuf and gRPC code generation pipeline...")

function(securecloud_add_proto_library TARGET_NAME)
    cmake_parse_arguments(ARG "" "" "PROTO_FILES" ${ARGN})

    if(NOT ARG_PROTO_FILES)
        message(FATAL_ERROR "[SecureCloud] securecloud_add_proto_library called on '${TARGET_NAME}' without PROTO_FILES")
    endif()

    if(NOT PROTOC_BIN)
        message(FATAL_ERROR "[SecureCloud] protoc compiler binary is unavailable (PROTOC_BIN is not set)")
    endif()

    if(NOT GRPC_CPP_PLUGIN_BIN)
        message(FATAL_ERROR "[SecureCloud] grpc_cpp_plugin binary is unavailable (GRPC_CPP_PLUGIN_BIN is not set)")
    endif()

    set(GENERATED_PROTO_DIR "${CMAKE_BINARY_DIR}/generated/proto")
    file(RELATIVE_PATH REL_GEN_DIR "${CMAKE_SOURCE_DIR}" "${GENERATED_PROTO_DIR}")
    set(ALL_GENERATED_SOURCES "")
    set(ALL_GENERATED_HEADERS "")

    foreach(PROTO_FILE IN LISTS ARG_PROTO_FILES)
        # Resolve relative vs absolute proto path
        if(IS_ABSOLUTE "${PROTO_FILE}")
            set(PROTO_FILE_ABS "${PROTO_FILE}")
            file(RELATIVE_PATH PROTO_REL "${CMAKE_SOURCE_DIR}/proto" "${PROTO_FILE_ABS}")
        else()
            set(PROTO_FILE_ABS "${CMAKE_SOURCE_DIR}/proto/${PROTO_FILE}")
            set(PROTO_REL "${PROTO_FILE}")
        endif()

        if(NOT EXISTS "${PROTO_FILE_ABS}")
            message(FATAL_ERROR "[SecureCloud] Proto file does not exist: ${PROTO_FILE_ABS}")
        endif()

        # Compute relative directory and stem preserving nested hierarchy
        get_filename_component(PROTO_DIR "${PROTO_REL}" DIRECTORY)
        get_filename_component(PROTO_NAME "${PROTO_REL}" NAME_WE)

        set(OUT_DIR "${GENERATED_PROTO_DIR}/${PROTO_DIR}")
        file(MAKE_DIRECTORY "${OUT_DIR}")

        set(GEN_PB_H "${OUT_DIR}/${PROTO_NAME}.pb.h")
        set(GEN_PB_CC "${OUT_DIR}/${PROTO_NAME}.pb.cc")
        set(GEN_GRPC_H "${OUT_DIR}/${PROTO_NAME}.grpc.pb.h")
        set(GEN_GRPC_CC "${OUT_DIR}/${PROTO_NAME}.grpc.pb.cc")

        # Execute protoc relative to CMAKE_SOURCE_DIR to avoid path colon-splitting issues
        add_custom_command(
            OUTPUT "${GEN_PB_H}" "${GEN_PB_CC}" "${GEN_GRPC_H}" "${GEN_GRPC_CC}"
            COMMAND "${PROTOC_BIN}"
                "--proto_path=proto"
                "--cpp_out=${REL_GEN_DIR}"
                "--grpc_out=${REL_GEN_DIR}"
                "--plugin=protoc-gen-grpc=${GRPC_CPP_PLUGIN_BIN}"
                "proto/${PROTO_REL}"
            WORKING_DIRECTORY "${CMAKE_SOURCE_DIR}"
            DEPENDS "${PROTO_FILE_ABS}"
            COMMENT "Generating Protobuf & gRPC C++ sources for ${PROTO_REL}"
            VERBATIM
        )

        list(APPEND ALL_GENERATED_SOURCES "${GEN_PB_CC}" "${GEN_GRPC_CC}")
        list(APPEND ALL_GENERATED_HEADERS "${GEN_PB_H}" "${GEN_GRPC_H}")
    endforeach()

    # Define static target wrapping all generated source and header files
    add_library(${TARGET_NAME} STATIC ${ALL_GENERATED_SOURCES} ${ALL_GENERATED_HEADERS})

    target_include_directories(${TARGET_NAME} PUBLIC
        $<BUILD_INTERFACE:${GENERATED_PROTO_DIR}>
    )

    target_link_libraries(${TARGET_NAME} PUBLIC
        Protobuf::libprotobuf
        gRPC::grpc++
    )

    # Exclude generated C++ code from clang-tidy static analysis rules (SC-004 policy)
    set_target_properties(${TARGET_NAME} PROPERTIES
        CXX_STANDARD 20
        CXX_STANDARD_REQUIRED ON
        CXX_CLANG_TIDY ""
    )
endfunction()
