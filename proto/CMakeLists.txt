# Register Protobuf and gRPC contracts for SecureCloud
securecloud_add_proto_library(securecloud_proto
    PROTO_FILES
        securecloud/common/v1/health.proto
        securecloud/auth/v1/auth.proto
)
