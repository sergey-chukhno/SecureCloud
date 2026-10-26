#include "files/domain/lifecycle_state_machine.hpp"

#include <algorithm>
#include <sstream>

namespace securecloud::files {

namespace {

std::string format_exception_message(FileStatus from, FileStatus to, std::string_view detail) {
    std::ostringstream oss;
    oss << "Invalid file lifecycle state transition from " << to_string(from) << " to " << to_string(to);
    if (!detail.empty()) {
        oss << ": " << detail;
    }
    return oss.str();
}

} // namespace

InvalidLifecycleTransitionException::InvalidLifecycleTransitionException(FileStatus from, FileStatus to,
                                                                         std::string_view detail)
    : std::runtime_error(format_exception_message(from, to, detail)), from_(from), to_(to) {}

std::string_view to_string(FileStatus status) noexcept {
    switch (status) {
    case FileStatus::Created:
        return "CREATED";
    case FileStatus::Uploading:
        return "UPLOADING";
    case FileStatus::Finalizing:
        return "FINALIZING";
    case FileStatus::Available:
        return "AVAILABLE";
    case FileStatus::Expired:
        return "EXPIRED";
    case FileStatus::Deleted:
        return "DELETED";
    case FileStatus::Failed:
        return "FAILED";
    }
    return "UNKNOWN";
}

std::optional<FileStatus> file_status_from_string(std::string_view str) noexcept {
    if (str == "CREATED" || str == "created") {
        return FileStatus::Created;
    }
    if (str == "UPLOADING" || str == "uploading") {
        return FileStatus::Uploading;
    }
    if (str == "FINALIZING" || str == "finalizing") {
        return FileStatus::Finalizing;
    }
    if (str == "AVAILABLE" || str == "available") {
        return FileStatus::Available;
    }
    if (str == "EXPIRED" || str == "expired") {
        return FileStatus::Expired;
    }
    if (str == "DELETED" || str == "deleted") {
        return FileStatus::Deleted;
    }
    if (str == "FAILED" || str == "failed") {
        return FileStatus::Failed;
    }
    return std::nullopt;
}

v1::FileLifecycleState to_proto(FileStatus status) noexcept {
    switch (status) {
    case FileStatus::Created:
        return v1::FILE_LIFECYCLE_STATE_CREATED;
    case FileStatus::Uploading:
        return v1::FILE_LIFECYCLE_STATE_UPLOADING;
    case FileStatus::Finalizing:
        return v1::FILE_LIFECYCLE_STATE_FINALIZING;
    case FileStatus::Available:
        return v1::FILE_LIFECYCLE_STATE_AVAILABLE;
    case FileStatus::Expired:
        return v1::FILE_LIFECYCLE_STATE_EXPIRED;
    case FileStatus::Deleted:
        return v1::FILE_LIFECYCLE_STATE_DELETED;
    case FileStatus::Failed:
        return v1::FILE_LIFECYCLE_STATE_FAILED;
    }
    return v1::FILE_LIFECYCLE_STATE_UNSPECIFIED;
}

FileStatus from_proto(v1::FileLifecycleState proto_state) {
    switch (proto_state) {
    case v1::FILE_LIFECYCLE_STATE_CREATED:
        return FileStatus::Created;
    case v1::FILE_LIFECYCLE_STATE_UPLOADING:
        return FileStatus::Uploading;
    case v1::FILE_LIFECYCLE_STATE_FINALIZING:
        return FileStatus::Finalizing;
    case v1::FILE_LIFECYCLE_STATE_AVAILABLE:
        return FileStatus::Available;
    case v1::FILE_LIFECYCLE_STATE_EXPIRED:
        return FileStatus::Expired;
    case v1::FILE_LIFECYCLE_STATE_DELETED:
        return FileStatus::Deleted;
    case v1::FILE_LIFECYCLE_STATE_FAILED:
        return FileStatus::Failed;
    case v1::FILE_LIFECYCLE_STATE_UNSPECIFIED:
    default:
        throw std::invalid_argument("Unspecified or invalid protobuf FileLifecycleState");
    }
}

bool is_valid_state_transition(FileStatus from, FileStatus to) noexcept {
    switch (from) {
    case FileStatus::Created:
        return to == FileStatus::Uploading || to == FileStatus::Failed || to == FileStatus::Deleted;
    case FileStatus::Uploading:
        return to == FileStatus::Finalizing || to == FileStatus::Failed || to == FileStatus::Expired ||
               to == FileStatus::Deleted;
    case FileStatus::Finalizing:
        return to == FileStatus::Available || to == FileStatus::Failed;
    case FileStatus::Available:
        return to == FileStatus::Expired || to == FileStatus::Deleted;
    case FileStatus::Expired:
        return to == FileStatus::Deleted;
    case FileStatus::Deleted:
    case FileStatus::Failed:
        return false;
    }
    return false;
}

bool is_terminal_state(FileStatus status) noexcept {
    return status == FileStatus::Deleted || status == FileStatus::Failed;
}

void assert_valid_state_transition(FileStatus from, FileStatus to) {
    if (!is_valid_state_transition(from, to)) {
        throw InvalidLifecycleTransitionException(from, to);
    }
}

} // namespace securecloud::files
