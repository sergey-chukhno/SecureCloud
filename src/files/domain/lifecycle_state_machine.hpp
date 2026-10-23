#pragma once

#include "files/domain/file_entity.hpp"
#include "securecloud/files/v1/files.pb.h"

#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>

namespace securecloud::files {

/// Strongly typed domain exception thrown when an invalid file lifecycle transition is attempted.
class InvalidLifecycleTransitionException : public std::runtime_error {
  public:
    InvalidLifecycleTransitionException(FileStatus from, FileStatus to, std::string_view detail = "");

    [[nodiscard]] FileStatus from() const noexcept { return from_; }
    [[nodiscard]] FileStatus to() const noexcept { return to_; }

  private:
    FileStatus from_;
    FileStatus to_;
};

/// String conversion for FileStatus
[[nodiscard]] std::string_view to_string(FileStatus status) noexcept;

/// Parses a string into FileStatus. Returns std::nullopt if string is unrecognized.
[[nodiscard]] std::optional<FileStatus> file_status_from_string(std::string_view str) noexcept;

/// Converts domain FileStatus to Protobuf FileLifecycleState.
[[nodiscard]] v1::FileLifecycleState to_proto(FileStatus status) noexcept;

/// Converts Protobuf FileLifecycleState to domain FileStatus.
/// Throws std::invalid_argument if proto_state is unspecified or invalid.
[[nodiscard]] FileStatus from_proto(v1::FileLifecycleState proto_state);

/// Evaluates whether a transition from `from` to `to` is legally permitted.
[[nodiscard]] bool is_valid_state_transition(FileStatus from, FileStatus to) noexcept;

/// Returns true if status is a terminal state (Failed or Deleted).
[[nodiscard]] bool is_terminal_state(FileStatus status) noexcept;

/// Asserts that a state transition is legal. Throws InvalidLifecycleTransitionException if illegal.
void assert_valid_state_transition(FileStatus from, FileStatus to);

} // namespace securecloud::files
