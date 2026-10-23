#include "files/domain/lifecycle_state_machine.hpp"

#include <gtest/gtest.h>
#include <set>

namespace securecloud::files {
namespace {

TEST(LifecycleStateMachineTest, ToStringConversions) {
    EXPECT_EQ(to_string(FileStatus::Created), "CREATED");
    EXPECT_EQ(to_string(FileStatus::Uploading), "UPLOADING");
    EXPECT_EQ(to_string(FileStatus::Finalizing), "FINALIZING");
    EXPECT_EQ(to_string(FileStatus::Available), "AVAILABLE");
    EXPECT_EQ(to_string(FileStatus::Expired), "EXPIRED");
    EXPECT_EQ(to_string(FileStatus::Deleted), "DELETED");
    EXPECT_EQ(to_string(FileStatus::Failed), "FAILED");
}

TEST(LifecycleStateMachineTest, FromStringConversions) {
    EXPECT_EQ(file_status_from_string("CREATED"), FileStatus::Created);
    EXPECT_EQ(file_status_from_string("created"), FileStatus::Created);
    EXPECT_EQ(file_status_from_string("UPLOADING"), FileStatus::Uploading);
    EXPECT_EQ(file_status_from_string("uploading"), FileStatus::Uploading);
    EXPECT_EQ(file_status_from_string("FINALIZING"), FileStatus::Finalizing);
    EXPECT_EQ(file_status_from_string("finalizing"), FileStatus::Finalizing);
    EXPECT_EQ(file_status_from_string("AVAILABLE"), FileStatus::Available);
    EXPECT_EQ(file_status_from_string("available"), FileStatus::Available);
    EXPECT_EQ(file_status_from_string("EXPIRED"), FileStatus::Expired);
    EXPECT_EQ(file_status_from_string("expired"), FileStatus::Expired);
    EXPECT_EQ(file_status_from_string("DELETED"), FileStatus::Deleted);
    EXPECT_EQ(file_status_from_string("deleted"), FileStatus::Deleted);
    EXPECT_EQ(file_status_from_string("FAILED"), FileStatus::Failed);
    EXPECT_EQ(file_status_from_string("failed"), FileStatus::Failed);

    EXPECT_EQ(file_status_from_string("UNKNOWN"), std::nullopt);
    EXPECT_EQ(file_status_from_string(""), std::nullopt);
}

TEST(LifecycleStateMachineTest, ToProtoConversions) {
    EXPECT_EQ(to_proto(FileStatus::Created), v1::FILE_LIFECYCLE_STATE_CREATED);
    EXPECT_EQ(to_proto(FileStatus::Uploading), v1::FILE_LIFECYCLE_STATE_UPLOADING);
    EXPECT_EQ(to_proto(FileStatus::Finalizing), v1::FILE_LIFECYCLE_STATE_FINALIZING);
    EXPECT_EQ(to_proto(FileStatus::Available), v1::FILE_LIFECYCLE_STATE_AVAILABLE);
    EXPECT_EQ(to_proto(FileStatus::Expired), v1::FILE_LIFECYCLE_STATE_EXPIRED);
    EXPECT_EQ(to_proto(FileStatus::Deleted), v1::FILE_LIFECYCLE_STATE_DELETED);
    EXPECT_EQ(to_proto(FileStatus::Failed), v1::FILE_LIFECYCLE_STATE_FAILED);
}

TEST(LifecycleStateMachineTest, FromProtoConversions) {
    EXPECT_EQ(from_proto(v1::FILE_LIFECYCLE_STATE_CREATED), FileStatus::Created);
    EXPECT_EQ(from_proto(v1::FILE_LIFECYCLE_STATE_UPLOADING), FileStatus::Uploading);
    EXPECT_EQ(from_proto(v1::FILE_LIFECYCLE_STATE_FINALIZING), FileStatus::Finalizing);
    EXPECT_EQ(from_proto(v1::FILE_LIFECYCLE_STATE_AVAILABLE), FileStatus::Available);
    EXPECT_EQ(from_proto(v1::FILE_LIFECYCLE_STATE_EXPIRED), FileStatus::Expired);
    EXPECT_EQ(from_proto(v1::FILE_LIFECYCLE_STATE_DELETED), FileStatus::Deleted);
    EXPECT_EQ(from_proto(v1::FILE_LIFECYCLE_STATE_FAILED), FileStatus::Failed);

    EXPECT_THROW(from_proto(v1::FILE_LIFECYCLE_STATE_UNSPECIFIED), std::invalid_argument);
}

TEST(LifecycleStateMachineTest, TerminalStates) {
    EXPECT_TRUE(is_terminal_state(FileStatus::Deleted));
    EXPECT_TRUE(is_terminal_state(FileStatus::Failed));

    EXPECT_FALSE(is_terminal_state(FileStatus::Created));
    EXPECT_FALSE(is_terminal_state(FileStatus::Uploading));
    EXPECT_FALSE(is_terminal_state(FileStatus::Finalizing));
    EXPECT_FALSE(is_terminal_state(FileStatus::Available));
    EXPECT_FALSE(is_terminal_state(FileStatus::Expired));
}

TEST(LifecycleStateMachineTest, ExhaustiveTransitionMatrixVerification) {
    const std::vector<FileStatus> all_statuses = {
        FileStatus::Created, FileStatus::Uploading, FileStatus::Finalizing,
        FileStatus::Available, FileStatus::Expired, FileStatus::Deleted, FileStatus::Failed
    };

    // Define all legally allowed transitions
    const std::set<std::pair<FileStatus, FileStatus>> legal_transitions = {
        // Created paths
        {FileStatus::Created, FileStatus::Uploading},
        {FileStatus::Created, FileStatus::Failed},
        {FileStatus::Created, FileStatus::Deleted},
        // Uploading paths
        {FileStatus::Uploading, FileStatus::Finalizing},
        {FileStatus::Uploading, FileStatus::Failed},
        {FileStatus::Uploading, FileStatus::Expired},
        {FileStatus::Uploading, FileStatus::Deleted},
        // Finalizing paths
        {FileStatus::Finalizing, FileStatus::Available},
        {FileStatus::Finalizing, FileStatus::Failed},
        // Available paths
        {FileStatus::Available, FileStatus::Expired},
        {FileStatus::Available, FileStatus::Deleted},
        // Expired paths
        {FileStatus::Expired, FileStatus::Deleted}
    };

    // Test all 49 transitions
    for (const auto& from : all_statuses) {
        for (const auto& to : all_statuses) {
            bool expected_valid = legal_transitions.contains({from, to});
            bool actual_valid = is_valid_state_transition(from, to);

            EXPECT_EQ(actual_valid, expected_valid)
                << "Transition from " << to_string(from) << " to " << to_string(to)
                << " expected " << (expected_valid ? "VALID" : "INVALID")
                << " but got " << (actual_valid ? "VALID" : "INVALID");

            if (expected_valid) {
                EXPECT_NO_THROW(assert_valid_state_transition(from, to));
            } else {
                try {
                    assert_valid_state_transition(from, to);
                    FAIL() << "Expected InvalidLifecycleTransitionException from "
                           << to_string(from) << " to " << to_string(to);
                } catch (const InvalidLifecycleTransitionException& ex) {
                    EXPECT_EQ(ex.from(), from);
                    EXPECT_EQ(ex.to(), to);
                    EXPECT_FALSE(std::string(ex.what()).empty());
                }
            }
        }
    }
}

} // namespace
} // namespace securecloud::files
