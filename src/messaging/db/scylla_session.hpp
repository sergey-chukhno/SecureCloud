#pragma once

#include "messaging/db/scylla_session_interface.hpp"
#include "messaging/messaging_config.hpp"

#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace securecloud::messaging::db {

/// Production implementation of IScyllaSession speaking Native CQL Binary Protocol v4.
class ScyllaSession : public IScyllaSession {
  public:
    explicit ScyllaSession(ScyllaConfig config);
    ~ScyllaSession() override;

    ScyllaQueryResult execute(std::string_view cql, ConsistencyLevel cl = ConsistencyLevel::LocalQuorum) override;

    PreparedStatementId prepare(std::string_view query_id, std::string_view cql) override;

    ScyllaQueryResult execute_prepared(const PreparedStatementId& id, const ScyllaParams& params,
                                       ConsistencyLevel cl = ConsistencyLevel::LocalQuorum) override;

    void execute_batch(const std::vector<BoundStatement>& batch, BatchType type = BatchType::Logged) override;

    bool ping() override;
    void close() override;
    [[nodiscard]] bool is_closed() const noexcept override;

    [[nodiscard]] const ScyllaConfig& config() const noexcept { return config_; }

  private:
    struct WireColumnSpec {
        std::string name;
        uint16_t type_id{0};
        uint16_t elem_type_id{0};
    };

    struct PreparedStatementEntry {
        std::string cql;
        std::vector<uint8_t> scylla_id;
        std::vector<WireColumnSpec> param_specs;
        std::vector<WireColumnSpec> result_specs;
        bool prepared_on_wire{false};
    };

    struct CqlFrame {
        uint8_t opcode{0};
        std::vector<uint8_t> body;
    };

    void ensure_connected_locked();
    void disconnect_socket_locked() noexcept;
    void send_all_locked(const uint8_t* data, std::size_t len);
    void recv_all_locked(uint8_t* data, std::size_t len);
    CqlFrame send_frame_and_recv_locked(uint8_t opcode, const std::vector<uint8_t>& body);

    PreparedStatementEntry& ensure_prepared_locked(const std::string& query_id, bool force_reprepare = false);

    ScyllaQueryResult execute_query_once_locked(std::string_view cql, ConsistencyLevel cl,
                                                const std::vector<uint8_t>* paging_state,
                                                std::vector<uint8_t>& out_next_paging_state);

    ScyllaQueryResult execute_prepared_once_locked(PreparedStatementEntry& entry, const ScyllaParams& params,
                                                   ConsistencyLevel cl, const std::vector<uint8_t>* paging_state,
                                                   std::vector<uint8_t>& out_next_paging_state, bool& out_unprepared);

    ScyllaQueryResult parse_result_frame_locked(const std::vector<uint8_t>& body,
                                                const std::vector<WireColumnSpec>* fallback_result_specs,
                                                std::vector<uint8_t>* out_next_paging_state);

    ScyllaConfig config_;
    std::atomic<bool> closed_{false};
    mutable std::mutex mutex_;
    int socket_fd_{-1};
    int16_t next_stream_id_{1};
    std::unordered_map<std::string, PreparedStatementEntry> prepared_cache_;
};

} // namespace securecloud::messaging::db
