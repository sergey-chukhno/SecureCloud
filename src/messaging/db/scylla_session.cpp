#include "messaging/db/scylla_session.hpp"

#include "messaging/db/scylla_error_mapper.hpp"

#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sstream>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

namespace securecloud::messaging::db {

namespace {

constexpr uint8_t k_cql_version_request = 0x04;
constexpr uint8_t k_cql_version_response = 0x84;

constexpr uint8_t k_op_error = 0x00;
constexpr uint8_t k_op_startup = 0x01;
constexpr uint8_t k_op_ready = 0x02;
constexpr uint8_t k_op_authenticate = 0x03;
constexpr uint8_t k_op_options = 0x05;
constexpr uint8_t k_op_supported = 0x06;
constexpr uint8_t k_op_query = 0x07;
constexpr uint8_t k_op_result = 0x08;
constexpr uint8_t k_op_prepare = 0x09;
constexpr uint8_t k_op_execute = 0x0A;
constexpr uint8_t k_op_batch = 0x0D;
constexpr uint8_t k_op_auth_response = 0x0F;
constexpr uint8_t k_op_auth_success = 0x10;

constexpr int32_t k_result_void = 0x0001;
constexpr int32_t k_result_rows = 0x0002;
constexpr int32_t k_result_set_keyspace = 0x0003;
constexpr int32_t k_result_prepared = 0x0004;
constexpr int32_t k_result_schema_change = 0x0005;

constexpr int32_t k_meta_flag_global_tables_spec = 0x0001;
constexpr int32_t k_meta_flag_has_more_pages = 0x0002;
constexpr int32_t k_meta_flag_no_metadata = 0x0004;

constexpr uint8_t k_query_flag_values = 0x01;
constexpr uint8_t k_query_flag_with_paging_state = 0x08;

constexpr uint16_t k_type_custom = 0x0000;
constexpr uint16_t k_type_ascii = 0x0001;
constexpr uint16_t k_type_bigint = 0x0002;
constexpr uint16_t k_type_blob = 0x0003;
constexpr uint16_t k_type_boolean = 0x0004;
constexpr uint16_t k_type_counter = 0x0005;
constexpr uint16_t k_type_int = 0x0009;
constexpr uint16_t k_type_timestamp = 0x000B;
constexpr uint16_t k_type_uuid = 0x000C;
constexpr uint16_t k_type_varchar = 0x000D;
constexpr uint16_t k_type_timeuuid = 0x000F;
constexpr uint16_t k_type_list = 0x0020;
constexpr uint16_t k_type_map = 0x0021;
constexpr uint16_t k_type_set = 0x0022;
constexpr uint16_t k_type_udt = 0x0030;
constexpr uint16_t k_type_tuple = 0x0031;

constexpr uint32_t k_max_cql_frame_bytes = 64U * 1024U * 1024U;

void write_u8(std::vector<uint8_t>& out, uint8_t v) {
    out.push_back(v);
}

void write_u16(std::vector<uint8_t>& out, uint16_t v) {
    out.push_back(static_cast<uint8_t>((v >> 8) & 0xFFU));
    out.push_back(static_cast<uint8_t>(v & 0xFFU));
}

void write_i32(std::vector<uint8_t>& out, int32_t v) {
    const uint32_t u = static_cast<uint32_t>(v);
    out.push_back(static_cast<uint8_t>((u >> 24) & 0xFFU));
    out.push_back(static_cast<uint8_t>((u >> 16) & 0xFFU));
    out.push_back(static_cast<uint8_t>((u >> 8) & 0xFFU));
    out.push_back(static_cast<uint8_t>(u & 0xFFU));
}

void write_i64(std::vector<uint8_t>& out, int64_t v) {
    const uint64_t u = static_cast<uint64_t>(v);
    for (int shift = 56; shift >= 0; shift -= 8) {
        out.push_back(static_cast<uint8_t>((u >> shift) & 0xFFU));
    }
}

void write_string(std::vector<uint8_t>& out, std::string_view s) {
    write_u16(out, static_cast<uint16_t>(s.size()));
    out.insert(out.end(), s.begin(), s.end());
}

void write_long_string(std::vector<uint8_t>& out, std::string_view s) {
    write_i32(out, static_cast<int32_t>(s.size()));
    out.insert(out.end(), s.begin(), s.end());
}

void write_short_bytes(std::vector<uint8_t>& out, const std::vector<uint8_t>& b) {
    write_u16(out, static_cast<uint16_t>(b.size()));
    out.insert(out.end(), b.begin(), b.end());
}

void write_bytes(std::vector<uint8_t>& out, const uint8_t* data, std::size_t len) {
    write_i32(out, static_cast<int32_t>(len));
    if (len > 0) {
        out.insert(out.end(), data, data + len);
    }
}

uint16_t to_cql_consistency(ConsistencyLevel cl) noexcept {
    switch (cl) {
    case ConsistencyLevel::Any:
        return 0x0000;
    case ConsistencyLevel::One:
        return 0x0001;
    case ConsistencyLevel::Two:
        return 0x0002;
    case ConsistencyLevel::Three:
        return 0x0003;
    case ConsistencyLevel::Quorum:
        return 0x0004;
    case ConsistencyLevel::All:
        return 0x0005;
    case ConsistencyLevel::LocalQuorum:
        return 0x0006;
    case ConsistencyLevel::EachQuorum:
        return 0x0007;
    case ConsistencyLevel::Serial:
        return 0x0008;
    case ConsistencyLevel::LocalSerial:
        return 0x0009;
    case ConsistencyLevel::LocalOne:
        return 0x000A;
    }
    return 0x0006;
}

ScyllaErrorCode map_cql_error_code(int32_t code) noexcept {
    switch (code) {
    case 0x0100: // Authentication error
    case 0x2100: // Unauthorized
        return ScyllaErrorCode::Unauthorized;
    case 0x1000: // Unavailable exception
        return ScyllaErrorCode::ConnectionError;
    case 0x1001: // Overloaded
        return ScyllaErrorCode::Overloaded;
    case 0x1100: // Write_timeout
    case 0x1200: // Read_timeout
        return ScyllaErrorCode::Timeout;
    case 0x2000: // Syntax_error
    case 0x2200: // Invalid
    case 0x2300: // Config_error
    case 0x2500: // Unprepared
        return ScyllaErrorCode::InvalidQuery;
    case 0x2400: // Already_exists
        return ScyllaErrorCode::AlreadyExists;
    default:
        return ScyllaErrorCode::InternalError;
    }
}

class FrameCursor {
  public:
    explicit FrameCursor(const std::vector<uint8_t>& buf) : data_(buf.data()), size_(buf.size()) {}

    [[nodiscard]] std::size_t remaining() const noexcept { return size_ - pos_; }

    uint8_t read_u8() {
        require(1);
        return data_[pos_++];
    }

    uint16_t read_u16() {
        require(2);
        const uint16_t v =
            static_cast<uint16_t>((static_cast<uint16_t>(data_[pos_]) << 8U) | static_cast<uint16_t>(data_[pos_ + 1]));
        pos_ += 2;
        return v;
    }

    int32_t read_i32() {
        require(4);
        const uint32_t u = (static_cast<uint32_t>(data_[pos_]) << 24U) |
                           (static_cast<uint32_t>(data_[pos_ + 1]) << 16U) |
                           (static_cast<uint32_t>(data_[pos_ + 2]) << 8U) | static_cast<uint32_t>(data_[pos_ + 3]);
        pos_ += 4;
        return static_cast<int32_t>(u);
    }

    int64_t read_i64() {
        require(8);
        uint64_t u = 0;
        for (int i = 0; i < 8; ++i) {
            u = (u << 8U) | static_cast<uint64_t>(data_[pos_ + static_cast<std::size_t>(i)]);
        }
        pos_ += 8;
        return static_cast<int64_t>(u);
    }

    std::string read_string() {
        const uint16_t len = read_u16();
        require(len);
        std::string s(reinterpret_cast<const char*>(data_ + pos_), len);
        pos_ += len;
        return s;
    }

    std::vector<uint8_t> read_short_bytes() {
        const uint16_t len = read_u16();
        require(len);
        std::vector<uint8_t> out(data_ + pos_, data_ + pos_ + len);
        pos_ += len;
        return out;
    }

    bool read_bytes_view(const uint8_t*& out_ptr, std::size_t& out_len) {
        const int32_t len = read_i32();
        if (len < 0) {
            out_ptr = nullptr;
            out_len = 0;
            return false;
        }
        const std::size_t ulen = static_cast<std::size_t>(len);
        require(ulen);
        out_ptr = data_ + pos_;
        out_len = ulen;
        pos_ += ulen;
        return true;
    }

  private:
    void require(std::size_t bytes) const {
        if (pos_ + bytes > size_) {
            throw ScyllaException(ScyllaErrorCode::InternalError, "Truncated CQL response frame");
        }
    }

    const uint8_t* data_;
    std::size_t size_;
    std::size_t pos_{0};
};

std::pair<uint16_t, uint16_t> parse_cql_option(FrameCursor& cursor) {
    const uint16_t type_id = cursor.read_u16();
    uint16_t elem_type_id = 0;
    switch (type_id) {
    case k_type_custom:
        (void)cursor.read_string();
        break;
    case k_type_list:
    case k_type_set:
        elem_type_id = parse_cql_option(cursor).first;
        break;
    case k_type_map:
        (void)parse_cql_option(cursor);
        (void)parse_cql_option(cursor);
        break;
    case k_type_udt: {
        (void)cursor.read_string();
        (void)cursor.read_string();
        const uint16_t field_count = cursor.read_u16();
        for (uint16_t i = 0; i < field_count; ++i) {
            (void)cursor.read_string();
            (void)parse_cql_option(cursor);
        }
        break;
    }
    case k_type_tuple: {
        const uint16_t field_count = cursor.read_u16();
        for (uint16_t i = 0; i < field_count; ++i) {
            (void)parse_cql_option(cursor);
        }
        break;
    }
    default:
        break;
    }
    return {type_id, elem_type_id};
}

std::string format_uuid_bytes(const uint8_t* ptr, std::size_t len) {
    if (len != 16) {
        return {};
    }
    static constexpr char k_hex[] = "0123456789abcdef";
    std::string out;
    out.reserve(36);
    for (std::size_t i = 0; i < 16; ++i) {
        if (i == 4 || i == 6 || i == 8 || i == 10) {
            out.push_back('-');
        }
        out.push_back(k_hex[(ptr[i] >> 4U) & 0x0FU]);
        out.push_back(k_hex[ptr[i] & 0x0FU]);
    }
    return out;
}

bool try_parse_uuid_bytes(std::string_view text, std::vector<uint8_t>& out) {
    auto hex_nibble = [](char ch) -> int {
        if (ch >= '0' && ch <= '9') {
            return ch - '0';
        }
        if (ch >= 'a' && ch <= 'f') {
            return 10 + (ch - 'a');
        }
        if (ch >= 'A' && ch <= 'F') {
            return 10 + (ch - 'A');
        }
        return -1;
    };

    out.clear();
    out.reserve(16);
    int hi = -1;
    for (char ch : text) {
        if (ch == '-') {
            continue;
        }
        const int nib = hex_nibble(ch);
        if (nib < 0) {
            return false;
        }
        if (hi < 0) {
            hi = nib;
        } else {
            out.push_back(static_cast<uint8_t>((hi << 4) | nib));
            hi = -1;
        }
    }
    return hi < 0 && out.size() == 16;
}

void encode_bound_value(std::vector<uint8_t>& out, const ScyllaValue& val, uint16_t expected_type_id) {
    if (val.is_null()) {
        write_i32(out, -1);
        return;
    }

    const auto& var = val.raw_value();
    if (const auto* s = std::get_if<std::string>(&var)) {
        if (expected_type_id == k_type_uuid || expected_type_id == k_type_timeuuid) {
            std::vector<uint8_t> uuid_bytes;
            if (!try_parse_uuid_bytes(*s, uuid_bytes)) {
                throw ScyllaException(ScyllaErrorCode::InvalidQuery, "Invalid UUID parameter value: " + *s);
            }
            write_bytes(out, uuid_bytes.data(), uuid_bytes.size());
        } else {
            write_bytes(out, reinterpret_cast<const uint8_t*>(s->data()), s->size());
        }
        return;
    }

    if (const auto* i32 = std::get_if<int32_t>(&var)) {
        if (expected_type_id == k_type_bigint || expected_type_id == k_type_timestamp ||
            expected_type_id == k_type_counter) {
            write_i32(out, 8);
            write_i64(out, static_cast<int64_t>(*i32));
        } else {
            write_i32(out, 4);
            write_i32(out, *i32);
        }
        return;
    }

    if (const auto* i64 = std::get_if<int64_t>(&var)) {
        if (expected_type_id == k_type_int) {
            write_i32(out, 4);
            write_i32(out, static_cast<int32_t>(*i64));
        } else {
            write_i32(out, 8);
            write_i64(out, *i64);
        }
        return;
    }

    if (const auto* b = std::get_if<bool>(&var)) {
        write_i32(out, 1);
        write_u8(out, *b ? 1 : 0);
        return;
    }

    if (const auto* blob = std::get_if<std::vector<uint8_t>>(&var)) {
        write_bytes(out, blob->data(), blob->size());
        return;
    }

    if (const auto* str_list = std::get_if<std::vector<std::string>>(&var)) {
        std::vector<uint8_t> encoded;
        write_i32(encoded, static_cast<int32_t>(str_list->size()));
        for (const auto& elem : *str_list) {
            write_bytes(encoded, reinterpret_cast<const uint8_t*>(elem.data()), elem.size());
        }
        write_bytes(out, encoded.data(), encoded.size());
        return;
    }

    write_i32(out, -1);
}

ScyllaValue decode_cell_value(const uint8_t* ptr, std::size_t len, uint16_t type_id) {
    switch (type_id) {
    case k_type_int: {
        if (len != 4) {
            throw ScyllaException(ScyllaErrorCode::InternalError, "Invalid CQL int cell length");
        }
        const uint32_t u = (static_cast<uint32_t>(ptr[0]) << 24U) | (static_cast<uint32_t>(ptr[1]) << 16U) |
                           (static_cast<uint32_t>(ptr[2]) << 8U) | static_cast<uint32_t>(ptr[3]);
        return ScyllaValue(static_cast<int32_t>(u));
    }
    case k_type_bigint:
    case k_type_counter:
    case k_type_timestamp: {
        if (len != 8) {
            throw ScyllaException(ScyllaErrorCode::InternalError, "Invalid CQL bigint/timestamp cell length");
        }
        uint64_t u = 0;
        for (int i = 0; i < 8; ++i) {
            u = (u << 8U) | static_cast<uint64_t>(ptr[i]);
        }
        return ScyllaValue(static_cast<int64_t>(u));
    }
    case k_type_boolean:
        if (len != 1) {
            throw ScyllaException(ScyllaErrorCode::InternalError, "Invalid CQL boolean cell length");
        }
        return ScyllaValue(ptr[0] != 0);
    case k_type_blob:
        return ScyllaValue(std::vector<uint8_t>(ptr, ptr + len));
    case k_type_uuid:
    case k_type_timeuuid:
        return ScyllaValue(format_uuid_bytes(ptr, len));
    case k_type_list:
    case k_type_set: {
        std::vector<uint8_t> raw(ptr, ptr + len);
        FrameCursor col_cursor(raw);
        const int32_t count = col_cursor.read_i32();
        if (count < 0) {
            return ScyllaValue(std::vector<std::string>{});
        }
        std::vector<std::string> items;
        items.reserve(static_cast<std::size_t>(count));
        for (int32_t i = 0; i < count; ++i) {
            const uint8_t* elem_ptr = nullptr;
            std::size_t elem_len = 0;
            if (!col_cursor.read_bytes_view(elem_ptr, elem_len)) {
                items.emplace_back();
            } else {
                items.emplace_back(reinterpret_cast<const char*>(elem_ptr), elem_len);
            }
        }
        return ScyllaValue(std::move(items));
    }
    case k_type_ascii:
    case k_type_varchar:
    default:
        return ScyllaValue(std::string(reinterpret_cast<const char*>(ptr), len));
    }
}

void set_socket_timeouts(int fd, uint32_t timeout_ms) {
    struct timeval tv{};
    tv.tv_sec = static_cast<decltype(tv.tv_sec)>(timeout_ms / 1000U);
    tv.tv_usec = static_cast<decltype(tv.tv_usec)>((timeout_ms % 1000U) * 1000U);
    (void)::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    (void)::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

int connect_tcp_socket(const std::string& host, uint16_t port, uint32_t connect_timeout_ms, uint32_t request_timeout_ms,
                       std::string& out_error) {
    struct addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    struct addrinfo* result = nullptr;
    const std::string port_str = std::to_string(port);
    const int gai_rc = ::getaddrinfo(host.c_str(), port_str.c_str(), &hints, &result);
    if (gai_rc != 0 || result == nullptr) {
        out_error = std::string("DNS resolution failed for ") + host + ": " + ::gai_strerror(gai_rc);
        return -1;
    }

    int connected_fd = -1;
    int last_errno = 0;

    for (struct addrinfo* rp = result; rp != nullptr; rp = rp->ai_next) {
        const int fd = ::socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) {
            last_errno = errno;
            continue;
        }

#ifdef SO_NOSIGPIPE
        int no_sigpipe = 1;
        (void)::setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &no_sigpipe, sizeof(no_sigpipe));
#endif
        int tcp_nodelay = 1;
        (void)::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &tcp_nodelay, sizeof(tcp_nodelay));

        const int flags = ::fcntl(fd, F_GETFL, 0);
        if (flags >= 0) {
            (void)::fcntl(fd, F_SETFL, flags | O_NONBLOCK);
        }

        int rc = ::connect(fd, rp->ai_addr, rp->ai_addrlen);
        if (rc < 0 && errno == EINPROGRESS) {
            struct pollfd pfd{};
            pfd.fd = fd;
            pfd.events = POLLOUT;
            const int poll_rc = ::poll(&pfd, 1, static_cast<int>(connect_timeout_ms));
            if (poll_rc > 0) {
                int so_err = 0;
                socklen_t so_len = sizeof(so_err);
                if (::getsockopt(fd, SOL_SOCKET, SO_ERROR, &so_err, &so_len) == 0 && so_err == 0) {
                    rc = 0;
                } else {
                    last_errno = (so_err != 0) ? so_err : errno;
                }
            } else {
                last_errno = (poll_rc == 0) ? ETIMEDOUT : errno;
            }
        } else if (rc < 0) {
            last_errno = errno;
        }

        if (rc == 0) {
            if (flags >= 0) {
                (void)::fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);
            }
            set_socket_timeouts(fd, request_timeout_ms > 0 ? request_timeout_ms : 2000U);
            connected_fd = fd;
            break;
        }

        ::close(fd);
    }

    ::freeaddrinfo(result);
    if (connected_fd < 0) {
        out_error = "Failed to connect to ScyllaDB at " + host + ":" + port_str + " (" +
                    std::strerror(last_errno != 0 ? last_errno : ECONNREFUSED) + ")";
    }
    return connected_fd;
}

[[noreturn]] void throw_cql_error_frame(const std::vector<uint8_t>& body, int32_t& out_error_code) {
    FrameCursor cursor(body);
    out_error_code = cursor.read_i32();
    const std::string msg = cursor.read_string();
    throw ScyllaException(map_cql_error_code(out_error_code), "ScyllaDB CQL error: " + msg);
}

} // namespace

ScyllaSession::ScyllaSession(ScyllaConfig config) : config_(std::move(config)) {}

ScyllaSession::~ScyllaSession() {
    close();
}

void ScyllaSession::disconnect_socket_locked() noexcept {
    if (socket_fd_ >= 0) {
        ::close(socket_fd_);
        socket_fd_ = -1;
    }
    for (auto& [_, entry] : prepared_cache_) {
        entry.prepared_on_wire = false;
        entry.scylla_id.clear();
    }
}

void ScyllaSession::send_all_locked(const uint8_t* data, std::size_t len) {
    std::size_t sent = 0;
    while (sent < len) {
#ifdef MSG_NOSIGNAL
        const ssize_t n = ::send(socket_fd_, data + sent, len - sent, MSG_NOSIGNAL);
#else
        const ssize_t n = ::send(socket_fd_, data + sent, len - sent, 0);
#endif
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            const int err = errno;
            disconnect_socket_locked();
            throw ScyllaException((err == EAGAIN || err == EWOULDBLOCK) ? ScyllaErrorCode::Timeout
                                                                        : ScyllaErrorCode::ConnectionError,
                                  std::string("ScyllaDB socket send failed: ") + std::strerror(err));
        }
        if (n == 0) {
            disconnect_socket_locked();
            throw ScyllaException(ScyllaErrorCode::ConnectionError, "ScyllaDB closed connection during send");
        }
        sent += static_cast<std::size_t>(n);
    }
}

void ScyllaSession::recv_all_locked(uint8_t* data, std::size_t len) {
    std::size_t recvd = 0;
    while (recvd < len) {
        const ssize_t n = ::recv(socket_fd_, data + recvd, len - recvd, 0);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            const int err = errno;
            disconnect_socket_locked();
            throw ScyllaException((err == EAGAIN || err == EWOULDBLOCK) ? ScyllaErrorCode::Timeout
                                                                        : ScyllaErrorCode::ConnectionError,
                                  std::string("ScyllaDB socket recv failed: ") + std::strerror(err));
        }
        if (n == 0) {
            disconnect_socket_locked();
            throw ScyllaException(ScyllaErrorCode::ConnectionError, "ScyllaDB closed connection unexpectedly");
        }
        recvd += static_cast<std::size_t>(n);
    }
}

ScyllaSession::CqlFrame ScyllaSession::send_frame_and_recv_locked(uint8_t opcode, const std::vector<uint8_t>& body) {
    const int16_t stream_id = next_stream_id_;
    next_stream_id_ = static_cast<int16_t>((next_stream_id_ & 0x7FFF) + 1);
    if (next_stream_id_ <= 0) {
        next_stream_id_ = 1;
    }

    std::vector<uint8_t> packet;
    packet.reserve(9 + body.size());
    packet.push_back(k_cql_version_request);
    packet.push_back(0x00);
    write_u16(packet, static_cast<uint16_t>(stream_id));
    packet.push_back(opcode);
    write_i32(packet, static_cast<int32_t>(body.size()));
    packet.insert(packet.end(), body.begin(), body.end());

    send_all_locked(packet.data(), packet.size());

    uint8_t hdr[9]{};
    recv_all_locked(hdr, sizeof(hdr));
    if (hdr[0] != k_cql_version_response) {
        disconnect_socket_locked();
        throw ScyllaException(ScyllaErrorCode::InternalError, "Unexpected CQL response frame version");
    }

    const uint32_t body_len = (static_cast<uint32_t>(hdr[5]) << 24U) | (static_cast<uint32_t>(hdr[6]) << 16U) |
                              (static_cast<uint32_t>(hdr[7]) << 8U) | static_cast<uint32_t>(hdr[8]);
    if (body_len > k_max_cql_frame_bytes) {
        disconnect_socket_locked();
        throw ScyllaException(ScyllaErrorCode::InternalError, "ScyllaDB response frame exceeds size limit");
    }

    CqlFrame resp;
    resp.opcode = hdr[4];
    resp.body.resize(body_len);
    if (body_len > 0) {
        recv_all_locked(resp.body.data(), body_len);
    }
    return resp;
}

void ScyllaSession::ensure_connected_locked() {
    if (closed_.load(std::memory_order_acquire)) {
        throw ScyllaException(ScyllaErrorCode::ConnectionError, "ScyllaDB session is closed");
    }
    if (socket_fd_ >= 0) {
        return;
    }

    std::string conn_error;
    const uint32_t connect_ms = config_.connect_timeout_ms > 0 ? config_.connect_timeout_ms : 5000U;
    const uint32_t req_ms = config_.request_timeout_ms > 0 ? config_.request_timeout_ms : 2000U;
    socket_fd_ = connect_tcp_socket(config_.host, config_.port, connect_ms, req_ms, conn_error);
    if (socket_fd_ < 0) {
        throw ScyllaException(ScyllaErrorCode::ConnectionError, conn_error);
    }

    // Send CQL v4 STARTUP {"CQL_VERSION": "3.0.0"}
    std::vector<uint8_t> startup_body;
    write_u16(startup_body, 1);
    write_string(startup_body, "CQL_VERSION");
    write_string(startup_body, "3.0.0");

    auto resp = send_frame_and_recv_locked(k_op_startup, startup_body);
    if (resp.opcode == k_op_authenticate) {
        std::vector<uint8_t> auth_body;
        write_i32(auth_body, 0);
        resp = send_frame_and_recv_locked(k_op_auth_response, auth_body);
    }
    if (resp.opcode == k_op_error) {
        int32_t err_code = 0;
        disconnect_socket_locked();
        throw_cql_error_frame(resp.body, err_code);
    }
    if (resp.opcode != k_op_ready && resp.opcode != k_op_auth_success) {
        disconnect_socket_locked();
        throw ScyllaException(ScyllaErrorCode::ConnectionError, "Unexpected CQL handshake response opcode");
    }
}

ScyllaSession::PreparedStatementEntry& ScyllaSession::ensure_prepared_locked(const std::string& query_id,
                                                                             bool force_reprepare) {
    auto it = prepared_cache_.find(query_id);
    if (it == prepared_cache_.end()) {
        throw ScyllaException(ScyllaErrorCode::InvalidQuery,
                              "Prepared statement not found in session cache: " + query_id);
    }

    auto& entry = it->second;
    if (entry.prepared_on_wire && !force_reprepare) {
        return entry;
    }

    ensure_connected_locked();
    std::vector<uint8_t> req_body;
    write_long_string(req_body, entry.cql);

    auto resp = send_frame_and_recv_locked(k_op_prepare, req_body);
    if (resp.opcode == k_op_error) {
        int32_t err_code = 0;
        throw_cql_error_frame(resp.body, err_code);
    }
    if (resp.opcode != k_op_result) {
        throw ScyllaException(ScyllaErrorCode::InternalError, "Expected RESULT opcode for CQL PREPARE");
    }

    FrameCursor cursor(resp.body);
    const int32_t kind = cursor.read_i32();
    if (kind != k_result_prepared) {
        throw ScyllaException(ScyllaErrorCode::InternalError, "Expected PREPARED result kind from ScyllaDB");
    }

    entry.scylla_id = cursor.read_short_bytes();

    auto parse_meta = [&](bool is_bind_meta) {
        std::vector<WireColumnSpec> specs;
        const int32_t flags = cursor.read_i32();
        const int32_t col_count = cursor.read_i32();
        if (is_bind_meta) {
            const int32_t pk_count = cursor.read_i32();
            for (int32_t i = 0; i < pk_count; ++i) {
                (void)cursor.read_u16();
            }
        } else if ((flags & k_meta_flag_has_more_pages) != 0) {
            const uint8_t* ptr = nullptr;
            std::size_t len = 0;
            (void)cursor.read_bytes_view(ptr, len);
        }

        if ((flags & k_meta_flag_no_metadata) == 0 && col_count > 0) {
            const bool global_spec = (flags & k_meta_flag_global_tables_spec) != 0;
            if (global_spec) {
                (void)cursor.read_string();
                (void)cursor.read_string();
            }
            specs.reserve(static_cast<std::size_t>(col_count));
            for (int32_t i = 0; i < col_count; ++i) {
                if (!global_spec) {
                    (void)cursor.read_string();
                    (void)cursor.read_string();
                }
                WireColumnSpec spec;
                spec.name = cursor.read_string();
                const auto [type_id, elem_type_id] = parse_cql_option(cursor);
                spec.type_id = type_id;
                spec.elem_type_id = elem_type_id;
                specs.push_back(std::move(spec));
            }
        }
        return specs;
    };

    entry.param_specs = parse_meta(true);
    entry.result_specs = parse_meta(false);
    entry.prepared_on_wire = true;
    return entry;
}

ScyllaQueryResult ScyllaSession::parse_result_frame_locked(const std::vector<uint8_t>& body,
                                                           const std::vector<WireColumnSpec>* fallback_result_specs,
                                                           std::vector<uint8_t>* out_next_paging_state) {
    if (out_next_paging_state) {
        out_next_paging_state->clear();
    }

    FrameCursor cursor(body);
    const int32_t kind = cursor.read_i32();
    if (kind == k_result_void || kind == k_result_set_keyspace || kind == k_result_schema_change) {
        return ScyllaQueryResult{};
    }
    if (kind != k_result_rows) {
        return ScyllaQueryResult{};
    }

    const int32_t flags = cursor.read_i32();
    const int32_t col_count = cursor.read_i32();
    if ((flags & k_meta_flag_has_more_pages) != 0) {
        const uint8_t* ps_ptr = nullptr;
        std::size_t ps_len = 0;
        if (cursor.read_bytes_view(ps_ptr, ps_len) && out_next_paging_state && ps_ptr != nullptr && ps_len > 0) {
            out_next_paging_state->assign(ps_ptr, ps_ptr + ps_len);
        }
    }

    std::vector<WireColumnSpec> specs;
    if ((flags & k_meta_flag_no_metadata) == 0 && col_count > 0) {
        const bool global_spec = (flags & k_meta_flag_global_tables_spec) != 0;
        if (global_spec) {
            (void)cursor.read_string();
            (void)cursor.read_string();
        }
        specs.reserve(static_cast<std::size_t>(col_count));
        for (int32_t i = 0; i < col_count; ++i) {
            if (!global_spec) {
                (void)cursor.read_string();
                (void)cursor.read_string();
            }
            WireColumnSpec spec;
            spec.name = cursor.read_string();
            const auto [type_id, elem_type_id] = parse_cql_option(cursor);
            spec.type_id = type_id;
            spec.elem_type_id = elem_type_id;
            specs.push_back(std::move(spec));
        }
    } else if (fallback_result_specs != nullptr) {
        specs = *fallback_result_specs;
    }

    std::vector<std::string> col_names;
    col_names.reserve(specs.size());
    for (const auto& s : specs) {
        col_names.push_back(s.name);
    }

    const int32_t row_count = cursor.read_i32();
    std::vector<ScyllaRow> rows;
    if (row_count > 0) {
        rows.reserve(static_cast<std::size_t>(row_count));
    }

    bool applied = true;
    for (int32_t r = 0; r < row_count; ++r) {
        std::vector<ScyllaValue> values;
        values.reserve(specs.size());
        for (std::size_t c = 0; c < specs.size(); ++c) {
            const uint8_t* cell_ptr = nullptr;
            std::size_t cell_len = 0;
            if (!cursor.read_bytes_view(cell_ptr, cell_len)) {
                values.push_back(ScyllaValue::null());
            } else {
                values.push_back(decode_cell_value(cell_ptr, cell_len, specs[c].type_id));
            }
        }
        ScyllaRow row(col_names, std::move(values));
        if (r == 0 && row.has_column("[applied]") && !row.is_null("[applied]")) {
            applied = row.get_bool("[applied]");
        }
        rows.push_back(std::move(row));
    }

    return ScyllaQueryResult(std::move(rows), applied);
}

ScyllaQueryResult ScyllaSession::execute_query_once_locked(std::string_view cql, ConsistencyLevel cl,
                                                           const std::vector<uint8_t>* paging_state,
                                                           std::vector<uint8_t>& out_next_paging_state) {
    ensure_connected_locked();

    std::vector<uint8_t> body;
    write_long_string(body, cql);
    write_u16(body, to_cql_consistency(cl));

    uint8_t flags = 0x00;
    if (paging_state != nullptr && !paging_state->empty()) {
        flags |= k_query_flag_with_paging_state;
    }
    write_u8(body, flags);
    if ((flags & k_query_flag_with_paging_state) != 0) {
        write_bytes(body, paging_state->data(), paging_state->size());
    }

    auto resp = send_frame_and_recv_locked(k_op_query, body);
    if (resp.opcode == k_op_error) {
        int32_t err_code = 0;
        throw_cql_error_frame(resp.body, err_code);
    }
    if (resp.opcode != k_op_result) {
        throw ScyllaException(ScyllaErrorCode::InternalError, "Expected RESULT opcode for CQL QUERY");
    }

    return parse_result_frame_locked(resp.body, nullptr, &out_next_paging_state);
}

ScyllaQueryResult ScyllaSession::execute(std::string_view cql, ConsistencyLevel cl) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (closed_.load(std::memory_order_acquire)) {
        throw ScyllaException(ScyllaErrorCode::ConnectionError, "ScyllaDB session is closed");
    }

    std::vector<uint8_t> paging_state;
    std::vector<uint8_t> next_paging_state;
    ScyllaQueryResult first_page = execute_query_once_locked(cql, cl, nullptr, next_paging_state);
    if (next_paging_state.empty()) {
        return first_page;
    }

    std::vector<ScyllaRow> all_rows;
    for (const auto& row : first_page) {
        all_rows.push_back(row);
    }
    while (!next_paging_state.empty()) {
        paging_state = std::move(next_paging_state);
        next_paging_state.clear();
        auto page = execute_query_once_locked(cql, cl, &paging_state, next_paging_state);
        for (const auto& row : page) {
            all_rows.push_back(row);
        }
    }
    return ScyllaQueryResult(std::move(all_rows), first_page.is_applied());
}

PreparedStatementId ScyllaSession::prepare(std::string_view query_id, std::string_view cql) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (closed_.load(std::memory_order_acquire)) {
        throw ScyllaException(ScyllaErrorCode::ConnectionError, "ScyllaDB session is closed");
    }

    std::string id_str(query_id);
    auto& entry = prepared_cache_[id_str];
    if (entry.cql != cql) {
        entry.cql = std::string(cql);
        entry.scylla_id.clear();
        entry.param_specs.clear();
        entry.result_specs.clear();
        entry.prepared_on_wire = false;
    }
    return PreparedStatementId(id_str);
}

ScyllaQueryResult ScyllaSession::execute_prepared_once_locked(PreparedStatementEntry& entry, const ScyllaParams& params,
                                                              ConsistencyLevel cl,
                                                              const std::vector<uint8_t>* paging_state,
                                                              std::vector<uint8_t>& out_next_paging_state,
                                                              bool& out_unprepared) {
    out_unprepared = false;
    ensure_connected_locked();

    std::vector<uint8_t> body;
    write_short_bytes(body, entry.scylla_id);
    write_u16(body, to_cql_consistency(cl));

    uint8_t flags = params.empty() ? 0x00 : k_query_flag_values;
    if (paging_state != nullptr && !paging_state->empty()) {
        flags |= k_query_flag_with_paging_state;
    }
    write_u8(body, flags);

    if ((flags & k_query_flag_values) != 0) {
        write_u16(body, static_cast<uint16_t>(params.size()));
        for (std::size_t i = 0; i < params.size(); ++i) {
            const uint16_t expected_type =
                (i < entry.param_specs.size()) ? entry.param_specs[i].type_id : k_type_varchar;
            encode_bound_value(body, params[i], expected_type);
        }
    }
    if ((flags & k_query_flag_with_paging_state) != 0) {
        write_bytes(body, paging_state->data(), paging_state->size());
    }

    auto resp = send_frame_and_recv_locked(k_op_execute, body);
    if (resp.opcode == k_op_error) {
        FrameCursor err_cursor(resp.body);
        const int32_t err_code = err_cursor.read_i32();
        if (err_code == 0x2500) { // UNPREPARED
            out_unprepared = true;
            return ScyllaQueryResult{};
        }
        const std::string msg = err_cursor.read_string();
        throw ScyllaException(map_cql_error_code(err_code), "ScyllaDB CQL error: " + msg);
    }
    if (resp.opcode != k_op_result) {
        throw ScyllaException(ScyllaErrorCode::InternalError, "Expected RESULT opcode for CQL EXECUTE");
    }

    return parse_result_frame_locked(resp.body, &entry.result_specs, &out_next_paging_state);
}

ScyllaQueryResult ScyllaSession::execute_prepared(const PreparedStatementId& id, const ScyllaParams& params,
                                                  ConsistencyLevel cl) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (closed_.load(std::memory_order_acquire)) {
        throw ScyllaException(ScyllaErrorCode::ConnectionError, "ScyllaDB session is closed");
    }

    auto run_page = [&](const std::vector<uint8_t>* paging_state,
                        std::vector<uint8_t>& next_paging_state) -> ScyllaQueryResult {
        auto& entry = ensure_prepared_locked(id.value(), false);
        bool unprepared = false;
        ScyllaQueryResult res =
            execute_prepared_once_locked(entry, params, cl, paging_state, next_paging_state, unprepared);
        if (unprepared) {
            auto& reprepared = ensure_prepared_locked(id.value(), true);
            res = execute_prepared_once_locked(reprepared, params, cl, paging_state, next_paging_state, unprepared);
            if (unprepared) {
                throw ScyllaException(ScyllaErrorCode::InvalidQuery,
                                      "Statement remained unprepared after retry: " + id.value());
            }
        }
        return res;
    };

    std::vector<uint8_t> paging_state;
    std::vector<uint8_t> next_paging_state;
    ScyllaQueryResult first_page = run_page(nullptr, next_paging_state);
    if (next_paging_state.empty()) {
        return first_page;
    }

    std::vector<ScyllaRow> all_rows;
    for (const auto& row : first_page) {
        all_rows.push_back(row);
    }
    while (!next_paging_state.empty()) {
        paging_state = std::move(next_paging_state);
        next_paging_state.clear();
        auto page = run_page(&paging_state, next_paging_state);
        for (const auto& row : page) {
            all_rows.push_back(row);
        }
    }
    return ScyllaQueryResult(std::move(all_rows), first_page.is_applied());
}

void ScyllaSession::execute_batch(const std::vector<BoundStatement>& batch, BatchType type) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (closed_.load(std::memory_order_acquire)) {
        throw ScyllaException(ScyllaErrorCode::ConnectionError, "ScyllaDB session is closed");
    }

    for (const auto& bound : batch) {
        if (prepared_cache_.find(bound.statement_id().value()) == prepared_cache_.end()) {
            throw ScyllaException(ScyllaErrorCode::InvalidQuery,
                                  "Batch contains un-prepared statement: " + bound.statement_id().value());
        }
    }

    if (batch.empty()) {
        ensure_connected_locked();
        return;
    }

    auto send_batch = [&](bool force_reprepare, bool& out_unprepared) {
        out_unprepared = false;
        ensure_connected_locked();

        std::vector<uint8_t> body;
        uint8_t batch_type_byte = 0;
        if (type == BatchType::Unlogged) {
            batch_type_byte = 1;
        } else if (type == BatchType::Counter) {
            batch_type_byte = 2;
        }
        write_u8(body, batch_type_byte);
        write_u16(body, static_cast<uint16_t>(batch.size()));

        for (const auto& bound : batch) {
            const auto& entry = ensure_prepared_locked(bound.statement_id().value(), force_reprepare);
            write_u8(body, 1); // kind = prepared
            write_short_bytes(body, entry.scylla_id);
            write_u16(body, static_cast<uint16_t>(bound.params().size()));
            for (std::size_t i = 0; i < bound.params().size(); ++i) {
                const uint16_t expected_type =
                    (i < entry.param_specs.size()) ? entry.param_specs[i].type_id : k_type_varchar;
                encode_bound_value(body, bound.params()[i], expected_type);
            }
        }

        write_u16(body, to_cql_consistency(batch.front().consistency()));
        write_u8(body, 0x00); // flags

        auto resp = send_frame_and_recv_locked(k_op_batch, body);
        if (resp.opcode == k_op_error) {
            FrameCursor err_cursor(resp.body);
            const int32_t err_code = err_cursor.read_i32();
            if (err_code == 0x2500) {
                out_unprepared = true;
                return;
            }
            const std::string msg = err_cursor.read_string();
            throw ScyllaException(map_cql_error_code(err_code), "ScyllaDB CQL error: " + msg);
        }
    };

    bool unprepared = false;
    send_batch(false, unprepared);
    if (unprepared) {
        send_batch(true, unprepared);
        if (unprepared) {
            throw ScyllaException(ScyllaErrorCode::InvalidQuery, "Batch remained unprepared after retry");
        }
    }
}

bool ScyllaSession::ping() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (closed_.load(std::memory_order_acquire)) {
        return false;
    }
    try {
        ensure_connected_locked();
        auto resp = send_frame_and_recv_locked(k_op_options, {});
        return resp.opcode == k_op_supported || resp.opcode == k_op_ready;
    } catch (...) {
        disconnect_socket_locked();
        return false;
    }
}

void ScyllaSession::close() {
    std::lock_guard<std::mutex> lock(mutex_);
    closed_.store(true, std::memory_order_release);
    disconnect_socket_locked();
    prepared_cache_.clear();
}

bool ScyllaSession::is_closed() const noexcept {
    return closed_.load(std::memory_order_acquire);
}

} // namespace securecloud::messaging::db
