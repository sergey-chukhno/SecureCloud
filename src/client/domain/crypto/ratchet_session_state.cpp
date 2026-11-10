#include "domain/crypto/ratchet_session_state.hpp"

#include <cstring>
#include <openssl/crypto.h>

namespace securecloud::client::domain::crypto {
namespace {

constexpr uint8_t kMagic[4] = {'S', 'C', 'S', 0x01};

void write_u16(std::vector<uint8_t>& buf, uint16_t val) {
    buf.push_back(static_cast<uint8_t>((val >> 8) & 0xFF));
    buf.push_back(static_cast<uint8_t>(val & 0xFF));
}

void write_u32(std::vector<uint8_t>& buf, uint32_t val) {
    buf.push_back(static_cast<uint8_t>((val >> 24) & 0xFF));
    buf.push_back(static_cast<uint8_t>((val >> 16) & 0xFF));
    buf.push_back(static_cast<uint8_t>((val >> 8) & 0xFF));
    buf.push_back(static_cast<uint8_t>(val & 0xFF));
}

void write_i64(std::vector<uint8_t>& buf, int64_t val) {
    const auto uval = static_cast<uint64_t>(val);
    for (int i = 7; i >= 0; --i) {
        buf.push_back(static_cast<uint8_t>((uval >> (static_cast<unsigned int>(i) * 8)) & 0xFF));
    }
}

void write_string(std::vector<uint8_t>& buf, std::string_view str) {
    write_u16(buf, static_cast<uint16_t>(str.size()));
    buf.insert(buf.end(), str.begin(), str.end());
}

void write_bytes(std::vector<uint8_t>& buf, std::span<const uint8_t> data) {
    write_u32(buf, static_cast<uint32_t>(data.size()));
    buf.insert(buf.end(), data.begin(), data.end());
}

bool read_u16(std::span<const uint8_t>& in, uint16_t& val) {
    if (in.size() < 2) {
        return false;
    }
    val = static_cast<uint16_t>((static_cast<uint16_t>(in[0]) << 8) | in[1]);
    in = in.subspan(2);
    return true;
}

bool read_u32(std::span<const uint8_t>& in, uint32_t& val) {
    if (in.size() < 4) {
        return false;
    }
    val = (static_cast<uint32_t>(in[0]) << 24) | (static_cast<uint32_t>(in[1]) << 16) |
          (static_cast<uint32_t>(in[2]) << 8) | static_cast<uint32_t>(in[3]);
    in = in.subspan(4);
    return true;
}

bool read_i64(std::span<const uint8_t>& in, int64_t& val) {
    if (in.size() < 8) {
        return false;
    }
    uint64_t uval = 0;
    for (std::size_t i = 0; i < 8; ++i) {
        uval = (uval << 8) | static_cast<uint64_t>(in[i]);
    }
    in = in.subspan(8);
    val = static_cast<int64_t>(uval);
    return true;
}

bool read_string(std::span<const uint8_t>& in, std::string& out) {
    uint16_t len = 0;
    if (!read_u16(in, len) || in.size() < len) {
        return false;
    }
    out.assign(reinterpret_cast<const char*>(in.data()), len);
    in = in.subspan(len);
    return true;
}

bool read_bytes(std::span<const uint8_t>& in, std::vector<uint8_t>& out) {
    uint32_t len = 0;
    if (!read_u32(in, len) || in.size() < len) {
        return false;
    }
    out.assign(in.begin(), in.begin() + len);
    in = in.subspan(len);
    return true;
}

} // namespace

application::ClientResult<securecloud::common::configuration::SecretString>
RatchetSessionSerializer::serialize(const RatchetSession& session) {
    std::vector<uint8_t> buf;
    buf.insert(buf.end(), std::begin(kMagic), std::end(kMagic));

    // Peer metadata
    write_string(buf, session.peer_user_id.str());
    write_string(buf, session.peer_device_id.str());
    write_bytes(buf, session.peer_identity_key);

    // Initial message pending & X3DH header
    buf.push_back(session.initial_message_pending ? 1 : 0);
    buf.push_back(session.pending_x3dh_header.has_value() ? 1 : 0);
    if (session.pending_x3dh_header.has_value()) {
        auto x3dh_bytes = session.pending_x3dh_header->serialize();
        write_bytes(buf, x3dh_bytes);
    }

    // Timestamps
    const auto est_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(session.established_at.time_since_epoch()).count();
    const auto act_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(session.last_active_at.time_since_epoch()).count();
    write_i64(buf, est_ms);
    write_i64(buf, act_ms);

    // RatchetState
    const auto& st = session.ratchet_state;
    const auto& rk = st.root_key.expose_unredacted_secret();
    write_bytes(buf, std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(rk.data()), rk.size()));

    const auto& priv = st.sending_dh_pair.private_key.expose_unredacted_secret();
    write_bytes(buf, std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(priv.data()), priv.size()));
    write_bytes(buf, st.sending_dh_pair.public_key);
    write_bytes(buf, st.peer_dh_pub);

    const auto& send_ck = st.sending_chain_key.expose_unredacted_secret();
    write_bytes(buf, std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(send_ck.data()), send_ck.size()));

    const auto& recv_ck = st.receiving_chain_key.expose_unredacted_secret();
    write_bytes(buf, std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(recv_ck.data()), recv_ck.size()));

    write_u32(buf, st.ns);
    write_u32(buf, st.nr);
    write_u32(buf, st.pn);

    // Skipped keys
    const auto& skipped_entries = st.skipped_keys.entries();
    write_u32(buf, static_cast<uint32_t>(skipped_entries.size()));
    for (const auto& [id, entry] : skipped_entries) {
        write_bytes(buf, id.dh_pub);
        write_u32(buf, id.message_index);
        const auto& mk = entry.message_key.expose_unredacted_secret();
        write_bytes(buf, std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(mk.data()), mk.size()));
        const auto c_ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(entry.created_at.time_since_epoch()).count();
        write_i64(buf, c_ms);
    }

    std::string serialized_str(reinterpret_cast<const char*>(buf.data()), buf.size());
    OPENSSL_cleanse(buf.data(), buf.size());

    return application::ClientResult<securecloud::common::configuration::SecretString>::ok(
        securecloud::common::configuration::SecretString(std::move(serialized_str)));
}

application::ClientResult<RatchetSession>
RatchetSessionSerializer::deserialize(const securecloud::common::configuration::SecretString& data) {
    const auto& raw_str = data.expose_unredacted_secret();
    std::span<const uint8_t> in(reinterpret_cast<const uint8_t*>(raw_str.data()), raw_str.size());

    if (in.size() < 4 || std::memcmp(in.data(), kMagic, 4) != 0) {
        return application::ClientResult<RatchetSession>::error(
            application::ClientError::validation("Invalid magic bytes in serialized RatchetSession"));
    }
    in = in.subspan(4);

    std::string peer_uid_str;
    std::string peer_did_str;
    std::vector<uint8_t> peer_ik;

    if (!read_string(in, peer_uid_str) || !read_string(in, peer_did_str) || !read_bytes(in, peer_ik)) {
        return application::ClientResult<RatchetSession>::error(
            application::ClientError::validation("Truncated peer metadata in RatchetSession"));
    }

    if (in.size() < 2) {
        return application::ClientResult<RatchetSession>::error(
            application::ClientError::validation("Truncated flags in RatchetSession"));
    }
    const bool init_pending = (in[0] != 0);
    const bool has_x3dh = (in[1] != 0);
    in = in.subspan(2);

    std::optional<X3dhHeader> x3dh_hdr;
    if (has_x3dh) {
        std::vector<uint8_t> x3dh_bytes;
        if (!read_bytes(in, x3dh_bytes)) {
            return application::ClientResult<RatchetSession>::error(
                application::ClientError::validation("Truncated X3DH header in RatchetSession"));
        }
        auto x_res = X3dhHeader::deserialize(x3dh_bytes);
        if (!x_res.is_ok()) {
            return application::ClientResult<RatchetSession>::error(x_res.error());
        }
        x3dh_hdr = std::move(x_res).value();
    }

    int64_t est_ms = 0;
    int64_t act_ms = 0;
    if (!read_i64(in, est_ms) || !read_i64(in, act_ms)) {
        return application::ClientResult<RatchetSession>::error(
            application::ClientError::validation("Truncated timestamps in RatchetSession"));
    }

    // RatchetState
    std::vector<uint8_t> rk_bytes;
    std::vector<uint8_t> priv_bytes;
    std::vector<uint8_t> pub_bytes;
    std::vector<uint8_t> peer_dh;
    std::vector<uint8_t> send_ck_bytes;
    std::vector<uint8_t> recv_ck_bytes;

    if (!read_bytes(in, rk_bytes) || !read_bytes(in, priv_bytes) || !read_bytes(in, pub_bytes) ||
        !read_bytes(in, peer_dh) || !read_bytes(in, send_ck_bytes) || !read_bytes(in, recv_ck_bytes)) {
        return application::ClientResult<RatchetSession>::error(
            application::ClientError::validation("Truncated cryptographic keys in RatchetSession"));
    }

    uint32_t ns = 0;
    uint32_t nr = 0;
    uint32_t pn = 0;
    if (!read_u32(in, ns) || !read_u32(in, nr) || !read_u32(in, pn)) {
        return application::ClientResult<RatchetSession>::error(
            application::ClientError::validation("Truncated sequence numbers in RatchetSession"));
    }

    uint32_t skipped_count = 0;
    if (!read_u32(in, skipped_count)) {
        return application::ClientResult<RatchetSession>::error(
            application::ClientError::validation("Truncated skipped keys count in RatchetSession"));
    }

    SkippedKeysStore skipped_store;
    for (uint32_t i = 0; i < skipped_count; ++i) {
        std::vector<uint8_t> dh;
        uint32_t idx = 0;
        std::vector<uint8_t> mk_bytes;
        int64_t c_ms = 0;
        if (!read_bytes(in, dh) || !read_u32(in, idx) || !read_bytes(in, mk_bytes) || !read_i64(in, c_ms)) {
            return application::ClientResult<RatchetSession>::error(
                application::ClientError::validation("Truncated skipped key entry in RatchetSession"));
        }
        std::string mk_str(reinterpret_cast<const char*>(mk_bytes.data()), mk_bytes.size());
        auto tp = std::chrono::system_clock::time_point(std::chrono::milliseconds(c_ms));
        auto s_res =
            skipped_store.store_key(dh, idx, securecloud::common::configuration::SecretString(std::move(mk_str)), tp);
        if (!s_res.is_ok()) {
            return application::ClientResult<RatchetSession>::error(s_res.error());
        }
    }

    RatchetState st{
        .root_key = securecloud::common::configuration::SecretString(
            std::string(reinterpret_cast<const char*>(rk_bytes.data()), rk_bytes.size())),
        .sending_dh_pair =
            application::interfaces::DhKeyPair{
                .public_key = std::move(pub_bytes),
                .private_key = securecloud::common::configuration::SecretString(
                    std::string(reinterpret_cast<const char*>(priv_bytes.data()), priv_bytes.size())),
            },
        .peer_dh_pub = std::move(peer_dh),
        .sending_chain_key = securecloud::common::configuration::SecretString(
            std::string(reinterpret_cast<const char*>(send_ck_bytes.data()), send_ck_bytes.size())),
        .receiving_chain_key = securecloud::common::configuration::SecretString(
            std::string(reinterpret_cast<const char*>(recv_ck_bytes.data()), recv_ck_bytes.size())),
        .ns = ns,
        .nr = nr,
        .pn = pn,
        .skipped_keys = std::move(skipped_store),
    };

    RatchetSession session{
        .peer_user_id = domain::UserId(peer_uid_str),
        .peer_device_id = domain::DeviceId(peer_did_str),
        .peer_identity_key = std::move(peer_ik),
        .ratchet_state = std::move(st),
        .initial_message_pending = init_pending,
        .pending_x3dh_header = std::move(x3dh_hdr),
        .established_at = std::chrono::system_clock::time_point(std::chrono::milliseconds(est_ms)),
        .last_active_at = std::chrono::system_clock::time_point(std::chrono::milliseconds(act_ms)),
    };

    return application::ClientResult<RatchetSession>::ok(std::move(session));
}

} // namespace securecloud::client::domain::crypto

