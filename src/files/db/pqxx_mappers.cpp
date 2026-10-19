#include "files/db/pqxx_mappers.hpp"

#include <algorithm>
#include <cctype>
#include <charconv>
#include <cstdio>
#include <iomanip>
#include <sstream>

namespace securecloud::files::db {

namespace {

// Howard Hinnant civil calendar algorithms (C++20 chrono standard)
int64_t days_from_civil(int y, unsigned m, unsigned d) noexcept {
    y -= m <= 2;
    const int era = (y >= 0 ? y : y - 399) / 400;
    const unsigned yoe = static_cast<unsigned>(y - era * 400);
    const unsigned doy = (153 * (m > 2 ? m - 3 : m + 9) + 2) / 5 + d - 1;
    const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + static_cast<int>(doe) - 719468;
}

void civil_from_days(int64_t days, int& out_y, unsigned& out_m, unsigned& out_d) noexcept {
    days += 719468;
    const int era = static_cast<int>((days >= 0 ? days : days - 146096) / 146097);
    const unsigned doe = static_cast<unsigned>(days - static_cast<int64_t>(era) * 146097);
    const unsigned yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    int y = static_cast<int>(yoe) + era * 400;
    const unsigned doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    const unsigned mp = (5 * doy + 2) / 153;
    const unsigned d = doy - (153 * mp + 2) / 5 + 1;
    const unsigned m = mp < 10 ? mp + 3 : mp - 9;
    y += (m <= 2);
    out_y = y;
    out_m = m;
    out_d = d;
}

int hex_char_to_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

} // namespace

// --- Strong Enum <-> String Conversions ---

std::string to_string(FileStatus status) {
    switch (status) {
        case FileStatus::Created: return "CREATED";
        case FileStatus::Uploading: return "UPLOADING";
        case FileStatus::Finalizing: return "FINALIZING";
        case FileStatus::Available: return "AVAILABLE";
        case FileStatus::Expired: return "EXPIRED";
        case FileStatus::Deleted: return "DELETED";
        case FileStatus::Failed: return "FAILED";
    }
    throw InvalidEnumException("Unknown FileStatus enum value: " + std::to_string(static_cast<int>(status)));
}

FileStatus file_status_from_string(std::string_view str) {
    if (str == "CREATED") return FileStatus::Created;
    if (str == "UPLOADING") return FileStatus::Uploading;
    if (str == "FINALIZING") return FileStatus::Finalizing;
    if (str == "AVAILABLE") return FileStatus::Available;
    if (str == "EXPIRED") return FileStatus::Expired;
    if (str == "DELETED") return FileStatus::Deleted;
    if (str == "FAILED") return FileStatus::Failed;
    throw InvalidEnumException("Invalid FileStatus string: " + std::string(str));
}

std::string to_string(TransferType type) {
    switch (type) {
        case TransferType::Upload: return "UPLOAD";
        case TransferType::Download: return "DOWNLOAD";
    }
    throw InvalidEnumException("Unknown TransferType enum value: " + std::to_string(static_cast<int>(type)));
}

TransferType transfer_type_from_string(std::string_view str) {
    if (str == "UPLOAD") return TransferType::Upload;
    if (str == "DOWNLOAD") return TransferType::Download;
    throw InvalidEnumException("Invalid TransferType string: " + std::string(str));
}

std::string to_string(TransferStatus status) {
    switch (status) {
        case TransferStatus::Created: return "CREATED";
        case TransferStatus::Transferring: return "TRANSFERRING";
        case TransferStatus::Finalizing: return "FINALIZING";
        case TransferStatus::Completed: return "COMPLETED";
        case TransferStatus::Failed: return "FAILED";
        case TransferStatus::Expired: return "EXPIRED";
        case TransferStatus::Cancelled: return "CANCELLED";
    }
    throw InvalidEnumException("Unknown TransferStatus enum value: " + std::to_string(static_cast<int>(status)));
}

TransferStatus transfer_status_from_string(std::string_view str) {
    if (str == "CREATED") return TransferStatus::Created;
    if (str == "TRANSFERRING") return TransferStatus::Transferring;
    if (str == "FINALIZING") return TransferStatus::Finalizing;
    if (str == "COMPLETED") return TransferStatus::Completed;
    if (str == "FAILED") return TransferStatus::Failed;
    if (str == "EXPIRED") return TransferStatus::Expired;
    if (str == "CANCELLED") return TransferStatus::Cancelled;
    throw InvalidEnumException("Invalid TransferStatus string: " + std::string(str));
}

std::string to_string(ChunkStatus status) {
    switch (status) {
        case ChunkStatus::Received: return "RECEIVED";
        case ChunkStatus::Committed: return "COMMITTED";
    }
    throw InvalidEnumException("Unknown ChunkStatus enum value: " + std::to_string(static_cast<int>(status)));
}

ChunkStatus chunk_status_from_string(std::string_view str) {
    if (str == "RECEIVED") return ChunkStatus::Received;
    if (str == "COMMITTED") return ChunkStatus::Committed;
    throw InvalidEnumException("Invalid ChunkStatus string: " + std::string(str));
}

std::string to_string(FilePermission permission) {
    switch (permission) {
        case FilePermission::Read: return "READ";
        case FilePermission::Write: return "WRITE";
        case FilePermission::Admin: return "ADMIN";
    }
    throw InvalidEnumException("Unknown FilePermission enum value: " + std::to_string(static_cast<int>(permission)));
}

FilePermission file_permission_from_string(std::string_view str) {
    if (str == "READ") return FilePermission::Read;
    if (str == "WRITE") return FilePermission::Write;
    if (str == "ADMIN") return FilePermission::Admin;
    throw InvalidEnumException("Invalid FilePermission string: " + std::string(str));
}

std::string to_string(OutboxStatus status) {
    switch (status) {
        case OutboxStatus::Pending: return "PENDING";
        case OutboxStatus::Published: return "PUBLISHED";
        case OutboxStatus::Failed: return "FAILED";
    }
    throw InvalidEnumException("Unknown OutboxStatus enum value: " + std::to_string(static_cast<int>(status)));
}

OutboxStatus outbox_status_from_string(std::string_view str) {
    if (str == "PENDING") return OutboxStatus::Pending;
    if (str == "PUBLISHED") return OutboxStatus::Published;
    if (str == "FAILED") return OutboxStatus::Failed;
    throw InvalidEnumException("Invalid OutboxStatus string: " + std::string(str));
}

// --- Timestamp Conversions ---

std::string to_iso8601(std::chrono::system_clock::time_point tp) {
    auto us = std::chrono::duration_cast<std::chrono::microseconds>(tp.time_since_epoch()).count();
    int64_t sec = us / 1000000;
    int64_t frac = us % 1000000;
    if (frac < 0) {
        frac += 1000000;
        sec -= 1;
    }

    int64_t days = sec / 86400;
    int64_t sec_in_day = sec % 86400;
    if (sec_in_day < 0) {
        sec_in_day += 86400;
        days -= 1;
    }

    int hour = static_cast<int>(sec_in_day / 3600);
    int minute = static_cast<int>((sec_in_day % 3600) / 60);
    int second = static_cast<int>(sec_in_day % 60);

    int y = 0;
    unsigned m = 0;
    unsigned d = 0;
    civil_from_days(days, y, m, d);

    char buf[64];
    if (frac == 0) {
        std::snprintf(buf, sizeof(buf), "%04d-%02u-%02uT%02d:%02d:%02dZ", y, m, d, hour, minute, second);
    } else {
        std::snprintf(buf, sizeof(buf), "%04d-%02u-%02uT%02d:%02d:%02d.%06lldZ",
                      y, m, d, hour, minute, second, static_cast<long long>(frac));
    }
    return std::string(buf);
}

std::chrono::system_clock::time_point from_iso8601(std::string_view str) {
    if (str.empty()) {
        throw TimestampParseException("Empty timestamp string");
    }

    // Expected format: YYYY-MM-DD[T ]HH:MM:SS[.ffffff][Z|(+|-)HH[:MM]]
    if (str.size() < 19) {
        throw TimestampParseException("Timestamp string too short: " + std::string(str));
    }

    int year = 0;
    unsigned month = 0;
    unsigned day = 0;
    int hour = 0;
    int minute = 0;
    int second = 0;

    auto parse_int = [](std::string_view s) -> int {
        int val = 0;
        for (char c : s) {
            if (c < '0' || c > '9') {
                throw TimestampParseException("Invalid digit in timestamp: " + std::string(s));
            }
            val = val * 10 + (c - '0');
        }
        return val;
    };

    if (str[4] != '-' || str[7] != '-') {
        throw TimestampParseException("Invalid date separator in timestamp: " + std::string(str));
    }

    year = parse_int(str.substr(0, 4));
    month = static_cast<unsigned>(parse_int(str.substr(5, 2)));
    day = static_cast<unsigned>(parse_int(str.substr(8, 2)));

    if (month < 1 || month > 12 || day < 1 || day > 31) {
        throw TimestampParseException("Date values out of range in timestamp: " + std::string(str));
    }

    char sep = str[10];
    if (sep != 'T' && sep != ' ' && sep != 't') {
        throw TimestampParseException("Invalid date/time separator in timestamp: " + std::string(str));
    }

    if (str[13] != ':' || str[16] != ':') {
        throw TimestampParseException("Invalid time separator in timestamp: " + std::string(str));
    }

    hour = parse_int(str.substr(11, 2));
    minute = parse_int(str.substr(14, 2));
    second = parse_int(str.substr(17, 2));

    if (hour < 0 || hour > 23 || minute < 0 || minute > 59 || second < 0 || second > 60) {
        throw TimestampParseException("Time values out of range in timestamp: " + std::string(str));
    }

    size_t pos = 19;
    int64_t microsec = 0;

    // Optional fractional seconds
    if (pos < str.size() && str[pos] == '.') {
        pos++;
        size_t frac_start = pos;
        while (pos < str.size() && std::isdigit(static_cast<unsigned char>(str[pos]))) {
            pos++;
        }
        std::string_view frac_part = str.substr(frac_start, pos - frac_start);
        if (frac_part.empty()) {
            throw TimestampParseException("Missing fractional digits after decimal point: " + std::string(str));
        }

        // Standardize to 6 digits (microseconds)
        int64_t factor = 100000;
        for (size_t i = 0; i < frac_part.size() && i < 6; ++i) {
            microsec += (frac_part[i] - '0') * factor;
            factor /= 10;
        }
    }

    int tz_offset_seconds = 0;
    if (pos < str.size()) {
        std::string_view tz = str.substr(pos);
        if (tz == "Z" || tz == "z") {
            tz_offset_seconds = 0;
        } else if (tz[0] == '+' || tz[0] == '-') {
            int sign = (tz[0] == '+') ? 1 : -1;
            std::string_view tz_digits = tz.substr(1);
            int tz_h = 0;
            int tz_m = 0;
            if (tz_digits.size() == 2) {
                tz_h = parse_int(tz_digits);
            } else if (tz_digits.size() == 5 && tz_digits[2] == ':') {
                tz_h = parse_int(tz_digits.substr(0, 2));
                tz_m = parse_int(tz_digits.substr(3, 2));
            } else if (tz_digits.size() == 4) {
                tz_h = parse_int(tz_digits.substr(0, 2));
                tz_m = parse_int(tz_digits.substr(2, 2));
            } else {
                throw TimestampParseException("Malformed timezone in timestamp: " + std::string(str));
            }
            tz_offset_seconds = sign * (tz_h * 3600 + tz_m * 60);
        } else {
            throw TimestampParseException("Unrecognized timezone specification: " + std::string(tz));
        }
    }

    int64_t days = days_from_civil(year, month, day);
    int64_t total_sec = days * 86400 + hour * 3600 + minute * 60 + second - tz_offset_seconds;
    int64_t total_us = total_sec * 1000000 + microsec;

    return std::chrono::system_clock::time_point(std::chrono::microseconds(total_us));
}

// --- PostgreSQL Bytea Conversions ---

std::string to_bytea_hex(const std::vector<uint8_t>& bytes) {
    static const char hex_digits[] = "0123456789abcdef";
    std::string out = "\\x";
    out.reserve(2 + bytes.size() * 2);
    for (uint8_t b : bytes) {
        out.push_back(hex_digits[(b >> 4) & 0x0F]);
        out.push_back(hex_digits[b & 0x0F]);
    }
    return out;
}

std::vector<uint8_t> from_bytea_hex(std::string_view hex_str) {
    if (hex_str.empty()) {
        return {};
    }

    if (hex_str.rfind("\\x", 0) == 0) {
        hex_str.remove_prefix(2);
    } else if (hex_str.rfind("\\\\x", 0) == 0) {
        hex_str.remove_prefix(3);
    }

    if (hex_str.size() % 2 != 0) {
        throw ByteaParseException("Bytea hex string has odd length: " + std::to_string(hex_str.size()));
    }

    std::vector<uint8_t> result;
    result.reserve(hex_str.size() / 2);

    for (size_t i = 0; i < hex_str.size(); i += 2) {
        int hi = hex_char_to_val(hex_str[i]);
        int lo = hex_char_to_val(hex_str[i + 1]);
        if (hi < 0 || lo < 0) {
            throw ByteaParseException("Invalid hex character in bytea string: " + std::string(hex_str.substr(i, 2)));
        }
        result.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }

    return result;
}

// --- Entity Row Mappers ---

FileEntity file_from_row(const pqxx::row& row) {
    FileEntity entity;
    entity.file_id = row["file_id"].as<std::string>();
    entity.owner_user_id = row["owner_user_id"].as<std::string>();
    entity.owner_device_id = row["owner_device_id"].as<std::string>();

    if (!row["conversation_id"].is_null()) {
        entity.conversation_id = row["conversation_id"].as<std::string>();
    }
    entity.encrypted_size = row["encrypted_size"].as<int64_t>();
    if (!row["content_type"].is_null()) {
        entity.content_type = row["content_type"].as<std::string>();
    }
    entity.encryption_algorithm = row["encryption_algorithm"].as<std::string>();
    entity.status = file_status_from_string(row["status"].as<std::string>());
    if (!row["retention_until"].is_null()) {
        entity.retention_until = from_iso8601(row["retention_until"].as<std::string>());
    }
    entity.created_at = from_iso8601(row["created_at"].as<std::string>());
    entity.updated_at = from_iso8601(row["updated_at"].as<std::string>());
    return entity;
}

FileVersionEntity file_version_from_row(const pqxx::row& row) {
    FileVersionEntity entity;
    entity.version_id = row["version_id"].as<std::string>();
    entity.file_id = row["file_id"].as<std::string>();
    entity.version_number = row["version_number"].as<int32_t>();
    entity.encrypted_size = row["encrypted_size"].as<int64_t>();
    entity.minio_object_key = row["minio_object_key"].as<std::string>();
    entity.checksum_sha256 = row["checksum_sha256"].as<std::string>();
    entity.created_at = from_iso8601(row["created_at"].as<std::string>());
    entity.is_active = row["is_active"].as<bool>();
    return entity;
}

EncryptedFileMetadataEntity encrypted_metadata_from_row(const pqxx::row& row) {
    EncryptedFileMetadataEntity entity;
    entity.file_id = row["file_id"].as<std::string>();
    entity.encrypted_filename = from_bytea_hex(row["encrypted_filename"].as<std::string>());
    if (!row["encrypted_mime_type"].is_null()) {
        entity.encrypted_mime_type = from_bytea_hex(row["encrypted_mime_type"].as<std::string>());
    }
    entity.metadata_nonce = from_bytea_hex(row["metadata_nonce"].as<std::string>());
    entity.metadata_tag = from_bytea_hex(row["metadata_tag"].as<std::string>());
    entity.client_encryption_metadata_json = row["client_encryption_metadata"].as<std::string>();
    entity.updated_at = from_iso8601(row["updated_at"].as<std::string>());
    return entity;
}

FileTransferEntity file_transfer_from_row(const pqxx::row& row) {
    FileTransferEntity entity;
    entity.transfer_id = row["transfer_id"].as<std::string>();
    entity.file_id = row["file_id"].as<std::string>();
    entity.transfer_type = transfer_type_from_string(row["transfer_type"].as<std::string>());
    entity.initiator_user_id = row["initiator_user_id"].as<std::string>();
    entity.initiator_device_id = row["initiator_device_id"].as<std::string>();
    entity.status = transfer_status_from_string(row["status"].as<std::string>());
    entity.total_chunks = row["total_chunks"].as<int32_t>();
    entity.accepted_chunks = row["accepted_chunks"].as<int32_t>();
    entity.total_bytes = row["total_bytes"].as<int64_t>();
    entity.transferred_bytes = row["transferred_bytes"].as<int64_t>();
    entity.created_at = from_iso8601(row["created_at"].as<std::string>());
    entity.updated_at = from_iso8601(row["updated_at"].as<std::string>());
    entity.expires_at = from_iso8601(row["expires_at"].as<std::string>());
    return entity;
}

FileChunkEntity file_chunk_from_row(const pqxx::row& row) {
    FileChunkEntity entity;
    entity.chunk_id = row["chunk_id"].as<std::string>();
    entity.transfer_id = row["transfer_id"].as<std::string>();
    entity.chunk_index = row["chunk_index"].as<int32_t>();
    entity.byte_offset = row["byte_offset"].as<int64_t>();
    entity.chunk_size = row["chunk_size"].as<int32_t>();
    entity.chunk_hash_sha256 = row["chunk_hash_sha256"].as<std::string>();
    entity.minio_chunk_key = row["minio_chunk_key"].as<std::string>();
    entity.status = chunk_status_from_string(row["status"].as<std::string>());
    entity.created_at = from_iso8601(row["created_at"].as<std::string>());
    return entity;
}

FileAccessEntity file_access_from_row(const pqxx::row& row) {
    FileAccessEntity entity;
    entity.access_id = row["access_id"].as<std::string>();
    entity.file_id = row["file_id"].as<std::string>();
    entity.grantee_user_id = row["grantee_user_id"].as<std::string>();
    if (!row["grantee_device_id"].is_null()) {
        entity.grantee_device_id = row["grantee_device_id"].as<std::string>();
    }
    entity.permission = file_permission_from_string(row["permission"].as<std::string>());
    entity.granted_by = row["granted_by"].as<std::string>();
    entity.granted_at = from_iso8601(row["granted_at"].as<std::string>());
    if (!row["revoked_at"].is_null()) {
        entity.revoked_at = from_iso8601(row["revoked_at"].as<std::string>());
    }
    return entity;
}

FilesOutboxEntity files_outbox_from_row(const pqxx::row& row) {
    FilesOutboxEntity entity;
    entity.event_id = row["event_id"].as<std::string>();
    entity.aggregate_type = row["aggregate_type"].as<std::string>();
    entity.aggregate_id = row["aggregate_id"].as<std::string>();
    entity.event_type = row["event_type"].as<std::string>();
    entity.payload_json = row["payload_json"].as<std::string>();
    entity.status = outbox_status_from_string(row["status"].as<std::string>());
    entity.retry_count = row["retry_count"].as<int32_t>();
    entity.created_at = from_iso8601(row["created_at"].as<std::string>());
    if (!row["processed_at"].is_null()) {
        entity.processed_at = from_iso8601(row["processed_at"].as<std::string>());
    }
    return entity;
}

// --- Test Helper Row Builder ---

RowBuilder& RowBuilder::set(std::string name, std::string value) {
    columns_.emplace_back(std::move(name), std::move(value));
    return *this;
}

RowBuilder& RowBuilder::set_null(std::string name) {
    columns_.emplace_back(std::move(name), std::nullopt);
    return *this;
}

pqxx::row RowBuilder::build() const {
#if !defined(SECURECLOUD_FILES_USE_REAL_PQXX) || !__has_include(<pqxx/pqxx>)
    std::vector<pqxx::field> fields;
    std::map<std::string, size_t> name_map;
    fields.reserve(columns_.size());
    for (size_t i = 0; i < columns_.size(); ++i) {
        const auto& [name, val] = columns_[i];
        name_map[name] = i;
        fields.emplace_back(val, name);
    }
    return pqxx::row(std::move(fields), std::move(name_map));
#else
    throw std::runtime_error("RowBuilder not supported with bundled libpqxx without active connection");
#endif
}

} // namespace securecloud::files::db
