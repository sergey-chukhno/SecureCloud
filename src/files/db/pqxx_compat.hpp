#pragma once

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#if __has_include(<pqxx/pqxx>)
#include <pqxx/pqxx>
#else

namespace pqxx {

/// Lightweight abstraction for a PostgreSQL row field when libpqxx is not bundled.
class field {
public:
    field() = default;
    explicit field(std::optional<std::string> value, std::string name = "")
        : value_(std::move(value)), name_(std::move(name)) {}

    [[nodiscard]] bool is_null() const noexcept {
        return !value_.has_value();
    }

    [[nodiscard]] const char* c_str() const {
        return value_ ? value_->c_str() : "";
    }

    [[nodiscard]] std::string_view view() const {
        return value_ ? std::string_view(*value_) : std::string_view();
    }

    [[nodiscard]] const std::string& name() const noexcept {
        return name_;
    }

    template <typename T>
    T as() const {
        if (is_null()) {
            throw std::runtime_error("Attempted to read non-nullable field from SQL NULL: " + name_);
        }

        if constexpr (std::is_same_v<T, std::string>) {
            return *value_;
        } else if constexpr (std::is_same_v<T, int32_t>) {
            return static_cast<int32_t>(std::stol(*value_));
        } else if constexpr (std::is_same_v<T, int64_t>) {
            return static_cast<int64_t>(std::stoll(*value_));
        } else if constexpr (std::is_same_v<T, uint32_t>) {
            return static_cast<uint32_t>(std::stoul(*value_));
        } else if constexpr (std::is_same_v<T, uint64_t>) {
            return static_cast<uint64_t>(std::stoull(*value_));
        } else if constexpr (std::is_same_v<T, bool>) {
            if (*value_ == "t" || *value_ == "true" || *value_ == "TRUE" || *value_ == "1") {
                return true;
            }
            if (*value_ == "f" || *value_ == "false" || *value_ == "FALSE" || *value_ == "0") {
                return false;
            }
            throw std::runtime_error("Invalid boolean value in field: " + *value_);
        } else {
            static_assert(!sizeof(T), "Unsupported type for pqxx::field::as<T>()");
        }
    }

private:
    std::optional<std::string> value_{std::nullopt};
    std::string name_;
};

/// Lightweight abstraction for a PostgreSQL row when libpqxx is not bundled.
class row {
public:
    row() = default;
    row(std::vector<field> fields, std::map<std::string, size_t> name_map)
        : fields_(std::move(fields)), name_map_(std::move(name_map)) {}

    [[nodiscard]] size_t size() const noexcept {
        return fields_.size();
    }

    [[nodiscard]] bool empty() const noexcept {
        return fields_.empty();
    }

    [[nodiscard]] const field& operator[](size_t index) const {
        if (index >= fields_.size()) {
            throw std::out_of_range("Column index out of range: " + std::to_string(index));
        }
        return fields_[index];
    }

    [[nodiscard]] const field& operator[](int index) const {
        if (index < 0 || static_cast<size_t>(index) >= fields_.size()) {
            throw std::out_of_range("Column index out of range: " + std::to_string(index));
        }
        return fields_[static_cast<size_t>(index)];
    }

    [[nodiscard]] const field& operator[](std::string_view name) const {
        auto it = name_map_.find(std::string(name));
        if (it == name_map_.end()) {
            throw std::out_of_range("Column name not found in row: " + std::string(name));
        }
        return fields_[it->second];
    }

    [[nodiscard]] const field& operator[](const char* name) const {
        return (*this)[std::string_view(name)];
    }

    [[nodiscard]] bool has_column(std::string_view name) const noexcept {
        return name_map_.find(std::string(name)) != name_map_.end();
    }

private:
    std::vector<field> fields_;
    std::map<std::string, size_t> name_map_;
};

/// Lightweight abstraction for PostgreSQL query result when libpqxx is not bundled.
class result {
public:
    result() = default;
    explicit result(std::vector<row> rows, size_t affected_rows = 0)
        : rows_(std::move(rows)), affected_rows_(affected_rows) {}

    [[nodiscard]] size_t size() const noexcept {
        return rows_.size();
    }

    [[nodiscard]] bool empty() const noexcept {
        return rows_.empty();
    }

    [[nodiscard]] const row& operator[](size_t index) const {
        return rows_.at(index);
    }

    [[nodiscard]] const row& at(size_t index) const {
        return rows_.at(index);
    }

    [[nodiscard]] size_t affected_rows() const noexcept {
        return affected_rows_;
    }

    [[nodiscard]] auto begin() const noexcept {
        return rows_.begin();
    }

    [[nodiscard]] auto end() const noexcept {
        return rows_.end();
    }

private:
    std::vector<row> rows_;
    size_t affected_rows_{0};
};

/// In-memory mock database store supporting unit test verification of SQL repositories
class MockStorage {
public:
    static MockStorage& instance() {
        static MockStorage s_instance;
        return s_instance;
    }

    void reset() {
        std::lock_guard<std::mutex> lock(mutex_);
        files_.clear();
        metadata_.clear();
        versions_.clear();
        transfers_.clear();
        chunks_.clear();
    }

    // Tables data structures
    struct StoredFile {
        std::string file_id;
        std::string owner_user_id;
        std::string owner_device_id;
        std::optional<std::string> conversation_id;
        std::string encrypted_size;
        std::optional<std::string> content_type;
        std::string encryption_algorithm;
        std::string status;
        std::optional<std::string> retention_until;
        std::string created_at;
        std::string updated_at;
    };

    struct StoredMetadata {
        std::string file_id;
        std::string encrypted_filename;
        std::optional<std::string> encrypted_mime_type;
        std::string metadata_nonce;
        std::string metadata_tag;
        std::string client_encryption_metadata;
        std::string updated_at;
    };

    struct StoredVersion {
        std::string version_id;
        std::string file_id;
        int32_t version_number{1};
        std::string encrypted_size;
        std::string minio_object_key;
        std::string checksum_sha256;
        std::string created_at;
        bool is_active{true};
    };

    struct StoredTransfer {
        std::string transfer_id;
        std::string file_id;
        std::string transfer_type;
        std::string initiator_user_id;
        std::string initiator_device_id;
        std::string status;
        int32_t total_chunks{0};
        int32_t accepted_chunks{0};
        int64_t total_bytes{0};
        int64_t transferred_bytes{0};
        std::string created_at;
        std::string updated_at;
        std::string expires_at;
    };

    struct StoredChunk {
        std::string chunk_id;
        std::string transfer_id;
        int32_t chunk_index{0};
        int64_t byte_offset{0};
        int32_t chunk_size{0};
        std::string chunk_hash_sha256;
        std::string minio_chunk_key;
        std::string status;
        std::string created_at;
    };

    std::mutex mutex_;
    std::map<std::string, StoredFile> files_;
    std::map<std::string, StoredMetadata> metadata_;
    std::map<std::pair<std::string, int32_t>, StoredVersion> versions_;
    std::map<std::string, StoredTransfer> transfers_;
    std::map<std::pair<std::string, int32_t>, StoredChunk> chunks_;
};

/// RAII transaction handle abstraction (compatible with pqxx::work)
class work {
public:
    work() = default;

    ~work() {
        if (!committed_) {
            abort();
        }
    }

    work(const work&) = delete;
    work& operator=(const work&) = delete;

    work(work&& other) noexcept
        : committed_(other.committed_),
          staged_files_(std::move(other.staged_files_)),
          staged_metadata_(std::move(other.staged_metadata_)),
          staged_versions_(std::move(other.staged_versions_)),
          staged_transfers_(std::move(other.staged_transfers_)),
          staged_chunks_(std::move(other.staged_chunks_)) {
        other.committed_ = true;
    }

    work& operator=(work&& other) noexcept {
        if (this != &other) {
            if (!committed_) abort();
            committed_ = other.committed_;
            staged_files_ = std::move(other.staged_files_);
            staged_metadata_ = std::move(other.staged_metadata_);
            staged_versions_ = std::move(other.staged_versions_);
            staged_transfers_ = std::move(other.staged_transfers_);
            staged_chunks_ = std::move(other.staged_chunks_);
            other.committed_ = true;
        }
        return *this;
    }

    template <typename... Args>
    result exec_params(std::string_view query, Args&&... args) {
        std::vector<std::optional<std::string>> params;
        params.reserve(sizeof...(args));
        (params.push_back(to_string_param(std::forward<Args>(args))), ...);
        return execute(query, params);
    }

    result exec(std::string_view query) {
        return execute(query, {});
    }

    void commit() {
        if (committed_) return;
        auto& store = MockStorage::instance();
        std::lock_guard<std::mutex> lock(store.mutex_);

        for (auto& [id, file] : staged_files_) {
            store.files_[id] = std::move(file);
        }
        for (auto& [id, meta] : staged_metadata_) {
            store.metadata_[id] = std::move(meta);
        }
        for (auto& [key, ver] : staged_versions_) {
            store.versions_[key] = std::move(ver);
        }
        for (auto& [id, trans] : staged_transfers_) {
            store.transfers_[id] = std::move(trans);
        }
        for (auto& [key, chunk] : staged_chunks_) {
            store.chunks_[key] = std::move(chunk);
        }

        staged_files_.clear();
        staged_metadata_.clear();
        staged_versions_.clear();
        staged_transfers_.clear();
        staged_chunks_.clear();
        committed_ = true;
    }

    void abort() {
        staged_files_.clear();
        staged_metadata_.clear();
        staged_versions_.clear();
        staged_transfers_.clear();
        staged_chunks_.clear();
        committed_ = true;
    }

private:
    template <typename T>
    static std::optional<std::string> to_string_param(const T& val) {
        if constexpr (std::is_same_v<T, std::nullopt_t>) {
            return std::nullopt;
        } else if constexpr (std::is_same_v<T, std::string>) {
            return val;
        } else if constexpr (std::is_same_v<T, const char*>) {
            return val ? std::make_optional(std::string(val)) : std::nullopt;
        } else if constexpr (std::is_same_v<T, std::string_view>) {
            return std::string(val);
        } else if constexpr (std::is_same_v<T, bool>) {
            return val ? "t" : "f";
        } else if constexpr (std::is_arithmetic_v<T>) {
            return std::to_string(val);
        } else if constexpr (requires { val.has_value(); }) { // optional
            if (!val.has_value()) return std::nullopt;
            return to_string_param(*val);
        } else {
            return std::nullopt;
        }
    }

    static row build_file_row(const MockStorage::StoredFile& f) {
        std::vector<field> fields;
        std::map<std::string, size_t> map;
        auto add = [&](std::string name, std::optional<std::string> val) {
            map[name] = fields.size();
            fields.emplace_back(std::move(val), std::move(name));
        };
        add("file_id", f.file_id);
        add("owner_user_id", f.owner_user_id);
        add("owner_device_id", f.owner_device_id);
        add("conversation_id", f.conversation_id);
        add("encrypted_size", f.encrypted_size);
        add("content_type", f.content_type);
        add("encryption_algorithm", f.encryption_algorithm);
        add("status", f.status);
        add("retention_until", f.retention_until);
        add("created_at", f.created_at);
        add("updated_at", f.updated_at);
        return row(std::move(fields), std::move(map));
    }

    static row build_metadata_row(const MockStorage::StoredMetadata& m) {
        std::vector<field> fields;
        std::map<std::string, size_t> map;
        auto add = [&](std::string name, std::optional<std::string> val) {
            map[name] = fields.size();
            fields.emplace_back(std::move(val), std::move(name));
        };
        add("file_id", m.file_id);
        add("encrypted_filename", m.encrypted_filename);
        add("encrypted_mime_type", m.encrypted_mime_type);
        add("metadata_nonce", m.metadata_nonce);
        add("metadata_tag", m.metadata_tag);
        add("client_encryption_metadata", m.client_encryption_metadata);
        add("updated_at", m.updated_at);
        return row(std::move(fields), std::move(map));
    }

    static row build_version_row(const MockStorage::StoredVersion& v) {
        std::vector<field> fields;
        std::map<std::string, size_t> map;
        auto add = [&](std::string name, std::optional<std::string> val) {
            map[name] = fields.size();
            fields.emplace_back(std::move(val), std::move(name));
        };
        add("version_id", v.version_id);
        add("file_id", v.file_id);
        add("version_number", std::to_string(v.version_number));
        add("encrypted_size", v.encrypted_size);
        add("minio_object_key", v.minio_object_key);
        add("checksum_sha256", v.checksum_sha256);
        add("created_at", v.created_at);
        add("is_active", v.is_active ? "t" : "f");
        return row(std::move(fields), std::move(map));
    }

    static row build_transfer_row(const MockStorage::StoredTransfer& t) {
        std::vector<field> fields;
        std::map<std::string, size_t> map;
        auto add = [&](std::string name, std::optional<std::string> val) {
            map[name] = fields.size();
            fields.emplace_back(std::move(val), std::move(name));
        };
        add("transfer_id", t.transfer_id);
        add("file_id", t.file_id);
        add("transfer_type", t.transfer_type);
        add("initiator_user_id", t.initiator_user_id);
        add("initiator_device_id", t.initiator_device_id);
        add("status", t.status);
        add("total_chunks", std::to_string(t.total_chunks));
        add("accepted_chunks", std::to_string(t.accepted_chunks));
        add("total_bytes", std::to_string(t.total_bytes));
        add("transferred_bytes", std::to_string(t.transferred_bytes));
        add("created_at", t.created_at);
        add("updated_at", t.updated_at);
        add("expires_at", t.expires_at);
        return row(std::move(fields), std::move(map));
    }

    static row build_chunk_row(const MockStorage::StoredChunk& c) {
        std::vector<field> fields;
        std::map<std::string, size_t> map;
        auto add = [&](std::string name, std::optional<std::string> val) {
            map[name] = fields.size();
            fields.emplace_back(std::move(val), std::move(name));
        };
        add("chunk_id", c.chunk_id);
        add("transfer_id", c.transfer_id);
        add("chunk_index", std::to_string(c.chunk_index));
        add("byte_offset", std::to_string(c.byte_offset));
        add("chunk_size", std::to_string(c.chunk_size));
        add("chunk_hash_sha256", c.chunk_hash_sha256);
        add("minio_chunk_key", c.minio_chunk_key);
        add("status", c.status);
        add("created_at", c.created_at);
        return row(std::move(fields), std::move(map));
    }

    result execute(std::string_view query, const std::vector<std::optional<std::string>>& params) {
        auto& store = MockStorage::instance();
        std::lock_guard<std::mutex> lock(store.mutex_);

        // 1. INSERT INTO files
        if (query.find("INSERT INTO files") != std::string_view::npos) {
            MockStorage::StoredFile f;
            f.file_id = params[0].value_or("");
            f.owner_user_id = params[1].value_or("");
            f.owner_device_id = params[2].value_or("");
            f.conversation_id = params[3];
            f.encrypted_size = params[4].value_or("0");
            f.content_type = params[5];
            f.encryption_algorithm = params[6].value_or("XChaCha20-Poly1305");
            f.status = params[7].value_or("CREATED");
            f.retention_until = params[8];
            f.created_at = params[9].value_or("");
            f.updated_at = params[10].value_or("");
            staged_files_[f.file_id] = f;
            return result({}, 1);
        }

        // 2. INSERT INTO encrypted_file_metadata
        if (query.find("INSERT INTO encrypted_file_metadata") != std::string_view::npos) {
            MockStorage::StoredMetadata m;
            m.file_id = params[0].value_or("");
            m.encrypted_filename = params[1].value_or("");
            m.encrypted_mime_type = params[2];
            m.metadata_nonce = params[3].value_or("");
            m.metadata_tag = params[4].value_or("");
            m.client_encryption_metadata = params[5].value_or("{}");
            m.updated_at = params[6].value_or("");
            staged_metadata_[m.file_id] = m;
            return result({}, 1);
        }

        // 3. SELECT ... FROM files WHERE file_id = $1
        if (query.find("FROM files WHERE file_id = $1") != std::string_view::npos) {
            std::string id = params.empty() ? "" : params[0].value_or("");
            if (staged_files_.find(id) != staged_files_.end()) {
                return result({build_file_row(staged_files_[id])}, 1);
            }
            if (store.files_.find(id) != store.files_.end()) {
                return result({build_file_row(store.files_[id])}, 1);
            }
            return result({}, 0);
        }

        // 4. SELECT ... FROM encrypted_file_metadata WHERE file_id = $1
        if (query.find("FROM encrypted_file_metadata WHERE file_id = $1") != std::string_view::npos) {
            std::string id = params.empty() ? "" : params[0].value_or("");
            if (staged_metadata_.find(id) != staged_metadata_.end()) {
                return result({build_metadata_row(staged_metadata_[id])}, 1);
            }
            if (store.metadata_.find(id) != store.metadata_.end()) {
                return result({build_metadata_row(store.metadata_[id])}, 1);
            }
            return result({}, 0);
        }

        // 5. UPDATE files SET status = $1, updated_at = $2 WHERE file_id = $3 AND status = $4
        if (query.find("UPDATE files SET status = $1, updated_at = $2 WHERE file_id = $3 AND status = $4") != std::string_view::npos) {
            std::string new_status = params[0].value_or("");
            std::string updated_at = params[1].value_or("");
            std::string file_id = params[2].value_or("");
            std::string exp_status = params[3].value_or("");

            MockStorage::StoredFile* f = nullptr;
            if (staged_files_.find(file_id) != staged_files_.end()) {
                f = &staged_files_[file_id];
            } else if (store.files_.find(file_id) != store.files_.end()) {
                staged_files_[file_id] = store.files_[file_id];
                f = &staged_files_[file_id];
            }

            if (f && f->status == exp_status) {
                f->status = new_status;
                f->updated_at = updated_at;
                return result({}, 1);
            }
            return result({}, 0);
        }

        // 6. UPDATE files SET status = 'DELETED', updated_at = $1 WHERE file_id = $2
        if (query.find("UPDATE files SET status = 'DELETED'") != std::string_view::npos) {
            std::string updated_at = params[0].value_or("");
            std::string file_id = params[1].value_or("");

            MockStorage::StoredFile* f = nullptr;
            if (staged_files_.find(file_id) != staged_files_.end()) {
                f = &staged_files_[file_id];
            } else if (store.files_.find(file_id) != store.files_.end()) {
                staged_files_[file_id] = store.files_[file_id];
                f = &staged_files_[file_id];
            }

            if (f) {
                f->status = "DELETED";
                f->updated_at = updated_at;
                return result({}, 1);
            }
            return result({}, 0);
        }

        // 7. SELECT ... FROM files WHERE retention_until <= $1 AND status != 'DELETED'
        if (query.find("WHERE retention_until IS NOT NULL AND retention_until <= $1") != std::string_view::npos) {
            std::string now_str = params[0].value_or("");
            size_t limit = params.size() > 1 ? static_cast<size_t>(std::stoul(params[1].value_or("100"))) : 100;

            std::map<std::string, MockStorage::StoredFile> all_files = store.files_;
            for (const auto& [id, f] : staged_files_) {
                all_files[id] = f;
            }

            std::vector<MockStorage::StoredFile> expired;
            for (const auto& [id, f] : all_files) {
                if (f.retention_until.has_value() && *f.retention_until <= now_str && f.status != "DELETED") {
                    expired.push_back(f);
                }
            }

            std::sort(expired.begin(), expired.end(), [](const auto& a, const auto& b) {
                return *a.retention_until < *b.retention_until;
            });

            if (expired.size() > limit) {
                expired.resize(limit);
            }

            std::vector<row> rows;
            for (const auto& f : expired) {
                rows.push_back(build_file_row(f));
            }
            return result(std::move(rows), rows.size());
        }

        // 8. INSERT INTO file_versions
        if (query.find("INSERT INTO file_versions") != std::string_view::npos) {
            MockStorage::StoredVersion v;
            v.version_id = params[0].value_or("");
            v.file_id = params[1].value_or("");
            v.version_number = std::stoi(params[2].value_or("1"));
            v.encrypted_size = params[3].value_or("0");
            v.minio_object_key = params[4].value_or("");
            v.checksum_sha256 = params[5].value_or("");
            v.created_at = params[6].value_or("");
            v.is_active = (params[7].value_or("t") == "t");

            auto key = std::make_pair(v.file_id, v.version_number);
            if (staged_versions_.find(key) != staged_versions_.end() ||
                store.versions_.find(key) != store.versions_.end()) {
                throw std::runtime_error("UNIQUE constraint violation: uq_file_version");
            }
            staged_versions_[key] = v;
            return result({}, 1);
        }

        // 9. UPDATE file_versions SET is_active = FALSE WHERE file_id = $1 AND version_number != $2
        if (query.find("UPDATE file_versions SET is_active = FALSE") != std::string_view::npos) {
            std::string file_id = params[0].value_or("");
            int32_t ver_num = std::stoi(params[1].value_or("0"));

            size_t count = 0;
            for (auto& [key, ver] : store.versions_) {
                if (key.first == file_id && key.second != ver_num && ver.is_active) {
                    ver.is_active = false;
                    staged_versions_[key] = ver;
                    count++;
                }
            }
            for (auto& [key, ver] : staged_versions_) {
                if (key.first == file_id && key.second != ver_num && ver.is_active) {
                    ver.is_active = false;
                    count++;
                }
            }
            return result({}, count);
        }

        // 10. SELECT ... FROM file_versions WHERE file_id = $1 AND is_active = TRUE
        if (query.find("FROM file_versions WHERE file_id = $1 AND is_active = TRUE") != std::string_view::npos) {
            std::string file_id = params[0].value_or("");

            std::map<std::pair<std::string, int32_t>, MockStorage::StoredVersion> all_vers = store.versions_;
            for (const auto& [k, v] : staged_versions_) {
                all_vers[k] = v;
            }

            std::optional<MockStorage::StoredVersion> active_ver;
            for (const auto& [k, v] : all_vers) {
                if (k.first == file_id && v.is_active) {
                    if (!active_ver || v.version_number > active_ver->version_number) {
                        active_ver = v;
                    }
                }
            }

            if (active_ver) {
                return result({build_version_row(*active_ver)}, 1);
            }
            return result({}, 0);
        }

        // 11. SELECT ... FROM file_versions WHERE file_id = $1 ORDER BY version_number ASC
        if (query.find("FROM file_versions WHERE file_id = $1 ORDER BY version_number") != std::string_view::npos) {
            std::string file_id = params[0].value_or("");

            std::map<std::pair<std::string, int32_t>, MockStorage::StoredVersion> all_vers = store.versions_;
            for (const auto& [k, v] : staged_versions_) {
                all_vers[k] = v;
            }

            std::vector<MockStorage::StoredVersion> matching;
            for (const auto& [k, v] : all_vers) {
                if (k.first == file_id) {
                    matching.push_back(v);
                }
            }

            std::sort(matching.begin(), matching.end(), [](const auto& a, const auto& b) {
                return a.version_number < b.version_number;
            });

            std::vector<row> rows;
            for (const auto& v : matching) {
                rows.push_back(build_version_row(v));
            }
            return result(std::move(rows), rows.size());
        }

        // 12. INSERT INTO file_transfers
        if (query.find("INSERT INTO file_transfers") != std::string_view::npos) {
            MockStorage::StoredTransfer t;
            t.transfer_id = params[0].value_or("");
            t.file_id = params[1].value_or("");
            t.transfer_type = params[2].value_or("UPLOAD");
            t.initiator_user_id = params[3].value_or("");
            t.initiator_device_id = params[4].value_or("");
            t.status = params[5].value_or("CREATED");
            t.total_chunks = std::stoi(params[6].value_or("0"));
            t.accepted_chunks = std::stoi(params[7].value_or("0"));
            t.total_bytes = std::stoll(params[8].value_or("0"));
            t.transferred_bytes = std::stoll(params[9].value_or("0"));
            t.created_at = params[10].value_or("");
            t.updated_at = params[11].value_or("");
            t.expires_at = params[12].value_or("");
            staged_transfers_[t.transfer_id] = t;
            return result({}, 1);
        }

        // 13. SELECT ... FROM file_transfers WHERE transfer_id = $1
        if (query.find("FROM file_transfers WHERE transfer_id = $1") != std::string_view::npos) {
            std::string id = params.empty() ? "" : params[0].value_or("");
            if (staged_transfers_.find(id) != staged_transfers_.end()) {
                return result({build_transfer_row(staged_transfers_[id])}, 1);
            }
            if (store.transfers_.find(id) != store.transfers_.end()) {
                return result({build_transfer_row(store.transfers_[id])}, 1);
            }
            return result({}, 0);
        }

        // 14. UPDATE file_transfers SET status = $1, updated_at = $2 WHERE transfer_id = $3
        if (query.find("UPDATE file_transfers SET status = $1") != std::string_view::npos) {
            std::string new_status = params[0].value_or("");
            std::string updated_at = params[1].value_or("");
            std::string transfer_id = params[2].value_or("");

            MockStorage::StoredTransfer* t = nullptr;
            if (staged_transfers_.find(transfer_id) != staged_transfers_.end()) {
                t = &staged_transfers_[transfer_id];
            } else if (store.transfers_.find(transfer_id) != store.transfers_.end()) {
                staged_transfers_[transfer_id] = store.transfers_[transfer_id];
                t = &staged_transfers_[transfer_id];
            }

            if (t) {
                t->status = new_status;
                t->updated_at = updated_at;
                return result({}, 1);
            }
            return result({}, 0);
        }

        // 15. UPDATE file_transfers SET accepted_chunks = accepted_chunks + 1
        if (query.find("accepted_chunks = accepted_chunks + 1") != std::string_view::npos) {
            int64_t bytes_added = std::stoll(params[0].value_or("0"));
            std::string updated_at = params[1].value_or("");
            std::string transfer_id = params[2].value_or("");

            MockStorage::StoredTransfer* t = nullptr;
            if (staged_transfers_.find(transfer_id) != staged_transfers_.end()) {
                t = &staged_transfers_[transfer_id];
            } else if (store.transfers_.find(transfer_id) != store.transfers_.end()) {
                staged_transfers_[transfer_id] = store.transfers_[transfer_id];
                t = &staged_transfers_[transfer_id];
            }

            if (t) {
                t->accepted_chunks++;
                t->transferred_bytes += bytes_added;
                t->updated_at = updated_at;
                return result({}, 1);
            }
            return result({}, 0);
        }

        // 16. INSERT INTO file_chunks ... ON CONFLICT (transfer_id, chunk_index) DO NOTHING
        if (query.find("INSERT INTO file_chunks") != std::string_view::npos) {
            MockStorage::StoredChunk c;
            c.chunk_id = params[0].value_or("");
            c.transfer_id = params[1].value_or("");
            c.chunk_index = std::stoi(params[2].value_or("0"));
            c.byte_offset = std::stoll(params[3].value_or("0"));
            c.chunk_size = std::stoi(params[4].value_or("0"));
            c.chunk_hash_sha256 = params[5].value_or("");
            c.minio_chunk_key = params[6].value_or("");
            c.status = params[7].value_or("RECEIVED");
            c.created_at = params[8].value_or("");

            auto key = std::make_pair(c.transfer_id, c.chunk_index);
            if (staged_chunks_.find(key) != staged_chunks_.end() ||
                store.chunks_.find(key) != store.chunks_.end()) {
                // Conflict: DO NOTHING (affected rows = 0)
                return result({}, 0);
            }

            staged_chunks_[key] = c;
            return result({}, 1);
        }

        // 17. SELECT chunk_hash_sha256 FROM file_chunks WHERE transfer_id = $1 AND chunk_index = $2
        if (query.find("SELECT chunk_hash_sha256 FROM file_chunks") != std::string_view::npos) {
            std::string transfer_id = params[0].value_or("");
            int32_t chunk_idx = std::stoi(params[1].value_or("0"));
            auto key = std::make_pair(transfer_id, chunk_idx);

            std::string hash;
            if (staged_chunks_.find(key) != staged_chunks_.end()) {
                hash = staged_chunks_[key].chunk_hash_sha256;
            } else if (store.chunks_.find(key) != store.chunks_.end()) {
                hash = store.chunks_[key].chunk_hash_sha256;
            }

            if (!hash.empty()) {
                std::vector<field> f;
                std::map<std::string, size_t> map;
                map["chunk_hash_sha256"] = 0;
                f.emplace_back(hash, "chunk_hash_sha256");
                return result({row(std::move(f), std::move(map))}, 1);
            }
            return result({}, 0);
        }

        // 18. SELECT chunk_index FROM file_chunks WHERE transfer_id = $1 ... ORDER BY chunk_index ASC
        if (query.find("SELECT chunk_index FROM file_chunks") != std::string_view::npos) {
            std::string transfer_id = params[0].value_or("");

            std::map<std::pair<std::string, int32_t>, MockStorage::StoredChunk> all_chunks = store.chunks_;
            for (const auto& [k, c] : staged_chunks_) {
                all_chunks[k] = c;
            }

            std::vector<int32_t> indices;
            for (const auto& [k, c] : all_chunks) {
                if (k.first == transfer_id) {
                    indices.push_back(k.second);
                }
            }
            std::sort(indices.begin(), indices.end());

            std::vector<row> rows;
            for (int32_t idx : indices) {
                std::vector<field> f;
                std::map<std::string, size_t> map;
                map["chunk_index"] = 0;
                f.emplace_back(std::to_string(idx), "chunk_index");
                rows.emplace_back(std::move(f), std::move(map));
            }
            return result(std::move(rows), rows.size());
        }

        // 19. SELECT COUNT(*) FROM file_chunks WHERE transfer_id = $1
        if (query.find("SELECT COUNT(*) FROM file_chunks") != std::string_view::npos) {
            std::string transfer_id = params[0].value_or("");

            std::map<std::pair<std::string, int32_t>, MockStorage::StoredChunk> all_chunks = store.chunks_;
            for (const auto& [k, c] : staged_chunks_) {
                all_chunks[k] = c;
            }

            int32_t count = 0;
            for (const auto& [k, c] : all_chunks) {
                if (k.first == transfer_id) count++;
            }

            std::vector<field> f;
            std::map<std::string, size_t> map;
            map["count"] = 0;
            f.emplace_back(std::to_string(count), "count");
            return result({row(std::move(f), std::move(map))}, 1);
        }

        // 20. SELECT 1 FROM file_chunks WHERE transfer_id = $1 AND chunk_index = $2
        if (query.find("SELECT 1 FROM file_chunks") != std::string_view::npos) {
            std::string transfer_id = params[0].value_or("");
            int32_t chunk_idx = std::stoi(params[1].value_or("0"));
            auto key = std::make_pair(transfer_id, chunk_idx);

            if (staged_chunks_.find(key) != staged_chunks_.end() ||
                store.chunks_.find(key) != store.chunks_.end()) {
                std::vector<field> f;
                std::map<std::string, size_t> map;
                map["?column?"] = 0;
                f.emplace_back("1", "?column?");
                return result({row(std::move(f), std::move(map))}, 1);
            }
            return result({}, 0);
        }

        // 21. SELECT ... FROM file_chunks WHERE transfer_id = $1 ORDER BY chunk_index ASC
        if (query.find("FROM file_chunks WHERE transfer_id = $1 ORDER BY chunk_index") != std::string_view::npos) {
            std::string transfer_id = params[0].value_or("");

            std::map<std::pair<std::string, int32_t>, MockStorage::StoredChunk> all_chunks = store.chunks_;
            for (const auto& [k, c] : staged_chunks_) {
                all_chunks[k] = c;
            }

            std::vector<MockStorage::StoredChunk> matching;
            for (const auto& [k, c] : all_chunks) {
                if (k.first == transfer_id) {
                    matching.push_back(c);
                }
            }

            std::sort(matching.begin(), matching.end(), [](const auto& a, const auto& b) {
                return a.chunk_index < b.chunk_index;
            });

            std::vector<row> rows;
            for (const auto& c : matching) {
                rows.push_back(build_chunk_row(c));
            }
            return result(std::move(rows), rows.size());
        }

        return result({}, 0);
    }

    bool committed_{false};
    std::map<std::string, MockStorage::StoredFile> staged_files_;
    std::map<std::string, MockStorage::StoredMetadata> staged_metadata_;
    std::map<std::pair<std::string, int32_t>, MockStorage::StoredVersion> staged_versions_;
    std::map<std::string, MockStorage::StoredTransfer> staged_transfers_;
    std::map<std::pair<std::string, int32_t>, MockStorage::StoredChunk> staged_chunks_;
};

} // namespace pqxx

#endif
