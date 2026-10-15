#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <variant>
#include <vector>

namespace securecloud::messaging::db {

/// Represents a strongly-typed CQL value.
class ScyllaValue {
  public:
    using ValueType = std::variant<std::monostate,          // Null
                                   std::string,             // text / varchar / ascii / uuid
                                   int32_t,                 // int
                                   int64_t,                 // bigint / timestamp (milliseconds since epoch)
                                   bool,                    // boolean
                                   std::vector<uint8_t>,    // blob
                                   std::vector<std::string> // list<text> / set<text>
                                   >;

    ScyllaValue() : value_(std::monostate{}) {}
    /* implicit */ ScyllaValue(std::string val) : value_(std::move(val)) {}
    /* implicit */ ScyllaValue(const char* val) : value_(std::string(val)) {}
    /* implicit */ ScyllaValue(std::string_view val) : value_(std::string(val)) {}
    /* implicit */ ScyllaValue(int32_t val) : value_(val) {}
    /* implicit */ ScyllaValue(int64_t val) : value_(val) {}
    /* implicit */ ScyllaValue(bool val) : value_(val) {}
    /* implicit */ ScyllaValue(std::vector<uint8_t> val) : value_(std::move(val)) {}
    /* implicit */ ScyllaValue(std::vector<std::string> val) : value_(std::move(val)) {}

    [[nodiscard]] static ScyllaValue null() { return ScyllaValue(); }

    [[nodiscard]] bool is_null() const noexcept { return std::holds_alternative<std::monostate>(value_); }

    [[nodiscard]] const std::string& as_string() const;
    [[nodiscard]] int32_t as_int() const;
    [[nodiscard]] int64_t as_int64() const;
    [[nodiscard]] int64_t as_timestamp() const { return as_int64(); }
    [[nodiscard]] bool as_bool() const;
    [[nodiscard]] const std::vector<uint8_t>& as_blob() const;
    [[nodiscard]] const std::vector<std::string>& as_string_list() const;

    [[nodiscard]] const ValueType& raw_value() const noexcept { return value_; }

    bool operator==(const ScyllaValue& other) const = default;

  private:
    ValueType value_;
};

/// Represents a single row returned from a CQL query.
class ScyllaRow {
  public:
    ScyllaRow() = default;
    ScyllaRow(std::vector<std::string> column_names, std::vector<ScyllaValue> values);

    [[nodiscard]] bool is_null(std::string_view column_name) const;
    [[nodiscard]] bool is_null(std::size_t index) const;

    [[nodiscard]] const ScyllaValue& get(std::string_view column_name) const;
    [[nodiscard]] const ScyllaValue& get(std::size_t index) const;

    [[nodiscard]] std::string get_string(std::string_view column_name) const;
    [[nodiscard]] int32_t get_int(std::string_view column_name) const;
    [[nodiscard]] int64_t get_int64(std::string_view column_name) const;
    [[nodiscard]] int64_t get_timestamp(std::string_view column_name) const;
    [[nodiscard]] bool get_bool(std::string_view column_name) const;
    [[nodiscard]] std::vector<std::string> get_string_list(std::string_view column_name) const;

    [[nodiscard]] std::size_t column_count() const noexcept { return values_.size(); }
    [[nodiscard]] const std::vector<std::string>& column_names() const noexcept { return column_names_; }

  private:
    [[nodiscard]] std::size_t find_column_index(std::string_view column_name) const;

    std::vector<std::string> column_names_;
    std::vector<ScyllaValue> values_;
    std::unordered_map<std::string, std::size_t> name_to_index_;
};

/// Represents the result set of an executed CQL query.
class ScyllaQueryResult {
  public:
    ScyllaQueryResult() = default;
    explicit ScyllaQueryResult(std::vector<ScyllaRow> rows, bool is_applied = true)
        : rows_(std::move(rows)), is_applied_(is_applied) {}

    [[nodiscard]] bool empty() const noexcept { return rows_.empty(); }
    [[nodiscard]] std::size_t size() const noexcept { return rows_.size(); }
    [[nodiscard]] bool is_applied() const noexcept { return is_applied_; }

    [[nodiscard]] const ScyllaRow& front() const;
    [[nodiscard]] const ScyllaRow& operator[](std::size_t index) const { return rows_[index]; }

    auto begin() noexcept { return rows_.begin(); }
    auto end() noexcept { return rows_.end(); }
    auto begin() const noexcept { return rows_.begin(); }
    auto end() const noexcept { return rows_.end(); }

    void add_row(ScyllaRow row) { rows_.push_back(std::move(row)); }
    void set_applied(bool applied) noexcept { is_applied_ = applied; }

  private:
    std::vector<ScyllaRow> rows_;
    bool is_applied_{true};
};

} // namespace securecloud::messaging::db
