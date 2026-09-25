#pragma once

#include <chrono>
#include <cstdint>
#include <map>
#include <optional>
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

} // namespace pqxx

#endif
