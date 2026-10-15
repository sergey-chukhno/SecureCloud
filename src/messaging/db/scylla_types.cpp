#include "messaging/db/scylla_types.hpp"

#include <stdexcept>

namespace securecloud::messaging::db {

const std::string& ScyllaValue::as_string() const {
    if (const auto* val = std::get_if<std::string>(&value_)) {
        return *val;
    }
    throw std::bad_variant_access();
}

int32_t ScyllaValue::as_int() const {
    if (const auto* val = std::get_if<int32_t>(&value_)) {
        return *val;
    }
    throw std::bad_variant_access();
}

int64_t ScyllaValue::as_int64() const {
    if (const auto* val = std::get_if<int64_t>(&value_)) {
        return *val;
    }
    if (const auto* val32 = std::get_if<int32_t>(&value_)) {
        return static_cast<int64_t>(*val32);
    }
    throw std::bad_variant_access();
}

bool ScyllaValue::as_bool() const {
    if (const auto* val = std::get_if<bool>(&value_)) {
        return *val;
    }
    throw std::bad_variant_access();
}

const std::vector<uint8_t>& ScyllaValue::as_blob() const {
    if (const auto* val = std::get_if<std::vector<uint8_t>>(&value_)) {
        return *val;
    }
    throw std::bad_variant_access();
}

const std::vector<std::string>& ScyllaValue::as_string_list() const {
    if (const auto* val = std::get_if<std::vector<std::string>>(&value_)) {
        return *val;
    }
    throw std::bad_variant_access();
}

ScyllaRow::ScyllaRow(std::vector<std::string> column_names, std::vector<ScyllaValue> values)
    : column_names_(std::move(column_names)), values_(std::move(values)) {
    for (std::size_t i = 0; i < column_names_.size(); ++i) {
        name_to_index_[column_names_[i]] = i;
    }
}

std::size_t ScyllaRow::find_column_index(std::string_view column_name) const {
    auto it = name_to_index_.find(std::string(column_name));
    if (it == name_to_index_.end()) {
        throw std::out_of_range("Column not found in ScyllaRow: " + std::string(column_name));
    }
    return it->second;
}

bool ScyllaRow::is_null(std::string_view column_name) const {
    return is_null(find_column_index(column_name));
}

bool ScyllaRow::is_null(std::size_t index) const {
    if (index >= values_.size()) {
        throw std::out_of_range("Column index out of range: " + std::to_string(index));
    }
    return values_[index].is_null();
}

const ScyllaValue& ScyllaRow::get(std::string_view column_name) const {
    return get(find_column_index(column_name));
}

const ScyllaValue& ScyllaRow::get(std::size_t index) const {
    if (index >= values_.size()) {
        throw std::out_of_range("Column index out of range: " + std::to_string(index));
    }
    return values_[index];
}

std::string ScyllaRow::get_string(std::string_view column_name) const {
    return get(column_name).as_string();
}

int32_t ScyllaRow::get_int(std::string_view column_name) const {
    return get(column_name).as_int();
}

int64_t ScyllaRow::get_int64(std::string_view column_name) const {
    return get(column_name).as_int64();
}

int64_t ScyllaRow::get_timestamp(std::string_view column_name) const {
    return get(column_name).as_timestamp();
}

bool ScyllaRow::get_bool(std::string_view column_name) const {
    return get(column_name).as_bool();
}

std::vector<std::string> ScyllaRow::get_string_list(std::string_view column_name) const {
    return get(column_name).as_string_list();
}

bool ScyllaRow::has_column(std::string_view column_name) const noexcept {
    return name_to_index_.find(std::string(column_name)) != name_to_index_.end();
}

const ScyllaRow& ScyllaQueryResult::front() const {
    if (rows_.empty()) {
        throw std::out_of_range("Cannot call front() on empty ScyllaQueryResult");
    }
    return rows_.front();
}

} // namespace securecloud::messaging::db
