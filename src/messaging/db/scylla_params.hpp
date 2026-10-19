#pragma once

#include "messaging/db/scylla_types.hpp"

#include <string>
#include <string_view>
#include <vector>

namespace securecloud::messaging::db {

/// Container for positional parameter binding in prepared CQL statements.
class ScyllaParams {
  public:
    ScyllaParams() = default;

    void add_value(ScyllaValue value) { values_.push_back(std::move(value)); }
    void add_string(std::string_view val) { values_.emplace_back(std::string(val)); }
    void add_int(int32_t val) { values_.emplace_back(val); }
    void add_int64(int64_t val) { values_.emplace_back(val); }
    void add_timestamp(int64_t val) { values_.emplace_back(val); }
    void add_bool(bool val) { values_.emplace_back(val); }
    void add_blob(std::vector<uint8_t> val) { values_.emplace_back(std::move(val)); }
    void add_string_list(std::vector<std::string> val) { values_.emplace_back(std::move(val)); }
    void add_null() { values_.emplace_back(ScyllaValue::null()); }

    [[nodiscard]] std::size_t size() const noexcept { return values_.size(); }
    [[nodiscard]] bool empty() const noexcept { return values_.empty(); }

    [[nodiscard]] const ScyllaValue& operator[](std::size_t index) const { return values_[index]; }
    [[nodiscard]] const std::vector<ScyllaValue>& values() const noexcept { return values_; }

    auto begin() noexcept { return values_.begin(); }
    auto end() noexcept { return values_.end(); }
    auto begin() const noexcept { return values_.begin(); }
    auto end() const noexcept { return values_.end(); }

  private:
    std::vector<ScyllaValue> values_;
};

} // namespace securecloud::messaging::db
