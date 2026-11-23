#pragma once

#include <optional>
#include <string>

namespace securecloud::files::service {

/**
 * @brief Context propagated through Files domain services representing the caller identity
 * and distributed tracing correlation ID.
 */
struct FilesCallerContext {
    std::string user_id{};
    std::string device_id{};
    std::string correlation_id{};
    std::optional<std::string> file_capability{std::nullopt};
    std::optional<std::string> file_access_capability{std::nullopt};
};

namespace detail {

[[nodiscard]] inline std::optional<FilesCallerContext>& active_caller_context_slot() noexcept {
    thread_local std::optional<FilesCallerContext> slot{std::nullopt};
    return slot;
}

} // namespace detail

[[nodiscard]] inline std::optional<FilesCallerContext> current_files_caller_context() {
    return detail::active_caller_context_slot();
}

/**
 * @brief RAII scope propagating FilesCallerContext via thread-local storage for the active RPC call.
 */
class ScopedFilesCallerContext {
  public:
    explicit ScopedFilesCallerContext(FilesCallerContext ctx)
        : previous_(std::move(detail::active_caller_context_slot())) {
        detail::active_caller_context_slot() = std::move(ctx);
    }

    ~ScopedFilesCallerContext() { detail::active_caller_context_slot() = std::move(previous_); }

    ScopedFilesCallerContext(const ScopedFilesCallerContext&) = delete;
    ScopedFilesCallerContext& operator=(const ScopedFilesCallerContext&) = delete;
    ScopedFilesCallerContext(ScopedFilesCallerContext&&) = delete;
    ScopedFilesCallerContext& operator=(ScopedFilesCallerContext&&) = delete;

  private:
    std::optional<FilesCallerContext> previous_{std::nullopt};
};

} // namespace securecloud::files::service
