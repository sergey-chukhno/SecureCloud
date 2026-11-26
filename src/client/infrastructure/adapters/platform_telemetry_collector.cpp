#include "infrastructure/adapters/platform_telemetry_collector.hpp"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <thread>

#if defined(__APPLE__)
#include <mach/mach.h>
#include <sys/resource.h>
#elif defined(__linux__)
#include <fstream>
#include <string>
#include <sys/resource.h>
#include <unistd.h>
#elif defined(_WIN32)
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
// psapi.h must follow windows.h
#include <psapi.h>
#endif

namespace securecloud::client::infrastructure::adapters {
namespace {

[[nodiscard]] int64_t current_unix_ms() noexcept {
    return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch())
        .count();
}

[[nodiscard]] uint64_t read_process_rss_bytes() noexcept {
#if defined(__APPLE__)
    mach_task_basic_info_data_t info{};
    mach_msg_type_number_t count = MACH_TASK_BASIC_INFO_COUNT;
    const kern_return_t kr =
        task_info(mach_task_self(), MACH_TASK_BASIC_INFO, reinterpret_cast<task_info_t>(&info), &count);
    if (kr == KERN_SUCCESS) {
        return static_cast<uint64_t>(info.resident_size);
    }
    return 0U;
#elif defined(__linux__)
    std::ifstream statm("/proc/self/statm");
    uint64_t total_pages = 0U;
    uint64_t resident_pages = 0U;
    if (statm >> total_pages >> resident_pages) {
        const long page_size = sysconf(_SC_PAGESIZE);
        if (page_size > 0) {
            return resident_pages * static_cast<uint64_t>(page_size);
        }
    }
    return 0U;
#elif defined(_WIN32)
    PROCESS_MEMORY_COUNTERS_EX pmc{};
    if (GetProcessMemoryInfo(GetCurrentProcess(), reinterpret_cast<PROCESS_MEMORY_COUNTERS*>(&pmc), sizeof(pmc))) {
        return static_cast<uint64_t>(pmc.WorkingSetSize);
    }
    return 0U;
#else
    return 0U;
#endif
}

[[nodiscard]] uint64_t read_process_cpu_microseconds() noexcept {
#if defined(__APPLE__) || defined(__linux__)
    rusage ru{};
    if (getrusage(RUSAGE_SELF, &ru) != 0) {
        return 0U;
    }
    const int64_t user_us =
        static_cast<int64_t>(ru.ru_utime.tv_sec) * 1000000LL + static_cast<int64_t>(ru.ru_utime.tv_usec);
    const int64_t sys_us =
        static_cast<int64_t>(ru.ru_stime.tv_sec) * 1000000LL + static_cast<int64_t>(ru.ru_stime.tv_usec);
    const int64_t total_us = user_us + sys_us;
    return total_us > 0 ? static_cast<uint64_t>(total_us) : 0U;
#elif defined(_WIN32)
    FILETIME creation_ft{};
    FILETIME exit_ft{};
    FILETIME kernel_ft{};
    FILETIME user_ft{};
    if (!GetProcessTimes(GetCurrentProcess(), &creation_ft, &exit_ft, &kernel_ft, &user_ft)) {
        return 0U;
    }
    ULARGE_INTEGER kernel_ui{};
    ULARGE_INTEGER user_ui{};
    kernel_ui.LowPart = kernel_ft.dwLowDateTime;
    kernel_ui.HighPart = kernel_ft.dwHighDateTime;
    user_ui.LowPart = user_ft.dwLowDateTime;
    user_ui.HighPart = user_ft.dwHighDateTime;
    // FILETIME units are 100 ns -> divide by 10 for microseconds
    return (kernel_ui.QuadPart + user_ui.QuadPart) / 10ULL;
#else
    return 0U;
#endif
}

} // namespace

ProcessResourceSample PlatformTelemetryCollector::sample() {
    std::lock_guard<std::mutex> lock(mutex_);

    const auto now_wall = std::chrono::steady_clock::now();
    const uint64_t cpu_us = read_process_cpu_microseconds();
    const uint64_t rss_bytes = read_process_rss_bytes();

    double cpu_percent = 0.0;
    if (has_previous_) {
        const auto wall_us = std::chrono::duration_cast<std::chrono::microseconds>(now_wall - prev_wall_time_).count();
        if (wall_us > 0 && cpu_us >= prev_cpu_us_) {
            const uint64_t delta_cpu_us = cpu_us - prev_cpu_us_;
            const unsigned int logical_cores = std::max(1U, std::thread::hardware_concurrency());
            cpu_percent = (100.0 * static_cast<double>(delta_cpu_us)) /
                          (static_cast<double>(wall_us) * static_cast<double>(logical_cores));
            if (!std::isfinite(cpu_percent) || cpu_percent < 0.0) {
                cpu_percent = 0.0;
            } else if (cpu_percent > 100.0) {
                cpu_percent = 100.0;
            }
        }
    }

    has_previous_ = true;
    prev_wall_time_ = now_wall;
    prev_cpu_us_ = cpu_us;

    ProcessResourceSample out;
    out.rss_bytes = rss_bytes;
    out.rss_megabytes = static_cast<double>(rss_bytes) / (1024.0 * 1024.0);
    out.cpu_percent = cpu_percent;
    out.sampled_at_ms = current_unix_ms();
    return out;
}

} // namespace securecloud::client::infrastructure::adapters
