#pragma once

#include <string>
#include <string_view>
#include <vector>

namespace securecloud::client::application::managers {

/// Scrubs credentials, cryptographic key material, recovery seeds, message plaintexts,
/// user PII, @handles, and OS home paths out of diagnostic snapshots prior to .scdiag encryption.
class DiagnosticSanitizer final {
  public:
    [[nodiscard]] static std::string scrub_text(std::string_view raw,
                                                const std::vector<std::string>& extra_sensitive_literals = {});

    [[nodiscard]] static bool contains_unredacted_secret_marker(std::string_view text) noexcept;
};

} // namespace securecloud::client::application::managers
