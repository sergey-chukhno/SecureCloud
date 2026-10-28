#include "ingestion/acknowledgement_manager.hpp"

namespace securecloud::audit::ingestion {

    void AcknowledgementManager::complete_batch_success(const IngestionBatch& batch) {
        for (const auto& envelope : batch) {
            service::IngestionResult result{
                .success = true,
                .error_code = "",
                .error_message = "",
                .received_at = envelope.event.received_at.value_or(std::chrono::system_clock::now())
            };

            if (envelope.completion_promise) {
                envelope.completion_promise->set_value(result);
            }
            if (envelope.completion_callback) {
                envelope.completion_callback(result);
            }
        }
    }

    void AcknowledgementManager::complete_batch_failure(
        const IngestionBatch& batch,
        const std::string& error_code,
        const std::string& error_message) {
        for (const auto& envelope : batch) {
            service::IngestionResult result{
                .success = false,
                .error_code = error_code,
                .error_message = error_message,
                .received_at = envelope.event.received_at.value_or(std::chrono::system_clock::now())
            };

            if (envelope.completion_promise) {
                envelope.completion_promise->set_value(result);
            }
            if (envelope.completion_callback) {
                envelope.completion_callback(result);
            }
        }
    }

} // namespace securecloud::audit::ingestion