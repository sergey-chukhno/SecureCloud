#pragma once

#include <stdexcept>
#include <string>

namespace securecloud::auth::repository {

/// Base exception for all repository data access errors.
class RepositoryException : public std::runtime_error {
  public:
    explicit RepositoryException(const std::string& message) : std::runtime_error(message) {}
};

/// Thrown when an expected entity cannot be found by its identifier.
class EntityNotFoundException : public RepositoryException {
  public:
    explicit EntityNotFoundException(const std::string& message) : RepositoryException(message) {}
};

/// Thrown when an insert/update violates a unique constraint (e.g. unique credential identifier).
class DuplicateEntityException : public RepositoryException {
  public:
    explicit DuplicateEntityException(const std::string& message) : RepositoryException(message) {}
};

/// Thrown when an optimistic concurrency control (OCC) version collision occurs.
class OptimisticLockException : public RepositoryException {
  public:
    explicit OptimisticLockException(const std::string& message) : RepositoryException(message) {}
};

/// Thrown when an entity lifecycle invariant is violated (e.g. reactivating or modifying a revoked device).
class InvalidEntityStateException : public RepositoryException {
  public:
    explicit InvalidEntityStateException(const std::string& message) : RepositoryException(message) {}
};

/// Thrown on generic database execution or connectivity failures.
class DatabaseExecutionException : public RepositoryException {
  public:
    explicit DatabaseExecutionException(const std::string& message) : RepositoryException(message) {}
};

} // namespace securecloud::auth::repository
