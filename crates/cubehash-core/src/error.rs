use thiserror::Error;

/// Unified error type returned by `cubehash-core` configuration, custody, and mesh operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CubeHashError {
    #[error("invalid configuration: {0}")]
    InvalidConfig(&'static str),

    #[error("hardware lock rejected execution on unauthorized device")]
    UnauthorizedHardware,

    #[error("local monotonic clock rollback or overflow detected")]
    ClockRollbackDetected,

    #[error("packet sequence replay or stale epoch detected")]
    ReplayDetected,

    #[error("bit-level self-healing could not repair severe corruption")]
    UnrecoverableCorruption,

    #[error("authentication tag verification failed")]
    AuthenticationFailed,

    #[error("an outbound transaction is already awaiting ACK or rollback")]
    PendingTransactionExists,

    #[error("no pending outbound transaction exists to commit or rollback")]
    NoPendingTransaction,

    #[error("delivery acknowledgment does not match pending transaction")]
    AckMismatch,

    #[error("payload ({actual_bytes} bytes) exceeds raw core capacity ({max_bytes} bytes)")]
    PayloadTooLargeForCore {
        max_bytes: usize,
        actual_bytes: usize,
    },

    #[error("cryptographic operation failed: {0}")]
    CryptoFailure(&'static str),

    #[error("system random number generator failed")]
    RngFailure,
}

/// Convenience result alias for `cubehash-core`.
pub type Result<T> = std::result::Result<T, CubeHashError>;
