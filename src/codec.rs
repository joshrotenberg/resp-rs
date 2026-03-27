//! Shared types for the Tokio codec integration.

use crate::ParseError;

/// Error type for codec operations, wrapping both parse errors and I/O errors.
#[derive(Debug, thiserror::Error)]
pub enum CodecError {
    /// A RESP protocol parsing error.
    #[error(transparent)]
    Parse(#[from] ParseError),

    /// An I/O error from the underlying transport.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}
