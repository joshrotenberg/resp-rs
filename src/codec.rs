//! Shared types for the Tokio codec integration.

use crate::{ParseError, SerializeError};

/// Error type for codec operations, wrapping both parse errors and I/O errors.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CodecError {
    /// A RESP protocol parsing error.
    #[error(transparent)]
    Parse(#[from] ParseError),

    /// A frame that cannot be represented on the wire.
    ///
    /// `encode` validates before writing, so a frame carrying a CRLF in a line
    /// payload, or otherwise unable to parse back as itself, is refused rather
    /// than emitted. See [`SerializeError`].
    #[error(transparent)]
    Serialize(#[from] SerializeError),

    /// An I/O error from the underlying transport.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}
