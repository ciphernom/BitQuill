use std::{fmt, io};
use serde_json;
use std::sync::mpsc;

// Error handling types
pub type BitQuillResult<T> = Result<T, BitQuillError>;

#[derive(Debug)]
pub enum BitQuillError {
    IoError(io::Error),
    SerializationError(String),
    DeserializationError(String),
    HashError(String),
    VdfError(String),
    ValidationError(String),
    ResourceExhaustedError(String),
    ThreadError(String),
    StateError(String),
    LockError(String),
}

impl fmt::Display for BitQuillError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            BitQuillError::IoError(e) => write!(f, "I/O error: {}", e),
            BitQuillError::SerializationError(s) => write!(f, "Serialization error: {}", s),
            BitQuillError::DeserializationError(s) => write!(f, "Deserialization error: {}", s),
            BitQuillError::HashError(s) => write!(f, "Hash error: {}", s),
            BitQuillError::VdfError(s) => write!(f, "VDF error: {}", s),
            BitQuillError::ValidationError(s) => write!(f, "Validation error: {}", s),
            BitQuillError::ResourceExhaustedError(s) => write!(f, "Resource exhausted: {}", s),
            BitQuillError::ThreadError(s) => write!(f, "Thread error: {}", s),
            BitQuillError::StateError(s) => write!(f, "State error: {}", s),
            BitQuillError::LockError(s) => write!(f, "Lock error: {}", s),
        }
    }
}

impl From<io::Error> for BitQuillError {
    fn from(error: io::Error) -> Self {
        BitQuillError::IoError(error)
    }
}

impl From<serde_json::Error> for BitQuillError {
    fn from(error: serde_json::Error) -> Self {
        BitQuillError::DeserializationError(error.to_string())
    }
}

impl<T> From<std::sync::PoisonError<T>> for BitQuillError {
    fn from(error: std::sync::PoisonError<T>) -> Self {
        BitQuillError::LockError(error.to_string())
    }
}

impl From<mpsc::SendError<u64>> for BitQuillError {
    fn from(error: mpsc::SendError<u64>) -> Self {
        BitQuillError::ThreadError(format!("Channel send error: {}", error))
    }
}

impl From<mpsc::RecvError> for BitQuillError {
    fn from(error: mpsc::RecvError) -> Self {
        BitQuillError::ThreadError(format!("Channel receive error: {}", error))
    }
}

// Additional From<SendError<VDFClockTick>> implementation will be in the vdf module
