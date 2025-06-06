// Re-export submodules
mod types;
mod document;
mod verification;
mod serialization;
mod hash;
mod analysis;
mod export;

// Re-export all types and functions
pub use types::*;
pub use serialization::timestamp_serde;
