// Maximum number of recent files to remember
pub const MAX_RECENT_FILES: usize = 10;

// Auto-save interval in seconds
pub const AUTO_SAVE_INTERVAL: u64 = 60;

// File extension for BitQuill documents
pub const BITQUILL_FILE_EXT: &str = "bq";

// File extension for BitQuill chain data
pub const BITQUILL_CHAIN_EXT: &str = "bqc";

// Target time for VDF ticks (1 second)
pub const TARGET_TICK_SECONDS: f64 = 1.0;

// Initial VDF difficulty (iterations)
pub const INITIAL_VDF_ITERATIONS: u64 = 100_000;

// Minimum VDF difficulty
pub const MIN_VDF_ITERATIONS: u64 = 250_000;

// Maximum VDF difficulty
pub const MAX_VDF_ITERATIONS: u64 = 1000_000_000;

// Merkle leaf created every N ticks
pub const LEAF_TICK_INTERVAL: u64 = 1000; 

// Minimum ticks between leaves when pending changes exist
pub const MIN_TICKS_FOR_PENDING_LEAF: u64 = 1000;

// Number of ticks to store for difficulty adjustment
pub const DIFFICULTY_WINDOW_SIZE: usize = 1000;

// Frequency of difficulty adjustments (ticks)
pub const DIFFICULTY_ADJUSTMENT_INTERVAL: u64 = 1000;

// MINIMUM difficulty 
pub const ABSOLUTE_MIN_ITERATIONS: u64 = 100_000; // Reasonable minimum

// Maximum buffer size to prevent memory issues
pub const MAX_BUFFER_SIZE: usize = 10_000_000; // 10MB

// Maximum allowed leaves to prevent resource exhaustion
pub const MAX_ALLOWED_LEAVES: usize = 50_000;

// Safe maximum string size
pub const MAX_CONTENT_SIZE: usize = 1_000_000; // 1MB per paragraph
