use crate::constants::*;
use crate::vdf::{VDF, VDFClockTick};

use std::{
    collections::{HashMap, VecDeque},
    sync::{mpsc, Arc, Mutex},
    thread,
    time::{Duration, Instant, SystemTime},
};
use serde::{Serialize, Deserialize};

// Document state representing the content at a specific point
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct DocumentState {
    pub content: String,      // Will now store only this paragraph's content
    #[serde(skip)]
    pub timestamp: Instant,
    #[serde(with = "crate::merkle::timestamp_serde")]
    pub system_time: SystemTime,
    pub state_hash: String,   // Hash of just this paragraph's content
}

// Merkle leaf representing document state at a point in time
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerkleLeaf {
    pub document_state: DocumentState,  // Document content and metadata
    pub vdf_tick_reference: u64,        // VDF tick number
    pub prev_leaf_hash: String,         // Hash of previous leaf for ordering
    #[serde(with = "crate::merkle::timestamp_serde")]
    pub timestamp: SystemTime,          // Wall clock time
    pub hash: String,                   // Hash of this leaf
    pub leaf_number: u64,               // Sequential leaf number
    pub commitment: String,             // field for content-VDF binding
}

// Merkle tree node (internal node)
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct MerkleNode {
    pub hash: String,                  // Hash of this node
    pub height: usize,                 // Height in the tree
    // Children are stored separately to avoid recursive serialization issues
    pub left_child_hash: Option<String>, // Hash of left child
    pub right_child_hash: Option<String>, // Hash of right child
}

// Enum to represent Merkle tree elements
#[derive(Clone, Debug)]
pub enum MerkleTreeElement {
    Node(MerkleNode),
    Leaf(MerkleLeaf),
}

// Document metadata
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DocumentMetadata {
    pub title: String,
    pub author: String,
    pub created: SystemTime,
    pub last_modified: SystemTime,
    pub version: String,
    pub keywords: Vec<String>,
    pub description: String,
}

#[derive(Clone, Copy, Debug, PartialEq, PartialOrd)] 
pub enum VerificationLevel {
    Basic,     // Quick, superficial check
    Standard,  // Normal level of checking (default)
    Thorough,  // Comprehensive verification
    Forensic   // Exhaustive verification including statistical analysis
}

// Verification result with details
#[derive(Debug, Clone)]
pub struct VerificationResult {
    pub valid: bool,
    pub details: Vec<VerificationDetail>,
    pub timestamp: Instant,
    pub level: VerificationLevel,
}

// Detailed verification step
#[derive(Debug, Clone)]
pub struct VerificationDetail {
    pub description: String,
    pub valid: bool,
    pub block_number: Option<u64>,
    pub tick_number: Option<u64>,
}

// Struct for writing pattern analysis results
#[derive(Clone, Debug)]
pub struct WritingPatternAnomaly {
    pub leaf_number: u64,
    pub description: String,
    pub confidence: f64, // How confident we are this is an anomaly (0.0-1.0)
}

#[derive(Clone, Debug)]
pub struct WritingPatternResult {
    pub average_interval: u64,
    pub interval_deviation: f64,
    pub detected_anomalies: Vec<WritingPatternAnomaly>,
}

// Struct for compact verification proof
#[derive(Serialize, Deserialize)]
pub struct VerificationProof {
    pub document_hash: String,
    pub merkle_root: Option<String>,
    pub leaf_count: u64,
    pub author: String,
    pub title: String,
    #[serde(with = "crate::merkle::timestamp_serde")]
    pub creation_timestamp: SystemTime,
    #[serde(with = "crate::merkle::timestamp_serde")]
    pub last_modification: SystemTime,
    pub verification_samples: Vec<VerificationSample>,
    #[serde(with = "crate::merkle::timestamp_serde")]
    pub proof_generation_time: SystemTime,
}

#[derive(Serialize, Deserialize)]
pub struct VerificationSample {
    pub leaf_number: u64,
    pub leaf_hash: String,
    #[serde(with = "crate::merkle::timestamp_serde")]
    pub timestamp: SystemTime,
    pub vdf_reference: u64,
    pub commitment: String,
}

// MerkleQuill file format (replacing BitQuill format)
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerkleQuillFile {
    pub metadata: DocumentMetadata,
    pub leaves: Option<Vec<MerkleLeaf>>,
    pub nodes: Option<Vec<MerkleNode>>,  // Store nodes separately to avoid recursion
    pub root_hash: Option<String>,       // Store just the root hash
    pub vdf_ticks: Option<Vec<VDFClockTick>>,
    pub modulus: Option<Vec<u8>>,         // RSA modulus for verification
    pub current_iterations: u64,          // Current VDF difficulty
    pub version: String,                  // File format version
}

// For exporting Merkle tree data for verification
#[derive(Serialize, Deserialize)]
pub struct ExportedMerkleData {
    pub document_title: String,
    pub author: String,
    #[serde(with = "crate::merkle::timestamp_serde")]
    pub created: SystemTime,
    #[serde(with = "crate::merkle::timestamp_serde")]
    pub last_modified: SystemTime,
    pub leaves: Vec<MerkleLeaf>,
    pub nodes: Vec<MerkleNode>,
    pub root_hash: Option<String>,
    pub vdf_ticks: Vec<VDFClockTick>,
    pub modulus: Vec<u8>,
    pub current_iterations: u64,
}

impl Default for DocumentState {
    fn default() -> Self {
        Self {
            content: String::new(),
            timestamp: Instant::now(),
            system_time: SystemTime::now(),
            state_hash: String::new(),
        }
    }
}

impl Default for DocumentMetadata {
    fn default() -> Self {
        DocumentMetadata {
            title: "Untitled Document".to_string(),
            author: whoami::username(),
            created: SystemTime::now(),
            last_modified: SystemTime::now(),
            version: "1.0".to_string(),
            keywords: vec![],
            description: "".to_string(),
        }
    }
}

impl MerkleQuillFile {
    pub fn new(metadata: DocumentMetadata) -> Self {
        MerkleQuillFile {
            metadata,
            leaves: None,
            nodes: None,
            root_hash: None,
            vdf_ticks: None,
            modulus: None,
            current_iterations: INITIAL_VDF_ITERATIONS,
            version: "2.0".to_string(), // Updated for Merkle tree structure
        }
    }
}

// Document chain manager using Merkle tree with VDF clock integration
pub struct MerkleDocument {
    // Merkle tree components
    pub root: Option<MerkleNode>,
    pub leaves: Vec<MerkleLeaf>,
    pub nodes: HashMap<String, MerkleNode>, // Nodes indexed by hash
    
    // Writing pattern analysis
    pub edit_intervals: Vec<(SystemTime, u64)>,
    
    // Current document state
    pub current_state: DocumentState,
    
    // VDF components
    pub vdf: VDF,
    pub vdf_clock_receiver: mpsc::Receiver<VDFClockTick>,
    pub vdf_iterations_sender: mpsc::Sender<u64>, // Channel to update VDF difficulty
    pub vdf_clock_shutdown: Arc<Mutex<bool>>,
    pub vdf_thread_handle: Option<thread::JoinHandle<()>>,
    pub latest_tick: Option<VDFClockTick>,
    pub historical_ticks: HashMap<u64, VDFClockTick>,
    
    // Timing and adjustment
    pub tick_timestamps: VecDeque<(u64, SystemTime)>,
    pub current_iterations: u64,
    pub target_tick_interval: Duration,
    pub last_leaf_tick: u64,
    
    // Document editing status
    pub pending_changes: bool,
    pub dirty: bool,
    pub last_edit_time: Instant,
    
    // Document metadata
    pub metadata: DocumentMetadata,
    
    // Verification status
    pub last_verification: Option<VerificationResult>,
}
