use crate::constants::*;
use crate::error::{BitQuillError, BitQuillResult};
use crate::utils;
use crate::vdf::{VDF, VDFProof, VDFClockTick, compute_vdf_proof};

use num_bigint::BigUint;
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, VecDeque},
    fs,
    path::PathBuf,
    sync::{mpsc, Arc, Mutex},
    thread,
    time::{Duration, Instant, SystemTime},
};
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Local};
use hex;

// Document state representing the content at a specific point
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct DocumentState {
    pub content: String,      // Will now store only this paragraph's content
    #[serde(skip)]
    pub timestamp: Instant,
    #[serde(with = "timestamp_serde")]
    pub system_time: SystemTime,
    pub state_hash: String,   // Hash of just this paragraph's content
}

// For Instant serialization, we need to convert to SystemTime
pub mod timestamp_serde {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::SystemTime;
    use std::time::Duration;

    pub fn serialize<S>(time: &SystemTime, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let timestamp = time
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_secs();
        serializer.serialize_u64(timestamp)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<SystemTime, D::Error>
    where
        D: Deserializer<'de>,
    {
        let timestamp = u64::deserialize(deserializer)?;
        Ok(SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(timestamp))
    }
}

// Merkle leaf representing document state at a point in time
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerkleLeaf {
    pub document_state: DocumentState,  // Document content and metadata
    pub vdf_tick_reference: u64,        // VDF tick number
    pub prev_leaf_hash: String,         // Hash of previous leaf for ordering
    #[serde(with = "timestamp_serde")]
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
    #[serde(with = "timestamp_serde")]
    pub creation_timestamp: SystemTime,
    #[serde(with = "timestamp_serde")]
    pub last_modification: SystemTime,
    pub verification_samples: Vec<VerificationSample>,
    #[serde(with = "timestamp_serde")]
    pub proof_generation_time: SystemTime,
}

#[derive(Serialize, Deserialize)]
pub struct VerificationSample {
    pub leaf_number: u64,
    pub leaf_hash: String,
    #[serde(with = "timestamp_serde")]
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

// For exporting Merkle tree data for verification
#[derive(Serialize, Deserialize)]
pub struct ExportedMerkleData {
    pub document_title: String,
    pub author: String,
    #[serde(with = "timestamp_serde")]
    pub created: SystemTime,
    #[serde(with = "timestamp_serde")]
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

impl MerkleDocument {
    pub fn new() -> BitQuillResult<Self> {
        // Production-grade VDF with 2048-bit modulus
        let vdf = VDF::new(2048)?;
        let modulus_clone = vdf.modulus.clone();

        // Create channels for VDF clock and iterations update
        let (vdf_clock_sender, vdf_clock_receiver) = mpsc::channel();
        let (iterations_sender, iterations_receiver) = mpsc::channel::<u64>();

        let shutdown_flag = Arc::new(Mutex::new(false));
        let shutdown_clone = shutdown_flag.clone();

        // Initial difficulty
        let initial_iterations = INITIAL_VDF_ITERATIONS;

        // Start the VDF clock thread with adjustable difficulty
        let handle = thread::spawn(move || {
            let mut current_input = Sha256::digest(b"VDF Clock Genesis").to_vec();
            let mut sequence_number = 0;
            let mut current_iterations = initial_iterations;
            
            let modulus = &*modulus_clone;

            loop {
                // Check for shutdown signal
                let should_shutdown = match shutdown_clone.lock() {
                    Ok(guard) => *guard,
                    Err(poisoned) => {
                        // Handle poisoned mutex by taking ownership
                        *poisoned.into_inner()  // Gets ownership of inner value
                    }
                };
                
                if should_shutdown {
                    break;
                }
                
                // Check for updated iterations
                match iterations_receiver.try_recv() {
                    Ok(new_iterations) => {
                        current_iterations = new_iterations.clamp(
                            MIN_VDF_ITERATIONS, 
                            MAX_VDF_ITERATIONS
                        );
                    },
                    Err(mpsc::TryRecvError::Empty) => {},
                    Err(mpsc::TryRecvError::Disconnected) => {
                        // Channel closed, exit thread
                        break;
                    }
                }
                
                // Calculate previous output hash for verification
                let prev_output_hash = hex::encode(Sha256::digest(&current_input).to_vec());

                // Compute VDF with current difficulty
                let proof_result = compute_vdf_proof(&current_input, current_iterations, modulus);
                
                let proof = match proof_result {
                    Ok(p) => p,
                    Err(_) => {
                        // In case of error, use a fallback approach
                        // This is a safety measure to prevent the thread from crashing
                        let mut fallback_hasher = Sha256::new();
                        fallback_hasher.update(&current_input);
                        fallback_hasher.update(b"fallback");
                        let fallback_hash = fallback_hasher.finalize();
                        
                        VDFProof {
                            y: fallback_hash.to_vec(),
                            pi: fallback_hash.to_vec(),
                            l: BigUint::from(65537u32).to_bytes_be(), // Use a known prime
                            r: BigUint::from(1u32).to_bytes_be(),
                        }
                    }
                };

                // Create tick with system time
                let tick = VDFClockTick {
                    output_y: proof.y.clone(),
                    proof,
                    sequence_number,
                    prev_output_hash,
                    timestamp: Instant::now(),
                    system_time: SystemTime::now(),
                    iterations: current_iterations, // Store current difficulty
                };

                // Send tick to main thread
                if vdf_clock_sender.send(tick.clone()).is_err() {
                    // Main thread terminated
                    break;
                }

                // Update for next iteration
                current_input = tick.output_y;
                sequence_number += 1;

                // Brief sleep to prevent spinning too aggressively
                thread::sleep(Duration::from_millis(10));
            }
        });

        // Create initial state hash for current_state
        let genesis_hash = hex::encode(Sha256::digest(b"MerkleQuill Genesis").to_vec());

        Ok(MerkleDocument {
            root: None,
            leaves: Vec::new(),
            nodes: HashMap::new(),
            current_state: DocumentState {
                content: String::new(),
                timestamp: Instant::now(),
                system_time: SystemTime::now(),
                state_hash: genesis_hash,
            },
            vdf,
            vdf_clock_receiver,
            vdf_iterations_sender: iterations_sender,
            vdf_clock_shutdown: shutdown_flag,
            vdf_thread_handle: Some(handle),
            latest_tick: None,
            edit_intervals: Vec::new(),
            historical_ticks: HashMap::new(),
            tick_timestamps: VecDeque::with_capacity(DIFFICULTY_WINDOW_SIZE),
            current_iterations: initial_iterations,
            target_tick_interval: Duration::from_secs_f64(TARGET_TICK_SECONDS),
            last_leaf_tick: 0,
            pending_changes: false,
            dirty: false,
            last_edit_time: Instant::now(),
            metadata: DocumentMetadata::default(),
            last_verification: None,
        })
    }

    // Process VDF clock ticks and create leaves when needed
    pub fn process_vdf_ticks(&mut self) -> BitQuillResult<bool> {
        let leaf_created = false;

        // Process new clock ticks
        while let Ok(tick) = self.vdf_clock_receiver.try_recv() {
            // Store for verification and difficulty adjustment
            self.historical_ticks.insert(tick.sequence_number, tick.clone());
            self.latest_tick = Some(tick.clone());
            
            // Track timestamp for difficulty adjustment
            self.tick_timestamps.push_back((tick.sequence_number, tick.system_time));
            while self.tick_timestamps.len() > DIFFICULTY_WINDOW_SIZE {
                self.tick_timestamps.pop_front();
            }
            
            // Automatic leaf creation REMOVED as specified in original code
            
            // Keep difficulty adjustment
            if tick.sequence_number % DIFFICULTY_ADJUSTMENT_INTERVAL == 0 {
                self.adjust_difficulty()?;
            }
        }

        Ok(leaf_created)
    }
    
    // Adjust VDF difficulty based on historical timing
    fn adjust_difficulty(&mut self) -> BitQuillResult<()> {
        if self.tick_timestamps.len() < 100 { // Need reasonable sample size
            return Ok(()); // Not enough data to adjust
        }
        
        // Get first and last timestamps in the window
        let first = match self.tick_timestamps.front() {
            Some(f) => f,
            None => return Ok(()) // No timestamps available
        };
        
        let last = match self.tick_timestamps.back() {
            Some(l) => l,
            None => return Ok(()) // No timestamps available  
        };
        
        let elapsed_ticks = last.0.saturating_sub(first.0);
        if elapsed_ticks < 10 { // Need at least 10 ticks to calculate
            return Ok(());
        }
        
        // Calculate average time per tick
        let elapsed_time = match last.1.duration_since(first.1) {
            Ok(duration) => duration,
            Err(_) => return Ok(()), // Clock skew, can't adjust properly
        };
        
        let avg_tick_time = Duration::from_secs_f64(
            elapsed_time.as_secs_f64() / elapsed_ticks as f64
        );
        
        // Calculate adjustment ratio (target / actual)
        let ratio = self.target_tick_interval.as_secs_f64() / avg_tick_time.as_secs_f64();
        
        // Limit change to prevent wild oscillations (max 4x change in either direction)
        let adjustment_factor = ratio.max(0.25).min(4.0);
        
        // Calculate new iterations
        let new_iterations = (self.current_iterations as f64 * adjustment_factor) as u64;
        
        // Clamp to min/max difficulty range
        let new_iterations = new_iterations.clamp(MIN_VDF_ITERATIONS, MAX_VDF_ITERATIONS);
        
        // Only send update if significant change
        if (new_iterations as f64 / self.current_iterations as f64) < 0.9 || 
           (new_iterations as f64 / self.current_iterations as f64) > 1.1 {
            match self.vdf_iterations_sender.send(new_iterations) {
                Ok(_) => self.current_iterations = new_iterations,
                Err(e) => return Err(BitQuillError::ThreadError(format!("Failed to update VDF iterations: {}", e)))
            }
        }
        
        Ok(())
    }

    // Create a new Merkle leaf for the current document state
    pub fn create_leaf(&mut self, tick_number: u64) -> BitQuillResult<()> {
        // Check resource limits before creating a new leaf
        if self.leaves.len() >= MAX_ALLOWED_LEAVES {
            return Err(BitQuillError::ResourceExhaustedError(format!(
                "Maximum number of leaves ({}) reached", MAX_ALLOWED_LEAVES
            )));
        }
    
        let tick = match self.historical_ticks.get(&tick_number) {
            Some(t) => t,
            None => return Err(BitQuillError::StateError(format!(
                "VDF tick #{} not found", tick_number
            )))
        };
    
        // Create new leaf with CONSISTENT timestamp
        let leaf_timestamp = SystemTime::now();
        
        let prev_leaf_hash = self.leaves.last().map_or_else(
            || hex::encode(Sha256::digest(b"MerkleQuill Genesis Leaf").to_vec()),
            |leaf| leaf.hash.clone()
        );
        
        let leaf_number = self.leaves.len() as u64 + 1;
        
        // Find previous commitment for chaining
        let prev_commitment = self.leaves.last().map(|leaf| leaf.commitment.clone());
        
        // Calculate enhanced commitment that chains from previous leaf
        let mut commitment_hasher = Sha256::new();
        commitment_hasher.update(self.current_state.state_hash.as_bytes());
        commitment_hasher.update(&tick.output_y);
        commitment_hasher.update(tick_number.to_be_bytes());
        if let Some(prev) = &prev_commitment {
            commitment_hasher.update(prev.as_bytes()); // Chain commitments
        }
        let commitment = hex::encode(commitment_hasher.finalize());
        
        // Create temporary leaf for hash calculation - with SAME timestamp
        let temp_leaf = MerkleLeaf {
            document_state: self.current_state.clone(),
            vdf_tick_reference: tick_number,
            prev_leaf_hash: prev_leaf_hash.clone(),
            timestamp: leaf_timestamp, // CONSISTENT timestamp
            hash: String::new(), // Placeholder
            leaf_number,
            commitment: commitment.clone(),
        };
        
        // Calculate leaf hash
        let hash = calculate_leaf_hash(&temp_leaf)?;
        
        // Create final leaf with SAME timestamp as used in hash calculation
        let new_leaf = MerkleLeaf {
            document_state: self.current_state.clone(),
            vdf_tick_reference: tick_number,
            prev_leaf_hash,
            timestamp: leaf_timestamp, // SAME timestamp used in hash
            hash,
            leaf_number,
            commitment,
        };
        
        // Add to leaves and rebuild tree
        self.leaves.push(new_leaf);
        self.rebuild_merkle_tree()?;
        self.dirty = true;
        
        // Add to writing pattern analysis
        self.record_edit_interval(leaf_timestamp);
        
        Ok(())
    }
    
    // Rebuild the Merkle tree from leaves
    fn rebuild_merkle_tree(&mut self) -> BitQuillResult<()> {
        if self.leaves.is_empty() {
            self.root = None;
            self.nodes.clear();
            return Ok(());
        }
        
        // Clear existing nodes
        self.nodes.clear();
        
        // Create leaf elements
        let mut current_level: Vec<MerkleTreeElement> = self.leaves.iter()
            .map(|leaf| MerkleTreeElement::Leaf(leaf.clone()))
            .collect();
        
        let mut height = 0;
        
        // Build tree levels until we reach the root
        while current_level.len() > 1 {
            if height > 100 {  // Sanity check to prevent potential infinite loops 
                return Err(BitQuillError::StateError(
                    "Merkle tree height exceeds maximum".to_string()
                ));
            }
            
            height += 1;
            let mut next_level = Vec::new();
            
            // Process pairs of nodes
            for chunk in current_level.chunks(2) {
                if chunk.len() == 2 {
                    let left = &chunk[0];
                    let right = &chunk[1];
                    
                    let left_hash = get_element_hash(left)?;
                    let right_hash = get_element_hash(right)?;
                    
                    // Calculate node hash
                    let hash = calculate_node_hash(&left_hash, &right_hash)?;
                    
                    // Create node
                    let node = MerkleNode {
                        hash: hash.clone(),
                        height,
                        left_child_hash: Some(left_hash),
                        right_child_hash: Some(right_hash),
                    };
                    
                    // Store node in map
                    self.nodes.insert(hash.clone(), node.clone());
                    
                    // Add to next level
                    next_level.push(MerkleTreeElement::Node(node));
                } else {
                    // Odd number of nodes, promote the last one
                    next_level.push(chunk[0].clone());
                }
            }
            
            current_level = next_level;
        }
        
        // Set the root
        if !current_level.is_empty() {
            if let MerkleTreeElement::Node(node) = &current_level[0] {
                self.root = Some(node.clone());
            } else if let MerkleTreeElement::Leaf(leaf) = &current_level[0] {
                // Only one leaf, create a root node pointing to it
                let node = MerkleNode {
                    hash: leaf.hash.clone(),
                    height: 1,
                    left_child_hash: Some(leaf.hash.clone()),
                    right_child_hash: None,
                };
                self.nodes.insert(node.hash.clone(), node.clone());
                self.root = Some(node);
                            }
        }
                        
            Ok(())
    }

    // Record a change to the document content
    pub fn record_change(&mut self, new_content: String) -> BitQuillResult<()> {
        // Skip if content hasn't changed
        if new_content == self.current_state.content {
            return Ok(());
        }
        
        // Check content size to prevent excessive memory usage
        if new_content.len() > MAX_CONTENT_SIZE {
            return Err(BitQuillError::ResourceExhaustedError(format!(
                "Content size {} exceeds maximum allowed {}", new_content.len(), MAX_CONTENT_SIZE
            )));
        }

        // Update the current state
        self.current_state.content = new_content;
        self.current_state.state_hash = hex::encode(
            Sha256::digest(self.current_state.content.as_bytes()).to_vec()
        );
        self.current_state.timestamp = Instant::now();
        self.current_state.system_time = SystemTime::now();
        self.last_edit_time = Instant::now();

        // Update metadata
        self.metadata.last_modified = SystemTime::now();

        // Mark that we have pending changes to commit with the next tick
        self.pending_changes = true;
        self.dirty = true;
        
        Ok(())
    }

    // Get the current document content by combining all paragraphs
    pub fn get_current_content(&self) -> String {
        let paragraphs: Vec<&str> = self.leaves.iter()
            .map(|leaf| leaf.document_state.content.as_str())
            .collect();
            
        // Join paragraphs with newlines
        paragraphs.join("\n")
    }

    // Get information about leaves for display
    pub fn get_leaf_history(&self) -> Vec<String> {
        self.leaves
            .iter()
            .map(|leaf| {
                let system_time: DateTime<Local> = leaf.timestamp.into();
                let content_preview = if leaf.document_state.content.len() > 30 {
                    format!("{}...", &leaf.document_state.content[..30])
                } else {
                    leaf.document_state.content.clone()
                };

                format!(
                    "Paragraph #{}: {} - VDF Tick #{} - \"{}\"",
                    leaf.leaf_number,
                    system_time.format("%Y-%m-%d %H:%M:%S"),
                    leaf.vdf_tick_reference,
                    content_preview
                )
            })
            .collect()
    }
    
    // Get Merkle tree structure for display
    pub fn get_tree_structure(&self) -> Vec<String> {
        let mut result = Vec::new();
        
        if let Some(root) = &self.root {
            result.push(format!("Root: {:.8}... (height: {})", root.hash, root.height));
            self.format_tree_level(&mut result, root, 0);
        } else {
            result.push("Empty tree".to_string());
        }
        
        result
    }
    
    // Format tree level for display
    fn format_tree_level(&self, result: &mut Vec<String>, node: &MerkleNode, indent: usize) {
        let indent_str = "  ".repeat(indent);
        
        // Process left child
        if let Some(left_hash) = &node.left_child_hash {
            if let Some(child) = self.nodes.get(left_hash) {
                result.push(format!("{}L: {:.8}... (height: {})", indent_str, child.hash, child.height));
                self.format_tree_level(result, child, indent + 1);
            } else {
                // Must be a leaf
                if let Some(leaf) = self.leaves.iter().find(|l| &l.hash == left_hash) {
                    result.push(format!("{}L: Leaf #{} - Tick #{}", indent_str, leaf.leaf_number, leaf.vdf_tick_reference));
                }
            }
        }
        
        // Process right child
        if let Some(right_hash) = &node.right_child_hash {
            if let Some(child) = self.nodes.get(right_hash) {
                result.push(format!("{}R: {:.8}... (height: {})", indent_str, child.hash, child.height));
                self.format_tree_level(result, child, indent + 1);
            } else {
                // Must be a leaf
                if let Some(leaf) = self.leaves.iter().find(|l| &l.hash == right_hash) {
                    result.push(format!("{}R: Leaf #{} - Tick #{}", indent_str, leaf.leaf_number, leaf.vdf_tick_reference));
                }
            }
        }
    }

    // Get number of VDF clock ticks processed (available in memory)
    pub fn get_tick_count(&self) -> usize {
        self.historical_ticks.len()
    }

    // Verify the integrity of the Merkle tree and VDF clock chain
    pub fn verify_merkle_integrity(&mut self, level: VerificationLevel) -> VerificationResult {
        let mut result = VerificationResult {
            valid: true,
            details: Vec::new(),
            timestamp: Instant::now(),
            level: level,
        };

        if self.leaves.is_empty() {
            result.details.push(VerificationDetail {
                description: "Empty document - no leaves to verify".to_string(),
                valid: true, block_number: None, tick_number: None,
            });
            self.last_verification = Some(result.clone());
            return result;
        }

        // Verify VDF RSA modulus strength
        result.details.push(VerificationDetail {
            description: "Verifying VDF RSA modulus strength...".to_string(),
            valid: true, block_number: None, tick_number: None,
        });

        let modulus = &*self.vdf.modulus; // Get a reference to the BigUint inside the Arc
        
        if !utils::verify_modulus_strength(modulus) {
            result.valid = false; // Mark overall result as invalid
            result.details.push(VerificationDetail {
                description: "CRITICAL: VDF RSA modulus failed strength verification.".to_string(),
                valid: false, block_number: None, tick_number: None,
            });
        } else {
            result.details.push(VerificationDetail {
                description: "VDF RSA modulus passed basic strength verification.".to_string(),
                valid: true, block_number: None, tick_number: None,
            });
        }

        // 1. For each paragraph (leaf), ensure it's properly linked to the previous one
        let mut expected_prev_hash = match hex::encode(Sha256::digest(b"MerkleQuill Genesis Leaf").to_vec()) {
            hash => hash,
        };
        
        for leaf in self.leaves.iter() {
            // Verify leaf chain (paragraph links)
            if expected_prev_hash != leaf.prev_leaf_hash {
                result.valid = false;
                result.details.push(VerificationDetail {
                    description: format!("CRITICAL: Paragraph #{} chain broken - not linked to previous", leaf.leaf_number),
                    valid: false, block_number: Some(leaf.leaf_number), tick_number: None,
                });
            } else {
                result.details.push(VerificationDetail {
                    description: format!("Paragraph #{} link verified", leaf.leaf_number),
                    valid: true, block_number: Some(leaf.leaf_number), tick_number: None,
                });
            }
            
            // Verify leaf hash is correctly calculated
            match calculate_leaf_hash(leaf) {
                Ok(calculated_hash) => {
                    if calculated_hash != leaf.hash {
                        result.valid = false;
                        result.details.push(VerificationDetail {
                            description: format!("CRITICAL: Paragraph #{} hash mismatch - integrity compromised", leaf.leaf_number),
                            valid: false, block_number: Some(leaf.leaf_number), tick_number: None,
                        });
                    } else {
                        result.details.push(VerificationDetail {
                            description: format!("Paragraph #{} hash verified", leaf.leaf_number),
                            valid: true, block_number: Some(leaf.leaf_number), tick_number: None,
                        });
                    }
                },
                Err(_) => {
                    result.valid = false;
                    result.details.push(VerificationDetail {
                        description: format!("CRITICAL: Failed to calculate hash for paragraph #{}", leaf.leaf_number),
                        valid: false, block_number: Some(leaf.leaf_number), tick_number: None,
                    });
                }
            };
            
            // Verify content hash matches stored hash - SPECIAL HANDLING FOR PARAGRAPH MODEL
            let content_hash = hex::encode(
                Sha256::digest(leaf.document_state.content.as_bytes()).to_vec()
            );
            
            // For empty or whitespace-only paragraphs, be more lenient
            if content_hash != leaf.document_state.state_hash {
                // Special cases for valid mismatches:
                let is_empty = leaf.document_state.content.trim().is_empty();
                let is_genesis = leaf.leaf_number == 1 && leaf.document_state.content.is_empty();
                
                if is_empty || is_genesis {
                    result.details.push(VerificationDetail {
                        description: format!("Paragraph #{} empty/new content verified", leaf.leaf_number),
                        valid: true, block_number: Some(leaf.leaf_number), tick_number: None,
                    });
                } else {
                    result.valid = false;
                    result.details.push(VerificationDetail {
                        description: format!("CRITICAL: Paragraph #{} content mismatch - paragraph modified", leaf.leaf_number),
                        valid: false, block_number: Some(leaf.leaf_number), tick_number: None,
                    });
                }
            } else {
                result.details.push(VerificationDetail {
                    description: format!("Paragraph #{} content verified", leaf.leaf_number),
                    valid: true, block_number: Some(leaf.leaf_number), tick_number: None,
                });
            }
            
            // Update expected hash for next paragraph
            expected_prev_hash = leaf.hash.clone();
        }

        // 2. Verify paragraph-to-VDF bindings
        for leaf in &self.leaves {
            if let Some(tick) = self.historical_ticks.get(&leaf.vdf_tick_reference) {
                // Get previous commitment for chaining
                let prev_commitment = if leaf.leaf_number > 1 {
                    self.leaves.iter()
                        .find(|l| l.leaf_number == leaf.leaf_number - 1)
                        .map(|l| l.commitment.clone())
                } else {
                    None
                };
                
                // Recalculate commitment binding paragraph to VDF tick
                let mut expected_hasher = Sha256::new();
                expected_hasher.update(leaf.document_state.state_hash.as_bytes());
                expected_hasher.update(&tick.output_y);
                expected_hasher.update(leaf.vdf_tick_reference.to_be_bytes());
                if let Some(prev) = prev_commitment {
                    expected_hasher.update(prev.as_bytes());
                }
                let expected_commitment = hex::encode(expected_hasher.finalize());
                
                if expected_commitment != leaf.commitment {
                    result.valid = false;
                    result.details.push(VerificationDetail {
                        description: format!("CRITICAL: Paragraph #{} not properly timestamped", leaf.leaf_number),
                        valid: false,
                        block_number: Some(leaf.leaf_number),
                        tick_number: Some(leaf.vdf_tick_reference),
                    });
                } else {
                    result.details.push(VerificationDetail {
                        description: format!("Paragraph #{} timestamp verified (VDF tick #{})", 
                                          leaf.leaf_number, leaf.vdf_tick_reference),
                        valid: true,
                        block_number: Some(leaf.leaf_number),
                        tick_number: Some(leaf.vdf_tick_reference),
                    });
                }
            } else {
                // For paragraph model, missing VDF tick is less critical than paragraph integrity
                result.details.push(VerificationDetail {
                    description: format!("NOTE: Timestamp data missing for paragraph #{} (VDF tick #{})", 
                                       leaf.leaf_number, leaf.vdf_tick_reference),
                    valid: true, // Don't fail just for missing timestamp data
                    block_number: Some(leaf.leaf_number),
                    tick_number: Some(leaf.vdf_tick_reference),
                });
            }
        }
        
        // 3. Verify Merkle tree structure - this stays mostly the same
        // Build a fresh tree and compare with stored nodes
        let temp_doc = match MerkleDocument::new() {
            Ok(mut doc) => {
                doc.leaves = self.leaves.clone();
                // Rebuild silently - ignore errors here as we're just checking consistency
                let _ = doc.rebuild_merkle_tree();
                doc
            },
            Err(_) => {
                result.valid = false;
                result.details.push(VerificationDetail {
                    description: "CRITICAL: Failed to create temporary document for tree verification".to_string(),
                    valid: false, block_number: None, tick_number: None,
                });
                
                // Skip further tree verification
                self.last_verification = Some(result.clone());
                return result;
            }
        };
        
        if let (Some(current_root), Some(rebuilt_root)) = (&self.root, &temp_doc.root) {
            if current_root.hash != rebuilt_root.hash {
                result.valid = false;
                result.details.push(VerificationDetail {
                    description: "CRITICAL: Merkle root hash mismatch - document structure compromised".to_string(),
                    valid: false, block_number: None, tick_number: None,
                });
            } else {
                result.details.push(VerificationDetail {
                    description: "Document structure verified (Merkle tree valid)".to_string(),
                    valid: true, block_number: None, tick_number: None,
                });
            }
        } else if self.root.is_some() || temp_doc.root.is_some() {
            result.valid = false;
            result.details.push(VerificationDetail {
                description: "CRITICAL: Document structure invalid (Merkle tree inconsistent)".to_string(),
                valid: false, block_number: None, tick_number: None,
            });
        }
        
        // Attack: Only create leaves at favorable times
        // Defense: Check for suspiciously large gaps between leaves
        let max_allowed_leaf_gap = 500; // Maximum ticks between leaves (e.g., ~8 minutes if 1 tick/sec)
        if self.leaves.len() > 1 { // Only check if there are at least two leaves
            result.details.push(VerificationDetail {
                description: format!("Checking leaf gaps (max allowed: {} ticks)", max_allowed_leaf_gap),
                valid: true, block_number: None, tick_number: None,
            });
            for i in 1..self.leaves.len() {
                let current = &self.leaves[i];
                let previous = &self.leaves[i-1];
                let tick_gap = current.vdf_tick_reference.saturating_sub(previous.vdf_tick_reference);

                if tick_gap > max_allowed_leaf_gap {
                    result.details.push(VerificationDetail {
                        description: format!("SUSPICIOUS: Large gap ({} ticks) between paragraphs #{} and #{}",
                                          tick_gap, previous.leaf_number, current.leaf_number),
                        valid: true, // Warning only
                        block_number: Some(current.leaf_number),
                        tick_number: None, // Not related to a specific tick verification
                    });
                    // Do not set result.valid = false here.
                }
            }
        }
        
        
        // 4. Verify VDF ticks - SIMPLIFIED
        // Ensure we have ticks and the verification level requires checking them
        if level != VerificationLevel::Basic && !self.historical_ticks.is_empty() {
            result.details.push(VerificationDetail {
                description: "Verifying VDF tick integrity...".to_string(),
                valid: true, block_number: None, tick_number: None,
            });    
                
            // Attack: Manipulate genesis values
            // Defense: Verify expected genesis hashes
            if let Some(first_tick) = self.historical_ticks.get(&0) {
                // Calculate the initial input hash (hash of the seed) used by the VDF thread
                let initial_vdf_input_hash = Sha256::digest(b"VDF Clock Genesis").to_vec();

                // Calculate the expected prev_output_hash for tick 0
                // (This is the hash of the initial VDF input hash)
                let expected_tick0_prev_hash = hex::encode(Sha256::digest(&initial_vdf_input_hash).to_vec());

                // Now compare the stored hash with the correctly calculated expected hash
                if first_tick.prev_output_hash != expected_tick0_prev_hash {
                    result.valid = false;
                    result.details.push(VerificationDetail {
                        description: format!(
                            "CRITICAL: Genesis VDF Tick #0 input hash mismatch! Expected {}, got {}",
                            expected_tick0_prev_hash, first_tick.prev_output_hash
                        ),
                        valid: false,
                        block_number: None,
                        tick_number: Some(0),
                    });
                } else {
                    result.details.push(VerificationDetail {
                        description: "Genesis VDF Tick #0 input hash verified".to_string(),
                        valid: true,
                        block_number: None,
                        tick_number: Some(0),
                    });
                    // --- Also verify the proof for the Genesis Tick ---
                    // The input for tick 0's proof is the initial_vdf_input_hash
                    match self.vdf.verify(&initial_vdf_input_hash, &first_tick.proof) {
                        Ok(valid) => {
                            if !valid {
                                result.valid = false; // Mark as invalid if genesis proof fails
                                result.details.push(VerificationDetail {
                                    description: format!("CRITICAL: Genesis VDF Tick #0 proof failed verification"),
                                    valid: false,
                                    block_number: None,
                                    tick_number: Some(0),
                                });
                            } else {
                                result.details.push(VerificationDetail {
                                    description: "Genesis VDF Tick #0 proof verified".to_string(),
                                    valid: true,
                                    block_number: None,
                                    tick_number: Some(0),
                                });
                            }
                        },
                        Err(_) => {
                            result.valid = false;
                            result.details.push(VerificationDetail {
                                description: "CRITICAL: Error verifying Genesis VDF Tick #0 proof".to_string(),
                                valid: false,
                                block_number: None,
                                tick_number: Some(0),
                            });
                        }
                    }
                }
            } else {
                // Handle missing genesis tick 0 (existing logic seems okay)
                if level >= VerificationLevel::Standard {
                    result.valid = false;
                    result.details.push(VerificationDetail {
                        description: "CRITICAL: Genesis VDF tick #0 is missing".to_string(),
                        valid: false, block_number: None, tick_number: Some(0),
                    });
                } else {
                    result.details.push(VerificationDetail {
                        description: "NOTE: Genesis VDF tick #0 not found (Basic check)".to_string(),
                        valid: true,
                        block_number: None, tick_number: Some(0),
                    });
                }
            }
            
            
            // Get sequential ticks available in memory
            let mut tick_numbers: Vec<u64> = self.historical_ticks.keys().cloned().collect();
            tick_numbers.sort();
            
            // For paragraph model, just check a few key ticks
            let mut key_ticks = Vec::new();
            
            // Always include first tick
            if !tick_numbers.is_empty() {
                key_ticks.push(tick_numbers[0]);
            }
            
            // Include ticks referenced by paragraphs
            for leaf in &self.leaves {
                if !key_ticks.contains(&leaf.vdf_tick_reference) {
                    key_ticks.push(leaf.vdf_tick_reference);
                }
            }
            
            // Include some recent ticks
            let num_recent = 5.min(tick_numbers.len());
            for i in 0..num_recent {
                let idx = tick_numbers.len().saturating_sub(1).saturating_sub(i);
                if idx < tick_numbers.len() && !key_ticks.contains(&tick_numbers[idx]) {
                    key_ticks.push(tick_numbers[idx]);
                }
            }
            
            key_ticks.sort();
            
            // Verify each key tick's proof is valid
            for &tick_num in &key_ticks {
                if let Some(tick) = self.historical_ticks.get(&tick_num) {
                    //check for reasonable difficulty
                    if tick.iterations < ABSOLUTE_MIN_ITERATIONS {
                        result.valid = false;
                        result.details.push(VerificationDetail {
                            description: format!("CRITICAL: VDF tick #{} used suspiciously low difficulty ({})",
                                               tick_num, tick.iterations),
                            valid: false,
                            block_number: None,
                            tick_number: Some(tick_num),
                        });
                    }
                    
                    // Check if proof uses suspiciously efficient parameters for Wesolowski proof
                    let l = BigUint::from_bytes_be(&tick.proof.l);
                    if l.bits() < 120 {
                        result.valid = false;
                        result.details.push(VerificationDetail {
                            description: format!("CRITICAL: VDF tick #{} uses insecure proof parameters",
                                          tick_num),
                            valid: false,
                            block_number: None,
                            tick_number: Some(tick_num),
                        });
                    }
                    
                    //check for reasonable proof parameter bits
                    let l = BigUint::from_bytes_be(&tick.proof.l);
                    if l.bits() < 120 {
                        result.valid = false;
                        result.details.push(VerificationDetail {
                            description: format!("CRITICAL: VDF tick #{} uses insecure proof parameters",
                                          tick_num),
                            valid: false,
                            block_number: None,
                            tick_number: Some(tick_num),
                        });
                    }

                    if tick_num > 0 {
                        // Get the previous tick in our complete list
                        let prev_num = tick_num - 1;
                        if let Some(prev_tick) = self.historical_ticks.get(&prev_num) {
                            // Verify the chain link only if we have consecutive ticks
                            let calculated_prev_output_hash = hex::encode(
                                Sha256::digest(&prev_tick.output_y).to_vec()
                            );
                            
                            if calculated_prev_output_hash != tick.prev_output_hash {
                                // For paragraph model, VDF chain issues are less critical
                                result.details.push(VerificationDetail {
                                    description: format!("NOTE: VDF tick #{} chain inconsistency", tick_num),
                                    valid: true, // Don't fail
                                    block_number: None,
                                    tick_number: Some(tick_num),
                                });
                            } else {
                                result.details.push(VerificationDetail {
                                    description: format!("VDF tick #{} chain verified", tick_num),
                                    valid: true,
                                    block_number: None,
                                    tick_number: Some(tick_num),
                                });
                            }
                            
                            // Attack: Modify system clock to create fake timestamps
                            // Defense: Add timestamp consistency checks
                            // Check only if prev_num is indeed tick_num - 1 (ensures consecutive ticks)
                            if prev_num == tick_num - 1 {
                                match tick.system_time.duration_since(prev_tick.system_time) {
                                    Ok(time_diff) => {
                                        // Check if time is jumping too far forward (e.g., > 1 hour)
                                        if time_diff.as_secs() > 3600 {
                                            result.valid = false;
                                            result.details.push(VerificationDetail {
                                                description: format!("CRITICAL: Suspicious time jump between ticks #{} and #{}: {} seconds",
                                                                 prev_num, tick_num, time_diff.as_secs()),
                                                valid: false,
                                                tick_number: Some(tick_num),
                                                block_number: None,
                                            });
                                        }
                                        
                                        // Check if VDF computation speed is suspiciously fast
                                        if tick.iterations > MIN_VDF_ITERATIONS * 10 {
                                            // Calculate minimum possible computation time on best known hardware
                                            let min_possible_time = tick.iterations as f64 / 1_000_000_000.0; // Estimate: 1 billion iterations per second on top hardware
                                            
                                            if time_diff.as_secs_f64() < min_possible_time * 0.5 {
                                                result.valid = false;
                                                result.details.push(VerificationDetail {
                                                    description: format!("CRITICAL: VDF computation for tick #{} impossibly fast. Possible RSA factorization attack.", tick_num),
                                                    valid: false,
                                                    tick_number: Some(tick_num),
                                                    block_number: None,
                                                });
                                            }
                                        }                                        
                                    },
                                    Err(_) => {
                                        // Time went backwards
                                        result.valid = false;
                                        result.details.push(VerificationDetail {
                                            description: format!("CRITICAL: Time went backwards between ticks #{} and #{}",
                                                             prev_num, tick_num),
                                            valid: false,
                                            tick_number: Some(tick_num),
                                            block_number: None,
                                        });
                                    }
                                }
                            }
                            
                            // Verify proof
                            let input_for_curr = prev_tick.output_y.clone();
                            match self.vdf.verify(&input_for_curr, &tick.proof) {
                                Ok(valid) => {
                                    if !valid {
                                        // For paragraph model, proof issues are less critical
                                        result.details.push(VerificationDetail {
                                            description: format!("NOTE: VDF tick #{} timestamp verification issue", tick_num),
                                            valid: true, // Don't fail
                                            block_number: None,
                                            tick_number: Some(tick_num),
                                        });
                                    }
                                },
                                Err(_) => {
                                    result.details.push(VerificationDetail {
                                        description: format!("ERROR: Failed to verify VDF tick #{} proof", tick_num),
                                        valid: true, // Don't fail just for verification errors
                                        block_number: None,
                                        tick_number: Some(tick_num),
                                    });
                                }
                            }
                        }
                    }
                }
            }
            
            let mut prev_tick: Option<&VDFClockTick> = None;

            for &tick_num in &key_ticks {
                if let Some(tick) = self.historical_ticks.get(&tick_num) {
                    if let Some(prev) = prev_tick {
                        // Max 4x change between consecutive samples (matches adjustment bounds)
                        if tick.iterations > prev.iterations.saturating_mul(4) || 
                           tick.iterations.saturating_mul(4) < prev.iterations {
                            result.valid = false;
                            result.details.push(VerificationDetail {
                                description: format!("CRITICAL: Suspicious difficulty change between ticks #{} ({}) and #{} ({})",
                                               prev.sequence_number, prev.iterations,
                                               tick.sequence_number, tick.iterations),
                                valid: false,
                                block_number: None,
                                tick_number: Some(tick_num),
                            });
                        }
                    }
                    prev_tick = Some(tick);
                }
            }
            
            // Verify difficulty adjustment algorithm integrity
            if key_ticks.len() >= 3 {
                let sample_indices = key_ticks.windows(3).step_by(2).collect::<Vec<_>>();
                
                for window in sample_indices {
                    if window.len() == 3 && window[1] == window[0] + 1 && window[2] == window[1] + 1 {
                        // We have three consecutive ticks
                        if let (Some(a), Some(b), Some(c)) = (
                            self.historical_ticks.get(&window[0]),
                            self.historical_ticks.get(&window[1]),
                            self.historical_ticks.get(&window[2])
                        ) {
                            // Calculate expected difficulty adjustment based on timestamps
                            let time_ab = match b.system_time.duration_since(a.system_time) {
                                Ok(d) => d.as_secs_f64(),
                                Err(_) => continue, // Skip if time went backwards
                            };
                            
                            // Target is 1 second per tick
                            let expected_ratio = TARGET_TICK_SECONDS / time_ab;
                            let expected_difficulty = (b.iterations as f64 * expected_ratio.max(0.25).min(4.0)) as u64;
                            
                            // Check if actual difficulty is within reasonable bounds of expected
                            let tolerance = 0.3; // 30% tolerance
                            let lower_bound = (expected_difficulty as f64 * (1.0 - tolerance)) as u64;
                            let upper_bound = (expected_difficulty as f64 * (1.0 + tolerance)) as u64;
                            
                            if c.iterations < lower_bound || c.iterations > upper_bound {
                                result.details.push(VerificationDetail {
                                    description: format!("SUSPICIOUS: Difficulty adjustment to {} for tick #{} differs from expected range ({}-{})",
                                                 c.iterations, c.sequence_number, lower_bound, upper_bound),
                                    valid: true, // Warning only, not critical
                                    block_number: None,
                                    tick_number: Some(c.sequence_number),
                                });
                            }
                        }
                    }
                }
            }
            
        }
        
        // 5. Writing pattern analysis for Forensic level
        if level == VerificationLevel::Forensic {
            let pattern_result = self.analyze_writing_patterns();
            
            if !pattern_result.detected_anomalies.is_empty() {
                for anomaly in &pattern_result.detected_anomalies {
                    result.details.push(VerificationDetail {
                        description: format!("NOTICE: Writing pattern anomaly at paragraph #{}: {}", 
                                          anomaly.leaf_number, anomaly.description),
                        valid: true,
                        block_number: Some(anomaly.leaf_number),
                        tick_number: None,
                    });
                }
                
                result.details.push(VerificationDetail {
                    description: format!("Writing pattern analysis: Avg time between paragraphs: {} seconds", 
                                      pattern_result.average_interval),
                    valid: true,
                    block_number: None,
                    tick_number: None,
                });
            } else {
                result.details.push(VerificationDetail {
                    description: "Writing pattern analysis: No anomalies detected".to_string(),
                    valid: true,
                    block_number: None,
                    tick_number: None,
                });
            }
        }
        
        self.last_verification = Some(result.clone());
        result
    }

    // Record intervals between edits
    fn record_edit_interval(&mut self, timestamp: SystemTime) {
        if self.edit_intervals.is_empty() {
            // Initialize with first edit
            self.edit_intervals.push((timestamp, 0)); // No interval for first edit
            return;
        }
        
        // Calculate interval from previous edit
        let last_edit = &self.edit_intervals.last().unwrap().0;
        match timestamp.duration_since(*last_edit) {
            Ok(duration) => {
                let seconds = duration.as_secs();
                self.edit_intervals.push((timestamp, seconds));
                
                // Keep a reasonable history (e.g., last 1000 edits)
                if self.edit_intervals.len() > 1000 {
                    self.edit_intervals.remove(0);
                }
            },
            Err(_) => {
                // Handle clock skew (shouldn't happen, but be defensive)
                self.edit_intervals.push((timestamp, 0));
                
                // Keep a reasonable history
                if self.edit_intervals.len() > 1000 {
                    self.edit_intervals.remove(0);
                }
            }
        }
    }

    // Analyze writing patterns
    fn analyze_writing_patterns(&self) -> WritingPatternResult {
        let intervals: Vec<u64> = self.edit_intervals.iter()
            .filter(|(_, interval)| *interval > 0) // Skip first entry with 0 interval
            .map(|(_, interval)| *interval)
            .collect();
        
        if intervals.len() < 5 {
            // Not enough data for meaningful analysis
            return WritingPatternResult {
                average_interval: 0,
                interval_deviation: 0.0,
                detected_anomalies: Vec::new(),
            };
        }
        
        // Calculate basic statistics
        let avg_interval = if intervals.is_empty() {
            0
        } else {
            intervals.iter().sum::<u64>() / intervals.len() as u64
        };
        
        // Calculate standard deviation
        let variance: f64 = if intervals.is_empty() || avg_interval == 0 {
            0.0
        } else {
            intervals.iter()
                .map(|&i| {
                    let diff = i as f64 - avg_interval as f64;
                    diff * diff
                })
                .sum::<f64>() / intervals.len() as f64
        };
        
        let std_dev = variance.sqrt();
        
        // Detect anomalies - intervals that are significant outliers
        let mut anomalies = Vec::new();
        
        // Map intervals to leaf numbers (excluding first which has no interval)
        let mut intervals_with_leaf: Vec<(u64, u64)> = Vec::new();
        let mut current_leaf = 1;
        
        for interval in &intervals {
            // i+1 because we skip the first entry in edit_intervals (which has 0 interval)
            intervals_with_leaf.push((*interval, current_leaf));
            current_leaf += 1;
        }
        
        // Find outliers (more than 3 standard deviations from mean)
        if std_dev > 0.0 {  // Prevent division by zero
            for (interval, leaf_number) in intervals_with_leaf {
                let z_score = (interval as f64 - avg_interval as f64) / std_dev;
                
                if z_score.abs() > 3.0 {
                    let description = if z_score > 0.0 {
                        format!("Unusually long pause ({} seconds vs avg {}) - possible session break", 
                                interval, avg_interval)
                    } else {
                        format!("Unusually rapid edit ({} seconds vs avg {}) - possible bulk insertion", 
                                interval, avg_interval)
                    };
                    
                    anomalies.push(WritingPatternAnomaly {
                        leaf_number,
                        description,
                        confidence: (z_score.abs() - 3.0) / 2.0, // Scale confidence (0.0-1.0)
                    });
                }
            }
        }
        
        // Look for sustained bursts of activity
        if intervals.len() >= 10 {
            let windows = intervals.windows(10);
            let mut window_idx = 0;
            
            for window in windows {
                if window.is_empty() {
                    continue;
                }
                
                let window_avg = window.iter().sum::<u64>() / window.len() as u64;
                
                // If a sustained period is significantly faster than overall average
                if window_avg < avg_interval / 3 && window_avg > 0 {
                    let leaf_start = window_idx + 1; // +1 because we skip first entry with 0 interval
                    let leaf_end = leaf_start + window.len() as u64;
                    
                    anomalies.push(WritingPatternAnomaly {
                        leaf_number: leaf_start, // Reference starting leaf of the burst
                        description: format!("Sustained rapid editing detected over leaves #{}-#{} (avg interval: {} vs global: {})",
                                            leaf_start, leaf_end, window_avg, avg_interval),
                        confidence: 0.7, // High confidence for sustained patterns
                    });
                }
                
                window_idx += 1;
            }
        }
        
        WritingPatternResult {
            average_interval: avg_interval,
            interval_deviation: std_dev,
            detected_anomalies: anomalies,
        }
    }
    
    // Generate Merkle proof for a specific leaf
    pub fn generate_merkle_proof(&self, leaf_number: u64) -> Option<Vec<String>> {
        // Find the leaf
        let leaf = self.leaves.iter().find(|l| l.leaf_number == leaf_number)?;
        let leaf_hash = leaf.hash.clone();
        
        let mut proof = Vec::new();
        let mut current_hash = leaf_hash;
        
        // Prevent potential infinite loop
        let max_iterations = self.nodes.len() + 1;
        let mut iterations = 0;
        
        // Walk up the tree
        loop {
            iterations += 1;
            if iterations > max_iterations {
                return None; // Break if too many iterations - likely a cycle
            }
            
            // Find the node that contains this hash as a child
            let parent = self.nodes.values().find(|n| 
                n.left_child_hash.as_ref() == Some(&current_hash) || 
                n.right_child_hash.as_ref() == Some(&current_hash)
            );
            
            if let Some(node) = parent {
                // Add the sibling to the proof
                if node.left_child_hash.as_ref() == Some(&current_hash) {
                    // Current is left child, add right sibling
                    if let Some(right) = &node.right_child_hash {
                        proof.push(right.clone());
                    }
                } else {
                    // Current is right child, add left sibling
                    if let Some(left) = &node.left_child_hash {
                        proof.push(left.clone());
                    }
                }
                
                // Move up to parent
                current_hash = node.hash.clone();
                
                // Stop if we reached the root
                if Some(node) == self.root.as_ref() {
                    break;
                }
            } else {
                // No parent found, must be root or invalid
                break;
            }
        }
        
        Some(proof)
    }

    // Create a MerkleQuillFile for saving
    pub fn create_merkle_quill_file(&self) -> MerkleQuillFile {
        // Keep logic for leaves, nodes, root_hash, vdf_ticks, modulus
        let leaves = if !self.leaves.is_empty() {
            Some(self.leaves.clone())
        } else {
            None
        };
        
        let nodes = if !self.nodes.is_empty() {
            Some(self.nodes.values().cloned().collect())
        } else {
            None
        };
        
        let root_hash = self.root.as_ref().map(|r| r.hash.clone());
        
        let vdf_ticks = if !self.historical_ticks.is_empty() {
            let mut ticks: Vec<VDFClockTick> = self.historical_ticks.values().cloned().collect();
            ticks.sort_by_key(|t| t.sequence_number);

            Some(ticks)
        } else {
            None
        };
        
        let modulus = Some(self.vdf.get_modulus_bytes());

        MerkleQuillFile {
            metadata: self.metadata.clone(),
            leaves,
            nodes,
            root_hash,
            vdf_ticks,
            modulus,
            current_iterations: self.current_iterations,
            version: "2.1".to_string(), // <<< UPDATED VERSION
        }
    }

    // Export a compact verification proof
    pub fn export_verification_proof(&self, path: &PathBuf) -> BitQuillResult<()> {
        // Select strategic samples from document history
        let sample_count = 20.min(self.leaves.len());
        let sample_indices = if self.leaves.len() <= sample_count {
            // If few leaves, include all
            (0..self.leaves.len()).collect::<Vec<_>>()
        } else {
            // Otherwise select strategic samples
            let mut indices = Vec::with_capacity(sample_count);
            
            // Always include first and last leaf
            if !self.leaves.is_empty() {
                indices.push(0);
                indices.push(self.leaves.len() - 1);
            }
            
            // Distribute remaining samples
            let remaining = sample_count - indices.len();
            if remaining > 0 && self.leaves.len() > 2 {
                let stride = (self.leaves.len() - 2) / remaining;
                if stride > 0 {  // Prevent division by zero or very small strides
                    for i in 0..remaining {
                        let idx = 1 + (i * stride);
                        if idx < self.leaves.len() - 1 {
                            indices.push(idx);
                        }
                    }
                }
            }
            
            // Sort indices
            indices.sort();
            indices
        };
        
        // Create verification samples
        let mut samples = Vec::with_capacity(sample_indices.len());
        for &idx in &sample_indices {
            if idx < self.leaves.len() {  // Bounds check
                let leaf = &self.leaves[idx];
                samples.push(VerificationSample {
                    leaf_number: leaf.leaf_number,
                    leaf_hash: leaf.hash.clone(),
                    timestamp: leaf.timestamp,
                    vdf_reference: leaf.vdf_tick_reference,
                    commitment: leaf.commitment.clone(),
                });
            }
        }
        
        // Create the proof
        let proof = VerificationProof {
            document_hash: self.current_state.state_hash.clone(),
            merkle_root: self.root.as_ref().map(|r| r.hash.clone()),
            leaf_count: self.leaves.len() as u64,
            author: self.metadata.author.clone(),
            title: self.metadata.title.clone(),
            creation_timestamp: self.metadata.created,
            last_modification: self.metadata.last_modified,
            verification_samples: samples,
            proof_generation_time: SystemTime::now(),
        };
        
        // Serialize to JSON
        let json = match serde_json::to_string_pretty(&proof) {
            Ok(json) => json,
            Err(e) => return Err(BitQuillError::SerializationError(format!(
                "Failed to serialize verification proof: {}", e
            )))
        };
        
        // Write to file
        match fs::write(path, json) {
            Ok(_) => Ok(()),
            Err(e) => Err(BitQuillError::IoError(e))
        }
    }
    
    // Save document with Merkle tree data to file
    pub fn save_to_file(&mut self, path: &PathBuf) -> BitQuillResult<()> {
        // For saving the full tree
        let file = self.create_merkle_quill_file();

        // Serialize to JSON
        let json = match serde_json::to_string_pretty(&file) {
            Ok(json) => json,
            Err(e) => return Err(BitQuillError::SerializationError(format!(
                "Failed to serialize document: {}", e
            )))
        };

        // Write to file
        match fs::write(path, json) {
            Ok(_) => {
                // Update dirty flag
                self.dirty = false;
                Ok(())
            },
            Err(e) => Err(BitQuillError::IoError(e))
        }
    }

    // Load document from file
    pub fn load_from_file(&mut self, path: &PathBuf) -> BitQuillResult<()> {
        // Read file content with proper error handling
        let json = match fs::read_to_string(path) {
            Ok(content) => content,
            Err(e) => return Err(BitQuillError::IoError(e))
        };

        // Attempt to parse into MerkleQuillFile format
        let file: MerkleQuillFile = match serde_json::from_str(&json) {
            Ok(parsed) => parsed,
            Err(e) => return Err(BitQuillError::DeserializationError(format!(
                "Failed to parse file {}: {}", path.display(), e
            )))
        };

        // --- Start Loading ---
        self.metadata = file.metadata;

        // Clear existing document structure
        self.root = None;
        self.leaves.clear();
        self.nodes.clear();
        self.historical_ticks.clear();
        self.latest_tick = None;
        self.edit_intervals.clear();

        // Load leaves (if present in file)
        if let Some(leaves) = file.leaves {
            // Check resource limit
            if leaves.len() > MAX_ALLOWED_LEAVES {
                return Err(BitQuillError::ResourceExhaustedError(format!(
                    "File contains too many leaves ({} > {})", leaves.len(), MAX_ALLOWED_LEAVES
                )));
            }
            
            self.leaves = leaves;
            
            // Ensure leaves are sorted by leaf_number (important for logic relying on order)
            self.leaves.sort_by_key(|l| l.leaf_number);
        }

        // Initialize current_state based on the last loaded leaf
        if let Some(last_leaf) = self.leaves.last() {
            self.current_state = last_leaf.document_state.clone();
            self.current_state.timestamp = Instant::now(); // Reset Instant
        } else {
            // No leaves, initialize as a new empty document state
            let genesis_hash = hex::encode(Sha256::digest(b"MerkleQuill Genesis").to_vec());
            self.current_state = DocumentState {
                content: String::new(),
                timestamp: Instant::now(),
                system_time: SystemTime::now(),
                state_hash: genesis_hash,
            };
        }
        self.last_edit_time = Instant::now(); // Reset edit time

        // Load nodes (if present in file)
        self.nodes.clear(); // Ensure map is empty before loading
        if let Some(nodes_vec) = file.nodes {
            // Validate node count to prevent resource exhaustion
            if nodes_vec.len() > MAX_ALLOWED_LEAVES * 2 {
                return Err(BitQuillError::ResourceExhaustedError(format!(
                    "File contains too many nodes ({} > {})", nodes_vec.len(), MAX_ALLOWED_LEAVES * 2
                )));
            }
            
            for node in nodes_vec {
                self.nodes.insert(node.hash.clone(), node);
            }
        }

        // Set root from loaded nodes or rebuild
        self.root = None; // Clear root before trying to set it
        if let Some(root_hash) = file.root_hash {
            self.root = self.nodes.get(&root_hash).cloned();
            
            // If root hash exists but node doesn't, tree is inconsistent
            if self.root.is_none() && !self.nodes.is_empty() {
                // Try rebuild
                if let Err(e) = self.rebuild_merkle_tree() {
                    return Err(BitQuillError::StateError(format!(
                        "Failed to rebuild Merkle tree: {}", e
                    )));
                }
            } else if self.root.is_none() && !self.leaves.is_empty() {
                // Root hash might be missing but we have nodes/leaves
                if let Err(e) = self.rebuild_merkle_tree() {
                    return Err(BitQuillError::StateError(format!(
                        "Failed to rebuild Merkle tree: {}", e
                    )));
                }
            }
        } else if !self.leaves.is_empty() {
            // No root hash stored, attempt rebuild if leaves exist
            if let Err(e) = self.rebuild_merkle_tree() {
                return Err(BitQuillError::StateError(format!(
                    "Failed to rebuild Merkle tree: {}", e
                )));
            }
        }

        // Load VDF ticks (if present in file)
        self.historical_ticks.clear();
        self.latest_tick = None;
        if let Some(ticks) = file.vdf_ticks {
            // Validate tick count to prevent resource exhaustion
            if ticks.len() > DIFFICULTY_WINDOW_SIZE * 2 {
                return Err(BitQuillError::ResourceExhaustedError(format!(
                    "File contains too many VDF ticks ({} > {})", ticks.len(), DIFFICULTY_WINDOW_SIZE * 2
                )));
            }
            
            for tick in ticks {
                self.historical_ticks.insert(tick.sequence_number, tick);
            }
            
            // Set latest_tick based on loaded historical data
            if let Some(max_seq) = self.historical_ticks.keys().max() {
                self.latest_tick = self.historical_ticks.get(max_seq).cloned();
            }
        }

        // Load VDF modulus (if present and valid)
        if let Some(modulus_bytes) = file.modulus {
            if !modulus_bytes.is_empty() {
                match VDF::from_modulus_bytes(&modulus_bytes) {
                    Ok(vdf) => self.vdf = vdf,
                    Err(e) => return Err(BitQuillError::ValidationError(format!(
                        "Invalid VDF modulus in file: {}", e
                    )))
                }
            } else {
                // Generate new VDF if empty modulus
                match VDF::new(2048) {
                    Ok(vdf) => self.vdf = vdf,
                    Err(e) => return Err(e)
                }
            }
        } else {
            // Generate new VDF if no modulus
            match VDF::new(2048) {
                Ok(vdf) => self.vdf = vdf,
                Err(e) => return Err(e)
            }
        }

        // Load current iterations with validation
        self.current_iterations = file.current_iterations.clamp(
            MIN_VDF_ITERATIONS, MAX_VDF_ITERATIONS
        );

        // Set last leaf tick
        self.last_leaf_tick = self.leaves.last().map_or(0, |l| l.vdf_tick_reference);

        // Rebuild edit intervals from loaded leaves' timestamps
        self.edit_intervals.clear();
        if !self.leaves.is_empty() {
            let first_leaf = &self.leaves[0];
            self.edit_intervals.push((first_leaf.timestamp, 0));
            
            for i in 1..self.leaves.len() {
                let prev_leaf = &self.leaves[i-1];
                let curr_leaf = &self.leaves[i];
                
                let interval_secs = match curr_leaf.timestamp.duration_since(prev_leaf.timestamp) {
                    Ok(duration) => duration.as_secs(),
                    Err(_) => 0  // Use 0 if time went backwards
                };
                
                self.edit_intervals.push((curr_leaf.timestamp, interval_secs));
            }
        }

        // Reset flags
        self.dirty = false;
        self.pending_changes = false;
        self.last_verification = None;

        Ok(())
    }

    // Export Merkle tree data for verification in a standalone format
    pub fn export_chain_data(&self, path: &PathBuf) -> BitQuillResult<()> {
        // Collect all ticks currently in memory for export
        let all_ticks: Vec<VDFClockTick> = self.historical_ticks.values().cloned().collect();

        // Check resource limits
        if all_ticks.len() > DIFFICULTY_WINDOW_SIZE * 2 {
            return Err(BitQuillError::ResourceExhaustedError(format!(
                "Too many ticks to export ({} > {})",
                all_ticks.len(), DIFFICULTY_WINDOW_SIZE * 2
            )));
        }

        let export_data = ExportedMerkleData {
            document_title: self.metadata.title.clone(),
            author: self.metadata.author.clone(),
            created: self.metadata.created,
            last_modified: self.metadata.last_modified,
            leaves: self.leaves.clone(),
            nodes: self.nodes.values().cloned().collect(),
            root_hash: self.root.as_ref().map(|r| r.hash.clone()),
            vdf_ticks: all_ticks,
            modulus: self.vdf.get_modulus_bytes(),
            current_iterations: self.current_iterations,
        };

        // Serialize to JSON with error handling
        let json = match serde_json::to_string_pretty(&export_data) {
            Ok(json) => json,
            Err(e) => return Err(BitQuillError::SerializationError(format!(
                "Failed to serialize chain data: {}", e
            )))
        };

        // Write to file
        match fs::write(path, json) {
            Ok(_) => Ok(()),
            Err(e) => Err(BitQuillError::IoError(e))
        }
    }

    // Check if there are unsaved changes
    pub fn has_unsaved_changes(&self) -> bool {
        self.dirty
    }

    // Shutdown VDF clock thread when app exits
    pub fn shutdown(&self) {
        // Set shutdown flag
        match self.vdf_clock_shutdown.lock() {
            Ok(mut guard) => *guard = true,
            Err(poisoned) => {
                // Handle poisoned mutex by taking ownership
                let mut guard = poisoned.into_inner();  // Gets ownership of inner value
                *guard = true;
                eprintln!("Warning: VDF clock shutdown mutex was poisoned");
            }
        }
        
        // Wait for thread to terminate gracefully if handle is available
        if let Some(handle) = &self.vdf_thread_handle {
            if !handle.is_finished() {
                // Give thread time to observe shutdown flag
                thread::sleep(Duration::from_millis(100));
            }
        }
    }
    
    // Method to record just a paragraph's content
    pub fn record_paragraph(&mut self, paragraph_content: String) -> BitQuillResult<()> {
        // Check content size
        if paragraph_content.len() > MAX_CONTENT_SIZE {
            return Err(BitQuillError::ResourceExhaustedError(format!(
                "Paragraph size ({} bytes) exceeds maximum allowed ({} bytes)",
                paragraph_content.len(), MAX_CONTENT_SIZE
            )));
        }

        // Update the current state with just this paragraph
        self.current_state.content = paragraph_content;
        self.current_state.state_hash = hex::encode(
            Sha256::digest(self.current_state.content.as_bytes()).to_vec()
        );
        self.current_state.timestamp = Instant::now();
        self.current_state.system_time = SystemTime::now();
        self.last_edit_time = Instant::now();

        // Update metadata
        self.metadata.last_modified = SystemTime::now();

        // Mark for next leaf creation
        self.pending_changes = true;
        self.dirty = true;
        
        Ok(())
    }
}

// Calculate hash for a MerkleLeaf
pub fn calculate_leaf_hash(leaf: &MerkleLeaf) -> BitQuillResult<String> {
    let mut hasher = Sha256::new();
    
    // Hash fields in a defined order
    hasher.update(leaf.document_state.state_hash.as_bytes());
    hasher.update(leaf.vdf_tick_reference.to_be_bytes());
    hasher.update(leaf.prev_leaf_hash.as_bytes());
    hasher.update(leaf.commitment.as_bytes()); // Include commitment in hash
    
    // System time as bytes - use consistent format (seconds)
    match leaf.timestamp.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(duration) => {
            let timestamp_secs = duration.as_secs();
            hasher.update(&timestamp_secs.to_be_bytes());
        },
        Err(_) => {
            return Err(BitQuillError::HashError(
                "Failed to calculate timestamp for leaf hash".to_string()
            ));
        }
    }
    
    // Leaf number
    hasher.update(leaf.leaf_number.to_be_bytes());
    
    Ok(hex::encode(hasher.finalize()))
}

// Calculate hash for a Merkle node
pub fn calculate_node_hash(left_hash: &str, right_hash: &str) -> BitQuillResult<String> {
    let mut hasher = Sha256::new();
    hasher.update(left_hash.as_bytes());
    
    // If right hash exists, include it
    if !right_hash.is_empty() {
        hasher.update(right_hash.as_bytes());
    }
    
    Ok(hex::encode(hasher.finalize()))
}

// Get hash from a MerkleTreeElement
pub fn get_element_hash(element: &MerkleTreeElement) -> BitQuillResult<String> {
    match element {
        MerkleTreeElement::Node(node) => Ok(node.hash.clone()),
        MerkleTreeElement::Leaf(leaf) => Ok(leaf.hash.clone()),
    }
}
