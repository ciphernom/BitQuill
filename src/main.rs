use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyModifiers},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use num_bigint::{BigUint, RandBigInt};
use num_integer::Integer;
use num_traits::One;
use rand::thread_rng;
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, VecDeque},
    io,
    sync::{mpsc, Arc, Mutex},
    thread,
    time::{Duration, Instant, SystemTime},
    path::{PathBuf, Path},
    fs,
    env,
};
use tui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Span, Line},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Terminal,
};
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Local};
use hex;
// Required for config dir
use dirs;

// Maximum number of recent files to remember
const MAX_RECENT_FILES: usize = 10;

// Auto-save interval in seconds
const AUTO_SAVE_INTERVAL: u64 = 60;

// File extension for BitQuill documents
const BITQUILL_FILE_EXT: &str = "bq";

// File extension for BitQuill chain data
const BITQUILL_CHAIN_EXT: &str = "bqc";

// Target time for VDF ticks (1 second)
const TARGET_TICK_SECONDS: f64 = 1.0;

// Initial VDF difficulty (iterations)
const INITIAL_VDF_ITERATIONS: u64 = 10_000;

// Minimum VDF difficulty
const MIN_VDF_ITERATIONS: u64 = 1_000;

// Maximum VDF difficulty
const MAX_VDF_ITERATIONS: u64 = 100_000;

// Merkle leaf created every N ticks
const LEAF_TICK_INTERVAL: u64 = 100; 

// Minimum ticks between leaves when pending changes exist
const MIN_TICKS_FOR_PENDING_LEAF: u64 = 100;

// Number of ticks to store for difficulty adjustment
const DIFFICULTY_WINDOW_SIZE: usize = 2016;

// Frequency of difficulty adjustments (ticks)
const DIFFICULTY_ADJUSTMENT_INTERVAL: u64 = 2016;

// Document state representing the content at a specific point
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
struct DocumentState {
    content: String,      // Will now store only this paragraph's content
    #[serde(skip)]
    timestamp: Instant,
    #[serde(with = "timestamp_serde")]
    system_time: SystemTime,
    state_hash: String,   // Hash of just this paragraph's content
}

// For Instant serialization, we need to convert to SystemTime
mod timestamp_serde {
    use serde::{Deserialize, Deserializer, Serializer};
    use std::time::SystemTime;

    pub fn serialize<S>(time: &SystemTime, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let timestamp = time
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(serde::ser::Error::custom)?
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

// VDF proof for efficient verification using Wesolowski's construction
#[derive(Clone, Debug, Serialize, Deserialize)]
struct VDFProof {
    y: Vec<u8>,     // Result y = x^(2^t) mod N
    pi: Vec<u8>,    // Proof π = x^q mod N
    l: Vec<u8>,     // Prime l (serialized as bytes)
    r: Vec<u8>,     // Remainder r = 2^t mod l (serialized as bytes)
}

// A single tick from the VDF clock
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
struct VDFClockTick {
    output_y: Vec<u8>,      // VDF output
    proof: VDFProof,        // VDF proof
    sequence_number: u64,   // Increasing sequence number
    prev_output_hash: String, // Hash of previous output for verification
    #[serde(skip)]
    timestamp: Instant,     // Wall clock time when generated
    #[serde(with = "timestamp_serde")]
    system_time: SystemTime, // System time for serialization
}

// Merkle leaf representing document state at a point in time
#[derive(Clone, Debug, Serialize, Deserialize)]
struct MerkleLeaf {
    document_state: DocumentState,  // Document content and metadata
    vdf_tick_reference: u64,        // VDF tick number
    prev_leaf_hash: String,         // Hash of previous leaf for ordering
    #[serde(with = "timestamp_serde")]
    timestamp: SystemTime,          // Wall clock time
    hash: String,                   // Hash of this leaf
    leaf_number: u64,               // Sequential leaf number
    commitment: String,             // field for content-VDF binding
}

// Merkle tree node (internal node)
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
struct MerkleNode {
    hash: String,                  // Hash of this node
    height: usize,                 // Height in the tree
    // Children are stored separately to avoid recursive serialization issues
    left_child_hash: Option<String>, // Hash of left child
    right_child_hash: Option<String>, // Hash of right child
}

// Enum to represent Merkle tree elements
#[derive(Clone, Debug)]
enum MerkleTreeElement {
    Node(MerkleNode),
    Leaf(MerkleLeaf),
}

// Document metadata
#[derive(Clone, Debug, Serialize, Deserialize)]
struct DocumentMetadata {
    title: String,
    author: String,
    created: SystemTime,
    last_modified: SystemTime,
    version: String,
    keywords: Vec<String>,
    description: String,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum VerificationLevel {
    Basic,     // Quick, superficial check
    Standard,  // Normal level of checking (default)
    Thorough,  // Comprehensive verification
    Forensic   // Exhaustive verification including statistical analysis
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

// Adding Default implementation for VDFClockTick
impl Default for VDFClockTick {
    fn default() -> Self {
        Self {
            output_y: Vec::new(),
            proof: VDFProof {
                y: Vec::new(),
                pi: Vec::new(),
                l: Vec::new(),
                r: Vec::new(),
            },
            sequence_number: 0,
            prev_output_hash: String::new(),
            timestamp: Instant::now(),
            system_time: SystemTime::now(),
        }
    }
}

// MerkleQuill file format (replacing BitQuill format)
#[derive(Clone, Debug, Serialize, Deserialize)]
struct MerkleQuillFile {
    metadata: DocumentMetadata,
    leaves: Option<Vec<MerkleLeaf>>,
    nodes: Option<Vec<MerkleNode>>,  // Store nodes separately to avoid recursion
    root_hash: Option<String>,       // Store just the root hash
    vdf_ticks: Option<Vec<VDFClockTick>>,
    modulus: Option<Vec<u8>>,         // RSA modulus for verification
    current_iterations: u64,          // Current VDF difficulty
    version: String,                  // File format version
}

impl MerkleQuillFile {
    fn new(content: String, metadata: DocumentMetadata) -> Self {
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

// VDF implementation using sequential squaring in an RSA group with Wesolowski proofs
struct VDF {
    modulus: Arc<BigUint>,
}

impl VDF {
    // Create a new VDF with a proper RSA modulus
    fn new(bit_length: usize) -> Self {
        // Generate two large primes p and q to create RSA modulus N = p * q
        let p = Self::generate_prime(bit_length / 2);
        let q = Self::generate_prime(bit_length / 2);
        let modulus = Arc::new(&p * &q);

        VDF { modulus }
    }

    // Generate a prime number of the specified bit length
    fn generate_prime(bit_length: usize) -> BigUint {
        let mut rng = thread_rng();

        loop {
            // Generate a random odd number of the required bit length
            let mut candidate = rng.gen_biguint(bit_length as u64);

            // Ensure the number is odd (all primes except 2 are odd)
            if candidate.is_even() {
                candidate += BigUint::one();
            }

            // Ensure the number has the correct bit length
            if candidate.bits() != bit_length as u64 {
                continue;
            }

            // Check primality using the Miller-Rabin test
            if Self::is_prime(&candidate, 40) { // Increased rounds for stronger primality testing
                return candidate;
            }
        }
    }

    // Miller-Rabin primality test
    fn is_prime(n: &BigUint, k: usize) -> bool {
        if n <= &BigUint::one() {
            return false;
        }

        if n == &BigUint::from(2u32) || n == &BigUint::from(3u32) {
            return true;
        }

        if n.is_even() {
            return false;
        }

        // Write n-1 as 2^r * d where d is odd
        let one = BigUint::one();
        let two = BigUint::from(2u32);
        let n_minus_1 = n - &one;

        let mut r = 0;
        let mut d = n_minus_1.clone();

        while d.is_even() {
            d >>= 1;
            r += 1;
        }

        // Witness loop
        let mut rng = thread_rng();

        'witness: for _ in 0..k {
            // Choose random a in the range [2, n-2]
            let a = rng.gen_biguint_range(&two, &(n_minus_1.clone() - &one));

            // Compute a^d mod n
            let mut x = a.modpow(&d, n);

            if x == one || x == n_minus_1 {
                continue 'witness;
            }

            for _ in 0..r-1 {
                x = x.modpow(&two, n);
                if x == n_minus_1 {
                    continue 'witness;
                }
            }

            return false;
        }

        true
    }

    // Generate a small prime for the Wesolowski proof
    fn generate_proof_prime() -> BigUint {
        // Generate a ~128-bit prime for l as recommended by Wesolowski
        Self::generate_prime(128)
    }

    // Compute the VDF with Wesolowski proof: x^(2^t) mod N
    fn compute_with_proof(&self, input: &[u8], iterations: u64) -> VDFProof {
        // Hash the input to get our starting value
        let mut hasher = Sha256::new();
        hasher.update(input);
        let hash = hasher.finalize();
        let x = BigUint::from_bytes_be(&hash);

        // Get a reference to the modulus
        let modulus = &*self.modulus;

        // Generate proof prime l (fixed size for proof efficiency)
        let l = Self::generate_proof_prime();

        // Calculate r = 2^t mod l
        let r = BigUint::from(2u32).modpow(&BigUint::from(iterations), &l);

        // Calculate y = x^(2^t) mod N (iterative squaring)
        let mut y = x.clone();
        for _ in 0..iterations {
            y = (&y * &y) % modulus;
        }

        // For large t, calculating 2^t directly might overflow.
        // We'll use modpow for the calculation of q

        // First, find the quotient q = floor((2^t - r) / l)
        // We can calculate this as q = floor(2^t / l) - floor(r / l)
        // Since r < l, floor(r / l) = 0, so q = floor(2^t / l)
        
        // For large t, we calculate q = floor(2^t / l) using modular arithmetic
        // First, calculate 2^t mod l
        let two_t_mod_l = BigUint::from(2u32).modpow(&BigUint::from(iterations), &l);
        
        // Then, use the fact that floor(2^t / l) = floor((2^t - (2^t mod l)) / l)
        // This avoids calculating the full 2^t value
        let q_times_l = BigUint::from(2u32).pow(iterations as u32) - two_t_mod_l;
        let q = &q_times_l / &l;

        // Calculate proof π = x^q mod N
        let pi = x.modpow(&q, modulus);

        VDFProof {
            y: y.to_bytes_be(),
            pi: pi.to_bytes_be(),
            l: l.to_bytes_be(),
            r: r.to_bytes_be(),
        }
    }

    // Verify a VDF output using Wesolowski's efficient verification
    fn verify(&self, input: &[u8], proof: &VDFProof) -> bool {
        // Hash the input to get our starting value x
        let mut hasher = Sha256::new();
        hasher.update(input);
        let hash = hasher.finalize();
        let x = BigUint::from_bytes_be(&hash);

        // Get a reference to the modulus
        let modulus = &*self.modulus;

        // Parse y and π from the proof
        let y = BigUint::from_bytes_be(&proof.y);
        let pi = BigUint::from_bytes_be(&proof.pi);
        let l = BigUint::from_bytes_be(&proof.l);
        let r = BigUint::from_bytes_be(&proof.r);

        // Verify: y == pi^l * x^r mod N
        let pi_l = pi.modpow(&l, modulus);
        let x_r = x.modpow(&r, modulus);
        let right_side = (pi_l * x_r) % modulus;

        y == right_side
    }

    // Convert desired delay time to iteration count
    fn time_to_iterations(&self, time: Duration) -> u64 {
        // Calculate iterations based on calibration
        let seconds = time.as_secs_f64();
        let iterations_per_second = 10_000_000.0; // Calibrated iterations per second
        
        // Calculate with minimum threshold
        let iterations = (seconds * iterations_per_second) as u64;
        iterations.max(MIN_VDF_ITERATIONS)
    }

    // Get the modulus as bytes for serialization
    fn get_modulus_bytes(&self) -> Vec<u8> {
        self.modulus.to_bytes_be()
    }

    // Recreate VDF from serialized modulus
    fn from_modulus_bytes(bytes: &[u8]) -> Self {
        let modulus = Arc::new(BigUint::from_bytes_be(bytes));
        VDF { modulus }
    }
}

// Verification result with details
#[derive(Debug, Clone)]
struct VerificationResult {
    valid: bool,
    details: Vec<VerificationDetail>,
    timestamp: Instant,
    level: VerificationLevel,
}

// Detailed verification step
#[derive(Debug, Clone)]
struct VerificationDetail {
    description: String,
    valid: bool,
    block_number: Option<u64>,
    tick_number: Option<u64>,
}

// Document chain manager using Merkle tree with VDF clock integration
struct MerkleDocument {
    // Merkle tree components
    root: Option<MerkleNode>,
    leaves: Vec<MerkleLeaf>,
    nodes: HashMap<String, MerkleNode>, // Nodes indexed by hash
    
    // Writing pattern analysis
    edit_intervals: Vec<(SystemTime, u64)>,
    
    // Current document state
    current_state: DocumentState,
    
    // VDF components
    vdf: VDF,
    vdf_clock_receiver: mpsc::Receiver<VDFClockTick>,
    vdf_iterations_sender: mpsc::Sender<u64>, // Channel to update VDF difficulty
    vdf_clock_shutdown: Arc<Mutex<bool>>,
    latest_tick: Option<VDFClockTick>,
    historical_ticks: HashMap<u64, VDFClockTick>,
    
    // Timing and adjustment
    tick_timestamps: VecDeque<(u64, SystemTime)>,
    current_iterations: u64,
    target_tick_interval: Duration,
    last_leaf_tick: u64,
    
    // Document editing status
    pending_changes: bool,
    last_edit_time: Instant,
    
    // Document metadata
    metadata: DocumentMetadata,
    
    // File status
    dirty: bool,
    
    // Verification status
    last_verification: Option<VerificationResult>,
}

 //  struct for writing pattern analysis results
    #[derive(Clone, Debug)]
    struct WritingPatternAnomaly {
        leaf_number: u64,
        description: String,
        confidence: f64, // How confident we are this is an anomaly (0.0-1.0)
    }

    #[derive(Clone, Debug)]
    struct WritingPatternResult {
        average_interval: u64,
        interval_deviation: f64,
        detected_anomalies: Vec<WritingPatternAnomaly>,
    }
    //  struct for compact verification proof
    #[derive(Serialize, Deserialize)]
    struct VerificationProof {
        document_hash: String,
        merkle_root: Option<String>,
        leaf_count: u64,
        author: String,
        title: String,
        #[serde(with = "timestamp_serde")]
        creation_timestamp: SystemTime,
        #[serde(with = "timestamp_serde")]
        last_modification: SystemTime,
        verification_samples: Vec<VerificationSample>,
        #[serde(with = "timestamp_serde")]
        proof_generation_time: SystemTime,
    }

    #[derive(Serialize, Deserialize)]
    struct VerificationSample {
        leaf_number: u64,
        leaf_hash: String,
        #[serde(with = "timestamp_serde")]
        timestamp: SystemTime,
        vdf_reference: u64,
        commitment: String,
    }
    
impl MerkleDocument {
    fn new() -> Self {
        // Production-grade VDF with 2048-bit modulus
        let vdf = VDF::new(2048);
        let modulus_clone = vdf.modulus.clone();

        // Create channels for VDF clock and iterations update
        let (vdf_clock_sender, vdf_clock_receiver) = mpsc::channel();
        let (iterations_sender, iterations_receiver) = mpsc::channel();
        
        let shutdown_flag = Arc::new(Mutex::new(false));
        let shutdown_clone = shutdown_flag.clone();

        // Initial difficulty
        let initial_iterations = INITIAL_VDF_ITERATIONS;

        // Start the VDF clock thread with adjustable difficulty
        thread::spawn(move || {
            let mut current_input = Sha256::digest(b"VDF Clock Genesis").to_vec();
            let mut sequence_number = 0;
            let mut current_iterations = initial_iterations;
            
            let modulus = &*modulus_clone;

            while !*shutdown_clone.lock().unwrap() {
                // Check for updated iterations
                if let Ok(new_iterations) = iterations_receiver.try_recv() {
                    current_iterations = new_iterations;
                }
                
                // Calculate previous output hash for verification
                let prev_output_hash = hex::encode(Sha256::digest(&current_input).to_vec());

                // Compute VDF with current difficulty
                let proof = compute_vdf_proof(&current_input, current_iterations, modulus);

                // Create tick with system time
                let tick = VDFClockTick {
                    output_y: proof.y.clone(),
                    proof,
                    sequence_number,
                    prev_output_hash,
                    timestamp: Instant::now(),
                    system_time: SystemTime::now(),
                };

                // Send tick to main thread
                if vdf_clock_sender.send(tick.clone()).is_err() {
                    eprintln!("VDF clock channel closed. Shutting down thread.");
                    break; // Main thread terminated
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

        MerkleDocument {
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
            latest_tick: None,
            edit_intervals: Vec::new(),
            historical_ticks: HashMap::new(),
            tick_timestamps: VecDeque::with_capacity(DIFFICULTY_WINDOW_SIZE),
            current_iterations: initial_iterations,
            target_tick_interval: Duration::from_secs_f64(TARGET_TICK_SECONDS),
            last_leaf_tick: 0,
            pending_changes: false,
            last_edit_time: Instant::now(),
            metadata: DocumentMetadata::default(),
            dirty: false,
            last_verification: None,
        }
    }

    // Process VDF clock ticks and create leaves when needed
    fn process_vdf_ticks(&mut self) -> bool {
        let  leaf_created = false;

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
            
            // REMOVE automatic leaf creation code:
            // if (tick.sequence_number % LEAF_TICK_INTERVAL == 0) || 
            //    (self.pending_changes && tick.sequence_number >= self.last_leaf_tick + MIN_TICKS_FOR_PENDING_LEAF) {
            //     self.create_leaf(tick.sequence_number);
            //     leaf_created = true;
            //     self.pending_changes = false;
            //     self.last_leaf_tick = tick.sequence_number;
            // }
            
            // Keep difficulty adjustment
            if tick.sequence_number % DIFFICULTY_ADJUSTMENT_INTERVAL == 0 {
                self.adjust_difficulty();
            }
        }

        // Rest of the function stays the same
        leaf_created // This will now always be false unless manual creation happens
}
    
    // Adjust VDF difficulty based on historical timing
    fn adjust_difficulty(&mut self) {
        if self.tick_timestamps.len() < 100 { // Need reasonable sample size
            return; // Not enough data to adjust
        }
        
        // Get first and last timestamps in the window
        let first = self.tick_timestamps.front().unwrap();
        let last = self.tick_timestamps.back().unwrap();
        
        let elapsed_ticks = last.0 - first.0;
        if elapsed_ticks < 10 { // Need at least 10 ticks to calculate
            return;
        }
        
        // Calculate average time per tick
        let elapsed_time = match last.1.duration_since(first.1) {
            Ok(duration) => duration,
            Err(_) => return, // Clock skew, can't adjust properly
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
        let new_iterations = new_iterations.max(MIN_VDF_ITERATIONS).min(MAX_VDF_ITERATIONS);
        
        // Only send update if significant change
        if (new_iterations as f64 / self.current_iterations as f64) < 0.9 || 
           (new_iterations as f64 / self.current_iterations as f64) > 1.1 {
            if let Err(e) = self.vdf_iterations_sender.send(new_iterations) {
                eprintln!("Failed to update VDF iterations: {}", e);
            } else {
                self.current_iterations = new_iterations;
            }
        }
    }

    // Create a new Merkle leaf for the current document state
  fn create_leaf(&mut self, tick_number: u64) {
    if let Some(tick) = self.historical_ticks.get(&tick_number) {
        // Create new leaf with CONSISTENT timestamp
        let leaf_timestamp = SystemTime::now();
        
        let prev_leaf_hash = self.leaves.last().map_or(
            hex::encode(Sha256::digest(b"MerkleQuill Genesis Leaf").to_vec()),
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
        let hash = calculate_leaf_hash(&temp_leaf);
        
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
        self.rebuild_merkle_tree();
        self.dirty = true;
        
        // Add to writing pattern analysis (new)
        self.record_edit_interval(leaf_timestamp);
    } else {
        // Log warning if tick not found - this shouldn't happen in normal operation
        eprintln!("Warning: Attempted to create leaf with missing VDF tick #{}", tick_number);
    }
}
    
    // Rebuild the Merkle tree from leaves
    fn rebuild_merkle_tree(&mut self) {
        if self.leaves.is_empty() {
            self.root = None;
            self.nodes.clear();
            return;
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
            height += 1;
            let mut next_level = Vec::new();
            
            // Process pairs of nodes
            for chunk in current_level.chunks(2) {
                if chunk.len() == 2 {
                    let left = &chunk[0];
                    let right = &chunk[1];
                    
                    let left_hash = get_element_hash(left);
                    let right_hash = get_element_hash(right);
                    
                    // Calculate node hash
                    let hash = calculate_node_hash(&left_hash, &right_hash);
                    
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
    }

    // Record a change to the document content
    fn record_change(&mut self, new_content: String) {
        // Skip if content hasn't changed
        if new_content == self.current_state.content {
            return;
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
    }

    // Get the current document content by combining all paragraphs
    fn get_current_content(&self) -> String {
        let paragraphs: Vec<&str> = self.leaves.iter()
            .map(|leaf| leaf.document_state.content.as_str())
            .collect();
            
        // Join paragraphs with newlines
        paragraphs.join("\n")
    }

    // Get information about leaves for display
    fn get_leaf_history(&self) -> Vec<String> {
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
    fn get_tree_structure(&self) -> Vec<String> {
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
    fn get_tick_count(&self) -> usize {
        self.historical_ticks.len()
    }

    // Verify the integrity of the Merkle tree and VDF clock chain
 
    
    //  method to select strategic tick samples across the timeline
    fn select_strategic_tick_samples(tick_numbers: &[u64], sample_count: usize) -> Vec<u64> {
        if tick_numbers.len() <= sample_count || tick_numbers.len() <= 20 {
            // If we have fewer ticks than requested sample count, return all
            return tick_numbers.to_vec();
        }

        let mut samples = Vec::with_capacity(sample_count);
        
        // Always include the first 5 ticks (genesis)
        let first_n = tick_numbers.len().min(5);
        samples.extend_from_slice(&tick_numbers[0..first_n]);
        
        // Always include the most recent 10 ticks
        let last_n_start = tick_numbers.len().saturating_sub(10);
        samples.extend_from_slice(&tick_numbers[last_n_start..]);
        
        // Distribute remaining samples evenly across the timeline
        let remaining_samples = sample_count.saturating_sub(samples.len());
        if remaining_samples > 0 && tick_numbers.len() > 15 {
            let range_start = 5; // After first 5
            let range_end = tick_numbers.len() - 10; // Before last 10
            let range_size = range_end - range_start;
            
            if range_size > 0 {
                let stride = range_size / remaining_samples;
                for i in 0..remaining_samples {
                    let idx = range_start + (i * stride);
                    if idx < range_end {
                        samples.push(tick_numbers[idx]);
                    }
                }
            }
        }
        
        // Sort and deduplicate
        samples.sort();
        samples.dedup();
        
        samples
    }
    
    fn verify_merkle_integrity(&mut self, level: VerificationLevel) -> VerificationResult {

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

        // 1. For each paragraph (leaf), ensure it's properly linked to the previous one
        let mut expected_prev_hash = hex::encode(Sha256::digest(b"MerkleQuill Genesis Leaf").to_vec());
        
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
            let calculated_hash = calculate_leaf_hash(leaf);
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
        let mut temp_doc = MerkleDocument::new();
        temp_doc.leaves = self.leaves.clone();
        temp_doc.rebuild_merkle_tree();
        
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
        
        // 4. Verify VDF ticks - SIMPLIFIED
        if level != VerificationLevel::Basic && self.historical_ticks.len() >= 2 {
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
                let idx = tick_numbers.len() - 1 - i;
                if idx < tick_numbers.len() && !key_ticks.contains(&tick_numbers[idx]) {
                    key_ticks.push(tick_numbers[idx]);
                }
            }
            
            key_ticks.sort();
            
            // Verify each key tick's proof is valid
            for &tick_num in &key_ticks {
                if let Some(tick) = self.historical_ticks.get(&tick_num) {
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
                            
                            // Verify proof
                            let input_for_curr = prev_tick.output_y.clone();
                            if !self.vdf.verify(&input_for_curr, &tick.proof) {
                                // For paragraph model, proof issues are less critical
                                result.details.push(VerificationDetail {
                                    description: format!("NOTE: VDF tick #{} timestamp verification issue", tick_num),
                                    valid: true, // Don't fail
                                    block_number: None,
                                    tick_number: Some(tick_num),
                                });
                            }
                        }
                    }
                }
            }
        }
        
        // 5. Still do writing pattern analysis for Forensic level
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

    //  method to record intervals between edits
    fn record_edit_interval(&mut self, timestamp: SystemTime) {
        if self.edit_intervals.is_empty() {
            // Initialize with first edit
            self.edit_intervals.push((timestamp, 0)); // No interval for first edit
            return;
        }
        
        // Calculate interval from previous edit
        let last_edit = self.edit_intervals.last().unwrap().0;
        if let Ok(duration) = timestamp.duration_since(last_edit) {
            let seconds = duration.as_secs();
            self.edit_intervals.push((timestamp, seconds));
            
            // Keep a reasonable history (e.g., last 1000 edits)
            if self.edit_intervals.len() > 1000 {
                self.edit_intervals.remove(0);
            }
        }
    }

    //  method to analyze writing patterns
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
        let avg_interval = intervals.iter().sum::<u64>() / intervals.len() as u64;
        
        // Calculate standard deviation
        let variance: f64 = intervals.iter()
            .map(|&i| {
                let diff = i as f64 - avg_interval as f64;
                diff * diff
            })
            .sum::<f64>() / intervals.len() as f64;
        
        let std_dev = variance.sqrt();
        
        // Detect anomalies - intervals that are significant outliers
        let mut anomalies = Vec::new();
        
        // Map intervals to leaf numbers (excluding first which has no interval)
        let mut intervals_with_leaf: Vec<(u64, u64)> = Vec::new();
        let mut current_leaf = 1;
        
        for (_i, interval) in intervals.iter().enumerate() {
            // i+1 because we skip the first entry in edit_intervals (which has 0 interval)
            intervals_with_leaf.push((*interval, current_leaf));
            current_leaf += 1;
        }
        
        // Find outliers (more than 3 standard deviations from mean)
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
        
        // Look for sustained bursts of activity
        if intervals.len() >= 10 {
            let windows = intervals.windows(10);
            let mut window_idx = 0;
            
            for window in windows {
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
    fn generate_merkle_proof(&self, leaf_number: u64) -> Option<Vec<String>> {
        // Find the leaf
        let leaf = self.leaves.iter().find(|l| l.leaf_number == leaf_number)?;
        let leaf_hash = leaf.hash.clone();
        
        let mut proof = Vec::new();
        let mut current_hash = leaf_hash;
        
        // Walk up the tree
        loop {
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
    fn create_merkle_quill_file(&self) -> MerkleQuillFile {

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
             let tick_save_limit = 100; // Keep limit for VDF ticks in main file
             if ticks.len() > tick_save_limit {
                 ticks = ticks[ticks.len() - tick_save_limit..].to_vec();
             }
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
    fn export_verification_proof(&self, path: &PathBuf) -> io::Result<()> {
        // Select strategic samples from document history
        let sample_count = 20.min(self.leaves.len());
        let sample_indices = if self.leaves.len() <= sample_count {
            // If few leaves, include all
            (0..self.leaves.len()).collect::<Vec<_>>()
        } else {
            // Otherwise select strategic samples
            let mut indices = Vec::with_capacity(sample_count);
            
            // Always include first and last leaf
            indices.push(0);
            indices.push(self.leaves.len() - 1);
            
            // Distribute remaining samples
            let remaining = sample_count - 2;
            if remaining > 0 && self.leaves.len() > 2 {
                let stride = (self.leaves.len() - 2) / remaining;
                for i in 0..remaining {
                    let idx = 1 + (i * stride);
                    if idx < self.leaves.len() - 1 {
                        indices.push(idx);
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
            let leaf = &self.leaves[idx];
            samples.push(VerificationSample {
                leaf_number: leaf.leaf_number,
                leaf_hash: leaf.hash.clone(),
                timestamp: leaf.timestamp,
                vdf_reference: leaf.vdf_tick_reference,
                commitment: leaf.commitment.clone(),
            });
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
        let json = serde_json::to_string_pretty(&proof)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;
        
        // Write to file
        fs::write(path, json)
    }
    
    // Save document with Merkle tree data to file
    fn save_to_file(&mut self, path: &PathBuf) -> io::Result<()> {
        // Reconstruct full document content from paragraph leaves
        let full_content = if !self.leaves.is_empty() {
            let paragraphs: Vec<&str> = self.leaves.iter()
                .map(|leaf| leaf.document_state.content.as_str())
                .collect();
            paragraphs.join("\n")
        } else {
            // If no leaves, use current state
            self.current_state.content.clone()
        };

        // For saving the full tree
        let leaves = if !self.leaves.is_empty() {
            Some(self.leaves.clone())
        } else {
            None
        };
        
        // Save all nodes
        let nodes = if !self.nodes.is_empty() {
            Some(self.nodes.values().cloned().collect())
        } else {
            None
        };
        
        // Root hash for quick access
        let root_hash = self.root.as_ref().map(|r| r.hash.clone());
        
        // Save the latest VDF ticks for verification (limited history in main file)
        let vdf_ticks = if !self.historical_ticks.is_empty() {
            let mut ticks: Vec<VDFClockTick> = self.historical_ticks.values().cloned().collect();
            ticks.sort_by_key(|t| t.sequence_number);
            // Only save the last 100 ticks to save space in main file
            let tick_save_limit = 100;
            if ticks.len() > tick_save_limit {
                ticks = ticks[ticks.len() - tick_save_limit..].to_vec();
            }
            Some(ticks)
        } else {
            None
        };

        // Include modulus for verification
        let modulus = Some(self.vdf.get_modulus_bytes());

        // Create the MerkleQuillFile
        let file = MerkleQuillFile {
            metadata: self.metadata.clone(),
            leaves,
            nodes,
            root_hash,
            vdf_ticks,
            modulus,
            current_iterations: self.current_iterations,
            version: "2.0".to_string(),
        };

        // Serialize to JSON
        let json = serde_json::to_string_pretty(&file)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        // Write to file
        fs::write(path, json)?;

        // Update dirty flag
        self.dirty = false;

        Ok(())
    }

    // Load document from file
    fn load_from_file(&mut self, path: &PathBuf) -> io::Result<()> {
        let json = fs::read_to_string(path)?;

        // Attempt to parse directly into the new format (without top-level content)
        match serde_json::from_str::<MerkleQuillFile>(&json) {
            Ok(file) => {

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
                self.leaves = file.leaves.unwrap_or_default(); // Use empty Vec if None
                if !self.leaves.is_empty() {
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
                    for node in nodes_vec {
                        self.nodes.insert(node.hash.clone(), node);
                    }
                }

                // Set root from loaded nodes or rebuild
                self.root = None; // Clear root before trying to set it
                if let Some(root_hash) = file.root_hash {
                     self.root = self.nodes.get(&root_hash).cloned();
                     // If root hash exists but node doesn't, tree is inconsistent
                     if self.root.is_none() && self.nodes.contains_key(&root_hash) {
                         eprintln!("Error: Merkle root hash points to non-existent node in loaded nodes map!");
                         // Decide how to handle: error out, or try rebuild? Let's try rebuild.
                         self.rebuild_merkle_tree();
                     } else if self.root.is_none() && !self.leaves.is_empty() {
                        // Root hash might be missing but we have nodes/leaves
                        self.rebuild_merkle_tree();
                     }
                } else if !self.leaves.is_empty() {
                    // No root hash stored, attempt rebuild if leaves exist
                    self.rebuild_merkle_tree();
                }


                // Load VDF ticks (if present in file)
                self.historical_ticks.clear();
                self.latest_tick = None;
                if let Some(ticks) = file.vdf_ticks {
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
                         self.vdf = VDF::from_modulus_bytes(&modulus_bytes);
                     } else {
                         eprintln!("Warning: Loaded empty VDF modulus bytes. Regenerating default VDF.");
                         self.vdf = VDF::new(2048); // Regenerate
                     }
                } else {
                     eprintln!("Warning: No VDF modulus found in file. Regenerating default VDF.");
                    self.vdf = VDF::new(2048); // Regenerate
                }

                // Load current iterations
                self.current_iterations = file.current_iterations.max(MIN_VDF_ITERATIONS);

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
                        let interval_secs = curr_leaf.timestamp.duration_since(prev_leaf.timestamp)
                            .map(|d| d.as_secs())
                            .unwrap_or(0); // Use 0 if time went backwards
                        self.edit_intervals.push((curr_leaf.timestamp, interval_secs));
                    }
                }


                // Reset flags
                self.dirty = false;
                self.pending_changes = false;
                self.last_verification = None;

                Ok(())

            }
            Err(e) => {
                // Deserialization failed - file is invalid or corrupt
                eprintln!("Error parsing file '{}': {}", path.display(), e);
                Err(io::Error::new(io::ErrorKind::InvalidData,
                   format!("Failed to parse file. It might be corrupted or an invalid format: {}", e)))
            }
        }
    }

    // Export Merkle tree data for verification in a standalone format
    fn export_chain_data(&self, path: &PathBuf) -> io::Result<()> {
        // Collect all ticks currently in memory for export
        let all_ticks: Vec<VDFClockTick> = self.historical_ticks.values().cloned().collect();

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

        // Serialize to JSON
        let json = serde_json::to_string_pretty(&export_data)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e.to_string()))?;

        // Write to file
        fs::write(path, json)?;

        Ok(())
    }

    // Check if there are unsaved changes
    fn has_unsaved_changes(&self) -> bool {
        self.dirty
    }

    // Shutdown VDF clock thread when app exits
    fn shutdown(&self) {
        if let Ok(mut shutdown) = self.vdf_clock_shutdown.lock() {
            *shutdown = true;
        } else {
            eprintln!("Error obtaining lock for VDF clock shutdown.");
        }
    }
    //  method to record just a paragraph's content
    fn record_paragraph(&mut self, paragraph_content: String) {

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
    }
    
}

// For exporting Merkle tree data for verification
#[derive(Serialize, Deserialize)]
struct ExportedMerkleData {
    document_title: String,
    author: String,
    #[serde(with = "timestamp_serde")]
    created: SystemTime,
    #[serde(with = "timestamp_serde")]
    last_modified: SystemTime,
    leaves: Vec<MerkleLeaf>,
    nodes: Vec<MerkleNode>,
    root_hash: Option<String>,
    vdf_ticks: Vec<VDFClockTick>,
    modulus: Vec<u8>,
    current_iterations: u64,
}

// Helper function to compute VDF proof
fn compute_vdf_proof(input: &[u8], iterations: u64, modulus: &BigUint) -> VDFProof {
    // Hash the input to get our starting value
    let mut hasher = Sha256::new();
    hasher.update(input);
    let hash = hasher.finalize();
    let x = BigUint::from_bytes_be(&hash);
    
    // Generate a suitable prime l for Wesolowski's proof
    let l = VDF::generate_proof_prime();
    
    // Calculate r = 2^t mod l
    let r = BigUint::from(2u32).modpow(&BigUint::from(iterations), &l);
    
    // Calculate y = x^(2^t) mod N (iterative squaring)
    let mut y = x.clone();
    for _ in 0..iterations {
        y = (&y * &y) % modulus;
    }
    
    // FIXED: Calculate q correctly without floating point arithmetic
    // Calculate 2^t directly (for current iteration ranges this should be fine)
    let power = BigUint::from(2u32).pow(iterations as u32);
    
    // Calculate q = (2^t - r) / l directly
    let q = (power - r.clone()) / &l;

    
    // Calculate proof π = x^q mod N
    let pi = x.modpow(&q, modulus);

    
    VDFProof {
        y: y.to_bytes_be(),
        pi: pi.to_bytes_be(),
        l: l.to_bytes_be(),
        r: r.to_bytes_be(),
    }
}

// Calculate hash for a MerkleLeaf
fn calculate_leaf_hash(leaf: &MerkleLeaf) -> String {
    let mut hasher = Sha256::new();
    
    // Hash fields in a defined order
    hasher.update(leaf.document_state.state_hash.as_bytes());
    hasher.update(leaf.vdf_tick_reference.to_be_bytes());
    hasher.update(leaf.prev_leaf_hash.as_bytes());
    hasher.update(leaf.commitment.as_bytes()); // Include commitment in hash
    
    // System time as bytes - use consistent format (seconds)
    let timestamp_secs = leaf.timestamp
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    hasher.update(&timestamp_secs.to_be_bytes());
    
    // Leaf number
    hasher.update(leaf.leaf_number.to_be_bytes());
    
    hex::encode(hasher.finalize())
}

// Calculate hash for a Merkle node
fn calculate_node_hash(left_hash: &str, right_hash: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(left_hash.as_bytes());
    
    // If right hash exists, include it
    if !right_hash.is_empty() {
        hasher.update(right_hash.as_bytes());
    }
    
    hex::encode(hasher.finalize())
}

// Get hash from a MerkleTreeElement
fn get_element_hash(element: &MerkleTreeElement) -> String {
    match element {
        MerkleTreeElement::Node(node) => node.hash.clone(),
        MerkleTreeElement::Leaf(leaf) => leaf.hash.clone(),
    }
}

// Multi-line text buffer for the editor
struct TextBuffer {
    lines: Vec<String>,
    cursor_row: usize,
    cursor_col: usize,
    last_edit_time: Instant,
    edit_idle_threshold: Duration,
    content_history: VecDeque<String>,
    max_history: usize,
    scroll_offset: usize, // For scrolling in long documents
    line_numbers: bool,   // Display line numbers
}

impl TextBuffer {
    fn new(idle_threshold_ms: u64) -> Self {
        TextBuffer {
            lines: vec![String::new()],
cursor_row: 0,
            cursor_col: 0,
            last_edit_time: Instant::now(),
            edit_idle_threshold: Duration::from_millis(idle_threshold_ms),
            content_history: VecDeque::new(),
            max_history: 50, // Increased history size
            scroll_offset: 0,
            line_numbers: true, // Enable line numbers by default
        }
    }

    fn insert_char(&mut self, c: char) {
        if c == '\n' {
            // Split the current line at cursor
            let current_line = &self.lines[self.cursor_row];
            let new_line = current_line[self.cursor_col..].to_string();
            self.lines[self.cursor_row] = current_line[..self.cursor_col].to_string();

            // Insert new line
            self.lines.insert(self.cursor_row + 1, new_line);

            // Move cursor to start of new line
            self.cursor_row += 1;
            self.cursor_col = 0;
        } else {
            // Insert character at cursor position
            // Ensure cursor_col is valid for insertion (can be == len)
            let current_line_len = self.lines[self.cursor_row].len();
            if self.cursor_col > current_line_len {
                self.cursor_col = current_line_len;
            }
            self.lines[self.cursor_row].insert(self.cursor_col, c);
            self.cursor_col += 1;
        }

        self.last_edit_time = Instant::now();
        // Don't record every char insert for undo, wait for idle
        self.ensure_cursor_visible();
    }

    fn delete_char(&mut self) { // Backspace behavior
        if self.cursor_col > 0 {
            // Delete character before cursor
            self.lines[self.cursor_row].remove(self.cursor_col - 1);
            self.cursor_col -= 1;
        } else if self.cursor_row > 0 {
            // At start of line, merge with previous line
            let current_line = self.lines.remove(self.cursor_row);
            let prev_line_len = self.lines[self.cursor_row - 1].len();
            self.lines[self.cursor_row - 1].push_str(&current_line);

            // Move cursor to end of previous line
            self.cursor_row -= 1;
            self.cursor_col = prev_line_len;
        }

        self.last_edit_time = Instant::now();
        // Don't record every char delete for undo, wait for idle
        self.ensure_cursor_visible();
    }

    fn move_cursor_left(&mut self) {
        if self.cursor_col > 0 {
            self.cursor_col -= 1;
        } else if self.cursor_row > 0 {
            // Move to end of previous line
            self.cursor_row -= 1;
            self.cursor_col = self.lines[self.cursor_row].len();
        }
        self.ensure_cursor_visible();
    }

    fn move_cursor_right(&mut self) {
        let current_line_len = self.lines[self.cursor_row].len();
        if self.cursor_col < current_line_len {
            self.cursor_col += 1;
        } else if self.cursor_row < self.lines.len() - 1 {
            // Move to start of next line
            self.cursor_row += 1;
            self.cursor_col = 0;
        }
        self.ensure_cursor_visible();
    }

    fn move_cursor_up(&mut self) {
        if self.cursor_row > 0 {
            self.cursor_row -= 1;
            // Adjust column if new line is shorter
            self.cursor_col = self.cursor_col.min(self.lines[self.cursor_row].len());
        }
        self.ensure_cursor_visible();
    }

    fn move_cursor_down(&mut self) {
        if self.cursor_row < self.lines.len() - 1 {
            self.cursor_row += 1;
            // Adjust column if new line is shorter
            self.cursor_col = self.cursor_col.min(self.lines[self.cursor_row].len());
        }
        self.ensure_cursor_visible();
    }

    fn move_cursor_home(&mut self) {
        self.cursor_col = 0;
    }

    fn move_cursor_end(&mut self) {
        self.cursor_col = self.lines[self.cursor_row].len();
    }

    fn page_up(&mut self, height: usize) {
        let effective_height = height.saturating_sub(1); // Move by almost a full page
        let target_row = self.cursor_row.saturating_sub(effective_height);
        self.cursor_row = target_row.max(0);
        self.cursor_col = self.cursor_col.min(self.lines[self.cursor_row].len());
        self.ensure_cursor_visible();
    }

    fn page_down(&mut self, height: usize) {
        let effective_height = height.saturating_sub(1); // Move by almost a full page
        let target_row = self.cursor_row.saturating_add(effective_height);
        self.cursor_row = target_row.min(self.lines.len().saturating_sub(1)); // Ensure bounds
        self.cursor_col = self.cursor_col.min(self.lines[self.cursor_row].len());
        self.ensure_cursor_visible();
    }

    fn ensure_cursor_visible(&mut self) {
        // Determine visible height (needs adjustment based on actual rendering context)
        // This is tricky without knowing the exact layout height. Assume 20 for now.
        let visible_height = 20; // Placeholder height

        // Adjust scroll offset if cursor moved above the visible area
        if self.cursor_row < self.scroll_offset {
            self.scroll_offset = self.cursor_row;
        }
        // Adjust scroll offset if cursor moved below the visible area
        else if self.cursor_row >= self.scroll_offset + visible_height {
            self.scroll_offset = self.cursor_row - visible_height + 1;
        }
    }

    fn get_content(&self) -> String {
        self.lines.join("\n")
    }

    // Get lines for display within a given height, handling scroll offset
    fn get_display_lines(&self, height: usize) -> Vec<String> {
        // Calculate maximum line number width needed for the *entire document*
        let line_num_width = if self.line_numbers {
            self.lines.len().to_string().len()
        } else {
            0
        };

        self.lines
            .iter()
            .enumerate()
            .skip(self.scroll_offset) // Start from the scroll offset
            .take(height)            // Take only enough lines to fill the height
            .map(|(i, line)| {
                if self.line_numbers {
                    // Format with padding based on max width
                    format!("{:<width$} │ {}", i + 1, line, width = line_num_width)
                } else {
                    line.clone()
                }
            })
            .collect()
    }

    fn is_idle(&self) -> bool {
        self.last_edit_time.elapsed() >= self.edit_idle_threshold
    }

    // Record current content state to undo history
    fn record_history(&mut self) {
        let content = self.get_content();

        // Don't record if content is unchanged from last history state
        if let Some(last) = self.content_history.back() {
            if *last == content {
                return;
            }
        } else if content.is_empty() && self.lines.len() == 1 {
            // Don't record initial empty state if history is empty
            return;
        }

        // Add to history
        self.content_history.push_back(content);

        // Trim history if needed
        while self.content_history.len() > self.max_history {
            self.content_history.pop_front();
        }
    }

    // Check if content differs from the last recorded history state
    fn has_changes_since_last_record(&self) -> bool {
        if let Some(last) = self.content_history.back() {
            self.get_content() != *last
        } else {
            // If history is empty, any content is considered a change
            !self.get_content().is_empty() || self.lines.len() > 1
        }
    }

    fn load_content(&mut self, content: &str) {
        // Clear current buffer
        self.lines.clear();
        self.cursor_row = 0;
        self.cursor_col = 0;
        self.scroll_offset = 0;
        self.content_history.clear(); // Clear history on load

        // Load content line by line
        let new_lines: Vec<String> = content.lines().map(|l| l.to_string()).collect();
        if new_lines.is_empty() {
            self.lines.push(String::new()); // Ensure at least one empty line
        } else {
            self.lines = new_lines;
        }

        // Record the loaded state as the initial history point
        self.record_history();
        self.last_edit_time = Instant::now(); // Reset edit time
    }

    fn toggle_line_numbers(&mut self) {
        self.line_numbers = !self.line_numbers;
    }

    // Get cursor position (1-based) for UI display
    fn get_cursor_position(&self) -> (usize, usize) {
        (self.cursor_row + 1, self.cursor_col + 1)
    }

    // Undo functionality
    fn undo(&mut self) {
        if self.content_history.len() > 1 {
            // Remove current state (the one most recently added)
            self.content_history.pop_back();

            // Get the previous state from the history
            if let Some(previous_content) = self.content_history.back().cloned() {
                // Load the previous content without adding it back to history here
                let current_cursor_row = self.cursor_row; // Store cursor roughly
                let current_cursor_col = self.cursor_col;

                self.lines = previous_content.lines().map(|l| l.to_string()).collect();
                if self.lines.is_empty() { self.lines.push(String::new()); }

                // Try to restore cursor position (might be imperfect)
                self.cursor_row = current_cursor_row.min(self.lines.len().saturating_sub(1));
                self.cursor_col = current_cursor_col.min(self.lines[self.cursor_row].len());

                self.last_edit_time = Instant::now(); // Mark as edited
                self.ensure_cursor_visible();
            }
        } else if self.content_history.len() == 1 {
            // If only one state left (initial loaded/new state), clear the buffer
            self.lines = vec![String::new()];
            self.cursor_row = 0;
            self.cursor_col = 0;
            self.scroll_offset = 0;
            self.content_history.pop_back(); // Remove the last state
            self.last_edit_time = Instant::now();
        }
    }
}

// Dialog for file operations
#[derive(PartialEq, Clone)] 
enum Dialog {
    None,
    SaveAs,
    Open,
    NewConfirm,
    Metadata,
    Export,
    UnsavedChanges(UnsavedAction),
}

// What action triggered unsaved changes dialog
#[derive(PartialEq, Clone)]
enum UnsavedAction {
    New,
    Open,
    Quit,
    OpenRecent(usize),
}

// File Browser component
struct FileBrowser {
    current_dir: PathBuf,
    entries: Vec<PathBuf>,
    selected_idx: usize,
    filter: Option<String>, // e.g., "bq", "bqc"
    filename_input: String,
    is_editing_filename: bool,
}

impl FileBrowser {
    fn new() -> Self {
        let current_dir = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        // Scan initially without filter
        let entries = Self::scan_directory(&current_dir, None);

        FileBrowser {
            current_dir,
            entries,
            selected_idx: 0,
            filter: None,
            filename_input: String::new(),
            is_editing_filename: false,
        }
    }

    // Scans directory, optionally filtering files by extension
    fn scan_directory(dir: &Path, filter_ext: Option<&str>) -> Vec<PathBuf> {
        let mut entries = Vec::new();

        // Add parent directory ("..") option, unless already at root
        if let Some(parent) = dir.parent() {
            if parent != dir { // Basic check to avoid adding ".." at root
                entries.push(dir.join(".."));
            }
        }

        // Read directory entries
        if let Ok(read_dir) = fs::read_dir(dir) {
            let mut dirs = Vec::new();
            let mut files = Vec::new();

            for entry_result in read_dir {
                if let Ok(entry) = entry_result {
                    let path = entry.path();

                    // Basic hidden file check (Unix/macOS style)
                    if path.file_name().and_then(|n| n.to_str()).map_or(false, |s| s.starts_with('.')) {
                        continue;
                    }

                    if path.is_dir() {
                        dirs.push(path);
                    } else if path.is_file() {
                        // Apply filter if specified
                        if let Some(ext_filter) = filter_ext {
                            if path.extension().and_then(|e| e.to_str()) == Some(ext_filter) {
                                files.push(path);
                            }
                        } else {
                            // No filter, include all files
                            files.push(path);
                        }
                    }
                }
            }

            // Sort directories and files alphabetically
            dirs.sort_by_key(|d| d.file_name().unwrap_or_default().to_ascii_lowercase());
            files.sort_by_key(|f| f.file_name().unwrap_or_default().to_ascii_lowercase());

            // Combine: ".." first, then sorted dirs, then sorted files
            entries.append(&mut dirs);
            entries.append(&mut files);
        } else {
            eprintln!("Warning: Could not read directory {}", dir.display());
            // Still add ".." if possible
            if entries.is_empty() {
                if let Some(parent) = dir.parent() {
                    if parent != dir { entries.push(dir.join("..")); }
                }
            }
        }

        entries
    }

    fn navigate_up(&mut self) {
        if self.selected_idx > 0 {
            self.selected_idx -= 1;
        }
    }

    fn navigate_down(&mut self) {
        if !self.entries.is_empty() && self.selected_idx < self.entries.len() - 1 {
            self.selected_idx += 1;
        }
    }

    // Tries to enter the selected directory. Returns true if successful.
    fn enter_directory(&mut self) -> bool {
        if self.entries.is_empty() || self.selected_idx >= self.entries.len() {
            return false; // Avoid panic on empty or out-of-bounds index
        }

        let selected_path = &self.entries[self.selected_idx];

        // Check if it's the ".." entry
        if selected_path.file_name().map_or(false, |name| name == "..") {
            if let Some(parent) = self.current_dir.parent() {
                self.current_dir = parent.to_path_buf();
                self.entries = Self::scan_directory(&self.current_dir, self.filter.as_deref());
                self.selected_idx = 0; // Reset selection
                self.filename_input.clear(); // Clear filename input when changing dir
                self.is_editing_filename = false;
                return true;
            }
        } else if selected_path.is_dir() {
            // Canonicalize to handle symlinks etc. but fallback gracefully
            self.current_dir = fs::canonicalize(selected_path).unwrap_or_else(|_| selected_path.to_path_buf());
            self.entries = Self::scan_directory(&self.current_dir, self.filter.as_deref());
            self.selected_idx = 0; // Reset selection
            self.filename_input.clear(); // Clear filename input
            self.is_editing_filename = false;
            return true;
        }

        false // Not a directory or ".."
    }

    // Gets the currently selected path (could be a file or directory)
    fn get_selected_path(&self) -> Option<PathBuf> {
        if self.entries.is_empty() || self.selected_idx >= self.entries.len() {
            None
        } else {
            Some(self.entries[self.selected_idx].clone())
        }
    }

    // Sets the file extension filter (e.g., "bq") and rescans
    fn set_filter(&mut self, ext: &str) {
        self.filter = Some(ext.to_string());
        self.entries = Self::scan_directory(&self.current_dir, self.filter.as_deref());
        self.selected_idx = 0; // Reset selection
        self.filename_input.clear();
        self.is_editing_filename = false;
    }

    // Clears the file extension filter and rescans
    fn clear_filter(&mut self) {
        self.filter = None;
        self.entries = Self::scan_directory(&self.current_dir, None);
        self.selected_idx = 0; // Reset selection
        self.filename_input.clear();
        self.is_editing_filename = false;
    }

    // Gets formatted entry names for display in the TUI List
    fn get_entries_for_display(&self) -> Vec<String> {
        self.entries
            .iter()
            .map(|path| {
                let name = path.file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("[invalid path]");

                if name == ".." {
                    "⬆️  ../".to_string() // Use ".." consistently
                } else if path.is_dir() {
                    format!("📁 {}/", name)
                } else {
                    format!("📄 {}", name)
                }
            })
            .collect()
    }
}

// Metadata editor dialog state
struct MetadataEditor {
    metadata: DocumentMetadata,
    current_field: usize, // 0: title, 1: author, 2: keywords, 3: description
    editing: bool,
    edit_buffer: String,
}

impl MetadataEditor {
    fn new(metadata: DocumentMetadata) -> Self {
        MetadataEditor {
            metadata,
            current_field: 0,
            editing: false,
            edit_buffer: String::new(),
        }
    }

    fn navigate_up(&mut self) {
        if self.editing { return; } // Don't navigate fields while editing buffer
        if self.current_field > 0 {
            self.current_field -= 1;
        }
    }

    fn navigate_down(&mut self) {
        if self.editing { return; } // Don't navigate fields while editing buffer
        // Adjust max field index if needed
        if self.current_field < 3 { // 0=title, 1=author, 2=keywords, 3=description
            self.current_field += 1;
        }
    }

    fn start_editing(&mut self) {
        if self.editing { return; } // Already editing
        self.editing = true;
        match self.current_field {
            0 => self.edit_buffer = self.metadata.title.clone(),
            1 => self.edit_buffer = self.metadata.author.clone(),
            2 => self.edit_buffer = self.metadata.keywords.join(", "), // Edit as comma-separated
            3 => self.edit_buffer = self.metadata.description.clone(),
            _ => self.editing = false, // Invalid field
        }
    }

    fn handle_edit_key(&mut self, code: KeyCode) {
        if !self.editing { return; }
        match code {
            KeyCode::Enter => self.finish_editing(),
            KeyCode::Esc => self.cancel_editing(),
            KeyCode::Backspace => { self.edit_buffer.pop(); },
            KeyCode::Char(c) => self.edit_buffer.push(c),
            _ => {} // Ignore other keys while editing buffer
        }
    }

    fn finish_editing(&mut self) {
        if !self.editing { return; }
        match self.current_field {
            0 => self.metadata.title = self.edit_buffer.trim().to_string(),
            1 => self.metadata.author = self.edit_buffer.trim().to_string(),
            2 => {
                self.metadata.keywords = self.edit_buffer
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty()) // Remove empty keywords
                    .collect();
            },
            3 => self.metadata.description = self.edit_buffer.trim().to_string(),
            _ => {}
        }
        self.editing = false;
        self.edit_buffer.clear();
    }

    fn cancel_editing(&mut self) {
        if !self.editing { return; }
        self.editing = false;
        self.edit_buffer.clear();
    }

    fn get_metadata(&self) -> DocumentMetadata {
        // Return a clone of the potentially modified metadata
        self.metadata.clone()
    }
}

// TUI App state
#[derive(PartialEq)]
enum AppMode {
    Editing,
    Viewing,        // View leaf history
    VerifyDetail,   // View verification results
    TreeView,       // View Merkle tree structure
    FileDialog,     // Indicates a file dialog is active
    MetadataEdit,   // Editing metadata fields
    Help,           // Display help screen
}

struct App {
    document: MerkleDocument,
    buffer: TextBuffer,
    history_scroll: usize, // Scroll offset for lists
    mode: AppMode,
    message: String,
    last_auto_save: Instant,
    file_path: Option<PathBuf>,
    recent_files: Vec<PathBuf>,
    dialog: Dialog,
    file_browser: FileBrowser,
    metadata_editor: Option<MetadataEditor>,
    should_quit: bool,
    status_time: Instant, // For temporary status indicators
    show_tick_indicator: bool,
    auto_save_enabled: bool,
}

impl App {
    fn new() -> Self {
        // Load recent files if available
        let recent_files = Self::load_recent_files();

        App {
            document: MerkleDocument::new(),
            buffer: TextBuffer::new(2000),  // 2 second idle threshold for history commit
            history_scroll: 0,
            mode: AppMode::Editing,
            message: String::from("Welcome to BitQuill - Merkle Edition! Press F1 for help."),
            last_auto_save: Instant::now(),
            file_path: None,
            recent_files,
            dialog: Dialog::None,
            file_browser: FileBrowser::new(),
            metadata_editor: None,
            should_quit: false,
            status_time: Instant::now(),
            show_tick_indicator: false,
            auto_save_enabled: true, // Auto-save on by default
        }
    }

    // Simplified char insertion - delegates to buffer
    fn insert_char(&mut self, c: char) {
        self.buffer.insert_char(c);
        // Mark document as dirty immediately on change
        self.document.dirty = true;
    }

    // Simplified char deletion - delegates to buffer
    fn delete_char(&mut self) {
        self.buffer.delete_char();
        // Mark document as dirty immediately on change
        self.document.dirty = true;
    }

    // Toggle between primary modes (Edit/View)
    fn toggle_edit_view_mode(&mut self) {
        match self.mode {
            AppMode::Editing => {
                // Before switching away from editing, record pending changes if any
                if self.buffer.has_changes_since_last_record() {
                    self.document.record_change(self.buffer.get_content());
                    self.buffer.record_history(); // Commit to buffer history too
                    self.message = "Changes recorded, switching to View mode.".to_string();
                } else {
                    self.message = "Viewing mode - Press Tab/F2 to return to editing".to_string();
                }
                self.mode = AppMode::Viewing;
                self.history_scroll = 0; // Reset scroll when entering view mode
            },
            AppMode::Viewing => {
                self.mode = AppMode::Editing;
                self.message = "Editing mode".to_string();
            },
            AppMode::VerifyDetail => {
                self.mode = AppMode::Viewing;
                self.message = "Viewing mode - Press Tab/F2 to return to editing".to_string();
                self.history_scroll = 0;
            },
            AppMode::TreeView => {
                self.mode = AppMode::Viewing;
                self.message = "Viewing mode - Press Tab/F2 to return to editing".to_string();
                self.history_scroll = 0;
            },
            _ => {
                // Don't toggle if in other modes like Help, FileDialog, MetadataEdit
            }
        }
    }

    // Toggle tree view mode (show Merkle tree structure)
    fn toggle_tree_view(&mut self) {
        match self.mode {
            AppMode::Viewing | AppMode::VerifyDetail => {
                self.mode = AppMode::TreeView;
                self.history_scroll = 0;
                self.message = "Tree View - Showing Merkle tree structure".to_string();
            },
            AppMode::TreeView => {
                self.mode = AppMode::Viewing;
                self.history_scroll = 0;
                self.message = "Viewing mode - Press Tab/F2 to return to editing".to_string();
            },
            _ => {
                // Only toggle from View/Verify modes
            }
        }
    }

    fn toggle_help(&mut self) {
        if self.mode == AppMode::Help {
            // Exit help mode, return to Editing (or previous mode?) - let's default to Editing
            self.mode = AppMode::Editing;
            self.message = "Help closed.".to_string();
        } else {
            // Enter help mode
            // Record pending changes before leaving editing state
            if self.mode == AppMode::Editing && self.buffer.has_changes_since_last_record() {
                self.document.record_change(self.buffer.get_content());
                self.buffer.record_history();
            }
            self.mode = AppMode::Help;
            self.message = "Showing help. Press F1 or Esc to close.".to_string();
        }
    }

    fn update(&mut self) {
        // Process any new VDF clock ticks and potentially create leaves
        let tick_before = self.document.latest_tick.as_ref().map(|t| t.sequence_number);
        let leaf_created = self.document.process_vdf_ticks();
        let tick_after = self.document.latest_tick.as_ref().map(|t| t.sequence_number);

        if leaf_created {
            self.message = format!("New leaf #{} created (VDF tick #{})",
                                  self.document.leaves.len(),
                                  tick_after.unwrap_or(0));
            self.show_tick_indicator = true; // Indicate leaf creation visually
            self.status_time = Instant::now();
        } else if tick_after != tick_before && tick_after.is_some() {
            // Show tick indicator even if no leaf was created this cycle
            self.message = format!("VDF Tick #{} received (diff: {})", 
                                  tick_after.unwrap_or(0),
                                  self.document.current_iterations);
            self.show_tick_indicator = true;
            self.status_time = Instant::now();
        }

        // Check for idle edits in Editing mode and commit to history/document state
        if self.mode == AppMode::Editing && self.buffer.is_idle() && self.buffer.has_changes_since_last_record() {
            let content = self.buffer.get_content();
            self.document.record_change(content); // Mark change pending VDF tick
            self.buffer.record_history(); // Record in undo history
            self.message = "Changes recorded - waiting for next Merkle leaf creation".to_string();
            // Mark dirty flag here too, although record_change should do it.
            self.document.dirty = true;
        }

        // Auto-save if enabled, document is dirty, path exists, and interval passed
        if self.auto_save_enabled &&
           self.document.has_unsaved_changes() && // Use dirty flag
           self.file_path.is_some() &&
           Instant::now().duration_since(self.last_auto_save) > Duration::from_secs(AUTO_SAVE_INTERVAL) {

            // Before saving, ensure latest buffer changes are recorded if in editing mode
            if self.mode == AppMode::Editing && self.buffer.has_changes_since_last_record() {
                self.document.record_change(self.buffer.get_content());
                self.buffer.record_history();
            }

            // Now attempt to save
            if let Err(e) = self.save_document() {
                self.message = format!("Auto-save error: {}", e);
            } else {
                self.message = format!("Document auto-saved to {}", self.file_path.as_ref().unwrap().display());
            }
            self.last_auto_save = Instant::now();
        }

        // Clear temporary status indicators after a few seconds
        if self.show_tick_indicator && Instant::now().duration_since(self.status_time) > Duration::from_secs(3) {
            self.show_tick_indicator = false;
            // Maybe clear the message related to the indicator? Or let the next message overwrite.
        }
    }

    // Save document to current file_path or trigger SaveAs dialog
    fn save_document(&mut self) -> io::Result<()> {
        // Ensure latest buffer changes are recorded before saving
        if self.mode == AppMode::Editing && self.buffer.has_changes_since_last_record() {
            self.document.record_change(self.buffer.get_content());
            self.buffer.record_history();
        }

        match &self.file_path {
            Some(p) => {
                let path_clone = p.clone(); // Clone to satisfy borrow checker
                self.document.save_to_file(&path_clone)?; // This now sets dirty = false
                self.add_to_recent_files(&path_clone); // Update recent files
                self.message = format!("Document saved to {}", path_clone.display());
                self.last_auto_save = Instant::now(); // Reset auto-save timer on manual save
                Ok(())
            },
            None => {
                // No path set - trigger SaveAs dialog
                self.trigger_save_as_dialog();
                // Indicate failure for now, dialog will handle the save later
                Err(io::Error::new(io::ErrorKind::Other, "Save As dialog triggered"))
            }
        }
    }

    // Trigger SaveAs dialog state change
    fn trigger_save_as_dialog(&mut self) {
        self.mode = AppMode::FileDialog; // Switch mode
        self.dialog = Dialog::SaveAs; // Set specific dialog type
        self.file_browser.set_filter(BITQUILL_FILE_EXT); // Set filter for .bq files
        self.file_browser.filename_input = self.file_path // Pre-fill filename if available
            .as_ref()
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| "Untitled.bq".to_string());
        self.file_browser.is_editing_filename = true; // Start editing the filename
        self.message = "Save As: Enter filename and press Enter.".to_string();
    }

    // Confirm SaveAs action from dialog input
    fn confirm_save_as(&mut self) -> io::Result<()> {
        let filename = self.file_browser.filename_input.trim();
        if filename.is_empty() {
            self.message = "Filename cannot be empty. Press Esc to cancel.".to_string();
            self.file_browser.is_editing_filename = true; // Keep editing
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "Empty filename"));
        }

        let mut save_path = self.file_browser.current_dir.clone();
        save_path.push(filename);

        // Ensure correct extension
        if save_path.extension().and_then(|e| e.to_str()) != Some(BITQUILL_FILE_EXT) {
            save_path.set_extension(BITQUILL_FILE_EXT);
        }

        // Ensure latest buffer changes are recorded
        if self.mode == AppMode::Editing && self.buffer.has_changes_since_last_record() {
            self.document.record_change(self.buffer.get_content());
            self.buffer.record_history();
        }

        // Save document to the new path
        self.document.save_to_file(&save_path)?; // This resets dirty flag

        // Update app state
        self.file_path = Some(save_path.clone());
        self.add_to_recent_files(&save_path); // Update recent files

        // Close dialog and return to editing mode
        self.dialog = Dialog::None;
        self.mode = AppMode::Editing; // Return to editing after save
        self.file_browser.filename_input.clear();
        self.file_browser.is_editing_filename = false;
        self.file_browser.clear_filter(); // Clear filter after dialog closes

        self.message = format!("Document saved to {}", save_path.display());
        self.last_auto_save = Instant::now(); // Reset auto-save timer
        Ok(())
    }

    // Trigger Open dialog state change
    fn trigger_open_dialog(&mut self) {
        if self.document.has_unsaved_changes() {
            self.dialog = Dialog::UnsavedChanges(UnsavedAction::Open);
            self.message = "Save unsaved changes before opening?".to_string();
        } else {
            self.start_open_dialog();
        }
    }

    // Actually starts the Open dialog UI
    fn start_open_dialog(&mut self) {
        self.mode = AppMode::FileDialog;
        self.dialog = Dialog::Open;
        self.file_browser.set_filter(BITQUILL_FILE_EXT); // Filter for .bq files
        self.file_browser.filename_input.clear(); // Not used for open
        self.file_browser.is_editing_filename = false;
        self.message = "Open File: Select a .bq file and press Enter.".to_string();
    }

    // Confirm Open action from dialog input
    fn confirm_open(&mut self) -> io::Result<()> {
        if let Some(path) = self.file_browser.get_selected_path() {
            if path.is_file() {
                // Ensure file has the correct extension before trying to load
                if path.extension().and_then(|e| e.to_str()) == Some(BITQUILL_FILE_EXT) {
                    // Load document
                    self.document.load_from_file(&path)?; // Load resets dirty flag

                    // Update buffer with loaded content
                    self.buffer.load_content(&self.document.get_current_content());

                    // Update app state
                    self.file_path = Some(path.clone());
                    self.add_to_recent_files(&path);

                    // Close dialog and switch to editing mode
                    self.dialog = Dialog::None;
                    self.mode = AppMode::Editing; // Go to editing after open
                    self.file_browser.clear_filter();

                    self.message = format!("Document opened from {}", path.display());
                    Ok(())
                } else {
                    self.message = "Invalid file type. Please select a .bq file.".to_string();
                    Err(io::Error::new(io::ErrorKind::InvalidInput, "Wrong file type"))
                }
            } else if path.is_dir() {
                // Navigate into directory
                self.file_browser.enter_directory();
                // Stay in dialog mode after navigation
                Err(io::Error::new(io::ErrorKind::Other, "Navigated directory"))
            } else {
                // Should not happen if scan_directory is correct
                self.message = "Selected path is not a file or directory.".to_string();
                Err(io::Error::new(io::ErrorKind::NotFound, "Invalid selection"))
            }
        } else {
            self.message = "No file or directory selected.".to_string();
            Err(io::Error::new(io::ErrorKind::NotFound, "No selection"))
        }
    }

    // Trigger New document action (checking for unsaved changes)
    fn trigger_new_document(&mut self) {
        if self.document.has_unsaved_changes() {
            self.dialog = Dialog::UnsavedChanges(UnsavedAction::New);
            self.message = "Save unsaved changes before creating a new document?".to_string();
        } else {
            self.confirm_new_document(); // No unsaved changes, proceed directly
        }
    }

    // Actually create the new document state
    fn confirm_new_document(&mut self) {
        // Record changes of the *old* document before discarding if needed
        if self.mode == AppMode::Editing && self.buffer.has_changes_since_last_record() {
            self.document.record_change(self.buffer.get_content());
            self.buffer.record_history();
        }

        // Shutdown old VDF clock before replacing document
        self.document.shutdown();

        // Create new document state (this starts a new VDF clock)
        self.document = MerkleDocument::new();

        // Clear buffer and history
        self.buffer = TextBuffer::new(2000); // Recreate buffer too

        // Clear file path and reset status
        self.file_path = None;
        self.document.last_verification = None;

        self.dialog = Dialog::None; // Ensure no dialog is active
        self.mode = AppMode::Editing; // Go to editing mode

        self.message = "New document created".to_string();
        self.last_auto_save = Instant::now(); // Reset auto-save timer
    }

    // Trigger verification action
    fn verify_document(&mut self, level: VerificationLevel) {
        // Record pending changes before verifying
        if self.mode == AppMode::Editing && self.buffer.has_changes_since_last_record() {
            self.document.record_change(self.buffer.get_content());
            self.buffer.record_history();
        }
        // Update message BEFORE starting verification
        self.message = format!("Starting verification with {} leaves and {} nodes...", 
                             self.document.leaves.len(), 
                             self.document.nodes.len());
        let result = self.document.verify_merkle_integrity(level);
        let leaf_count = self.document.leaves.len();
        let tick_count_mem = self.document.get_tick_count();

        if result.valid {
            self.message = format!("VERIFICATION PASSED ({:?}): {} leaves checked, {} nodes in tree, {} VDF ticks in memory.",
                                  level, leaf_count, self.document.nodes.len(), tick_count_mem);
        } else {
            self.message = format!("VERIFICATION FAILED ({:?}): Merkle tree integrity check failed! ({} leaves, {} nodes, {} ticks)",
                                  level, leaf_count, self.document.nodes.len(), tick_count_mem);
        }

        // Switch to verification detail view
        self.mode = AppMode::VerifyDetail;
        self.history_scroll = 0; // Reset scroll
    }

    // Trigger Export dialog
    fn trigger_export_dialog(&mut self) {
        if self.document.leaves.is_empty() {
            self.message = "No leaves to export. Create some document history first.".to_string();
            return; // Don't open dialog if nothing to export
        }

        self.mode = AppMode::FileDialog;
        self.dialog = Dialog::Export;
        self.file_browser.set_filter(BITQUILL_CHAIN_EXT); // Filter for .bqc
        // Suggest a default export filename based on the document name
        let default_export_name = self.file_path.as_ref()
            .map(|p| p.with_extension(BITQUILL_CHAIN_EXT))
            .and_then(|p| p.file_name().map(|n| n.to_os_string()))
            .and_then(|n| n.into_string().ok())
            .unwrap_or_else(|| "export.bqc".to_string());

        self.file_browser.filename_input = default_export_name;
        self.file_browser.is_editing_filename = true; // Start editing
        self.message = "Export Chain Data: Enter filename (.bqc) and press Enter.".to_string();
    }

    // Confirm Export action from dialog
    fn confirm_export(&mut self) -> io::Result<()> {
        let filename = self.file_browser.filename_input.trim();
        if filename.is_empty() {
            self.message = "Filename cannot be empty. Press Esc to cancel.".to_string();
            self.file_browser.is_editing_filename = true; // Keep editing
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "Empty filename"));
        }

        let mut export_path = self.file_browser.current_dir.clone();
        export_path.push(filename);

        // Ensure correct extension
        if export_path.extension().and_then(|e| e.to_str()) != Some(BITQUILL_CHAIN_EXT) {
            export_path.set_extension(BITQUILL_CHAIN_EXT);
        }

        // Export chain data
        self.document.export_chain_data(&export_path)?;

        // Close dialog and return to previous mode (usually Editing)
        self.dialog = Dialog::None;
        self.mode = AppMode::Editing; // Or whatever mode user was in before export
        self.file_browser.filename_input.clear();
        self.file_browser.is_editing_filename = false;
        self.file_browser.clear_filter();

        self.message = format!("Merkle tree data exported to {}", export_path.display());
        Ok(())
    }

    // Enter metadata editing mode
    fn trigger_edit_metadata(&mut self) {
        // Record pending buffer changes first
        if self.mode == AppMode::Editing && self.buffer.has_changes_since_last_record() {
            self.document.record_change(self.buffer.get_content());
            self.buffer.record_history();
        }
        // Create metadata editor state with current metadata
        self.metadata_editor = Some(MetadataEditor::new(self.document.metadata.clone()));
        self.mode = AppMode::MetadataEdit;
        self.message = "Edit Metadata: Use Arrows, Enter to edit field, Ctrl+S to save, Esc to cancel.".to_string();
    }

    // Save metadata changes from editor
    fn save_metadata(&mut self) {
        if let Some(editor) = &self.metadata_editor {
            // Check if metadata actually changed
            let new_metadata = editor.get_metadata();
            if new_metadata.title != self.document.metadata.title ||
               new_metadata.author != self.document.metadata.author ||
               new_metadata.keywords != self.document.metadata.keywords ||
               new_metadata.description != self.document.metadata.description {

                self.document.metadata = new_metadata;
                self.document.dirty = true; // Mark document dirty if metadata changed
                self.message = "Metadata updated and marked for saving.".to_string();
            } else {
                self.message = "Metadata unchanged.".to_string();
            }

            // Return to editing mode
            self.mode = AppMode::Editing;
            self.metadata_editor = None; // Clear editor state
        }
    }

    // Cancel metadata editing
    fn cancel_metadata(&mut self) {
        // Return to editing mode without saving changes from editor
        self.mode = AppMode::Editing;
        self.metadata_editor = None;
        self.message = "Metadata editing cancelled".to_string();
    }

    // Toggle auto-save setting
    fn toggle_auto_save(&mut self) {
        self.auto_save_enabled = !self.auto_save_enabled;
        self.message = if self.auto_save_enabled {
            format!("Auto-save enabled (every {} seconds)", AUTO_SAVE_INTERVAL)
        } else {
            "Auto-save disabled".to_string()
        };
        self.last_auto_save = Instant::now(); // Reset timer when toggling
    }

    // Toggle line numbers in buffer
    fn toggle_line_numbers(&mut self) {
        self.buffer.toggle_line_numbers();
        self.message = if self.buffer.line_numbers {
            "Line numbers enabled".to_string()
        } else {
            "Line numbers disabled".to_string()
        };
    }

    // Request quit, checking for unsaved changes
    fn request_quit(&mut self) {
        // Ensure latest buffer changes are recorded if needed
        if self.mode == AppMode::Editing && self.buffer.has_changes_since_last_record() {
            self.document.record_change(self.buffer.get_content());
            self.buffer.record_history();
        }

        if self.document.has_unsaved_changes() {
            // Ask about unsaved changes first
            self.dialog = Dialog::UnsavedChanges(UnsavedAction::Quit);
            self.message = "Save unsaved changes before quitting?".to_string();
        } else {
            // No unsaved changes, quit immediately
            self.should_quit = true;
        }
    }

    // Handle confirmation for unsaved changes dialog ('Y' or 'N')
    fn handle_unsaved_dialog_confirm(&mut self, save_first: bool) {
        if let Dialog::UnsavedChanges(action) = self.dialog.clone() { // Clone action
            if save_first {
                // Attempt to save; if successful or no path (SaveAs triggered), proceed.
                // If save fails, stay in dialog.
                match self.save_document() {
                    Ok(_) => { // Saved successfully
                        self.proceed_with_action(action);
                    }
                    Err(e) if e.to_string().contains("Save As dialog triggered") => {
                        // Save As dialog is now active, don't proceed yet.
                        // User needs to complete Save As first.
                        self.message = "Please complete the Save As dialog.".to_string();
                    }
                    Err(e) => { // Other save error
                        self.message = format!("Error saving: {}. Action cancelled.", e);
                        // Stay in the UnsavedChanges dialog? Or cancel? Let's cancel.
                        self.dialog = Dialog::None;
                    }
                }
            } else {
                // Discard changes and proceed
                self.document.dirty = false; // Mark as not dirty explicitly
                self.proceed_with_action(action);
            }
        }
    }

    // Proceeds with the original action after unsaved changes are handled
    fn proceed_with_action(&mut self, action: UnsavedAction) {
        match action {
            UnsavedAction::New => self.confirm_new_document(),
            UnsavedAction::Open => self.start_open_dialog(), // Start the open dialog now
            UnsavedAction::Quit => self.should_quit = true, // Quit now
            UnsavedAction::OpenRecent(index) => {
                // Need to re-trigger recent file opening after discard/save
                if let Err(e) = self.confirm_open_recent_file(index) {
                    self.message = format!("Error opening recent file: {}", e);
                }
            }
        }
        // Ensure dialog is closed unless another one was opened (like Save As)
        if self.dialog == Dialog::UnsavedChanges(action) {
            self.dialog = Dialog::None;
        }
    }

    // Add path to recent files list and save
    fn add_to_recent_files(&mut self, path: &PathBuf) {
        // Ensure path is absolute for consistency
        if let Ok(abs_path) = fs::canonicalize(path) {
            // Remove if already exists to avoid duplicates and move to top
            self.recent_files.retain(|p| p != &abs_path);

            // Add to front
            self.recent_files.insert(0, abs_path);

            // Trim list
            self.recent_files.truncate(MAX_RECENT_FILES);

            // Save to config file
            self.save_recent_files();
        } else {
            eprintln!("Warning: Could not canonicalize path for recent files: {}", path.display());
        }
    }

    // Get config directory path
    fn get_config_dir() -> PathBuf {
        // Use dirs crate for platform-appropriate config location
        if let Some(config_dir) = dirs::config_dir() {
            config_dir.join("bitquill") // App-specific subdirectory
        } else if let Some(home_dir) = dirs::home_dir() {
            // Fallback to home directory if config dir isn't found
            home_dir.join(".bitquill") // Hidden directory in home
        } else {
            // Last resort: current directory
            PathBuf::from(".bitquill_config")
        }
    }

    // Load recent files list from config
    fn load_recent_files() -> Vec<PathBuf> {
        let config_dir = Self::get_config_dir();
        let recent_files_path = config_dir.join("recent_files.txt");

        if !recent_files_path.exists() {
            return Vec::new();
        }

        match fs::read_to_string(recent_files_path) {
            Ok(content) => {
                content.lines()
                    .map(PathBuf::from)
                    .filter(|p| p.exists()) // Only keep files that still exist
                    .take(MAX_RECENT_FILES)
                    .collect()
            },
            Err(e) => {
                eprintln!("Warning: Failed to load recent files: {}", e);
                Vec::new()
            },
        }
    }

    // Save recent files list to config
    fn save_recent_files(&self) {
        let config_dir = Self::get_config_dir();

        // Create config directory if it doesn't exist
        if !config_dir.exists() {
            if let Err(e) = fs::create_dir_all(&config_dir) {
                eprintln!("Error: Failed to create config directory '{}': {}", config_dir.display(), e);
                return;
            }
        }

        let recent_files_path = config_dir.join("recent_files.txt");

        // Convert paths to strings for saving
        let content = self.recent_files.iter()
            .map(|p| p.to_string_lossy().to_string()) // Use lossy conversion
            .collect::<Vec<_>>()
            .join("\n");

        // Save to file
        if let Err(e) = fs::write(&recent_files_path, content) {
            eprintln!("Error: Failed to save recent files to '{}': {}", recent_files_path.display(), e);
        }
    }

    // Trigger opening a recent file
    fn trigger_open_recent_file(&mut self, index: usize) {
        if index >= self.recent_files.len() {
            self.message = format!("Invalid recent file number: {}", index + 1);
            return;
        }

        if self.document.has_unsaved_changes() {
            // Ask about unsaved changes first
            self.dialog = Dialog::UnsavedChanges(UnsavedAction::OpenRecent(index));
            self.message = "Save unsaved changes before opening recent file?".to_string();
        } else {
            // No unsaved changes, proceed directly
            if let Err(e) = self.confirm_open_recent_file(index) {
                self.message = format!("Error opening recent file: {}", e);
            }
        }
    }

    // Actually load the recent file
    fn confirm_open_recent_file(&mut self, index: usize) -> io::Result<()> {
        if index >= self.recent_files.len() {
            return Err(io::Error::new(io::ErrorKind::NotFound, "Recent file index out of bounds"));
        }

        let path = self.recent_files[index].clone(); // Clone to avoid borrow issues

        // Load document
        self.document.load_from_file(&path)?;

        // Update buffer with loaded content
        self.buffer.load_content(&self.document.get_current_content());

        // Update app state
        self.file_path = Some(path.clone());
        self.add_to_recent_files(&path); // Move to top of recent list

        // Ensure correct mode and clear dialog
        self.mode = AppMode::Editing;
        self.dialog = Dialog::None;

        self.message = format!("Opened recent file {}", path.display());
        Ok(())
    }
    
    // Get help text content
    fn get_help_text(&self) -> Vec<String> {
        vec![
            "BitQuill Merkle Edition Commands:".to_string(),
            "".to_string(),
            "File Operations:".to_string(),
            "  F1           - Show/Hide Help".to_string(),
            "  Ctrl+S       - Save Document".to_string(),
            "  Ctrl+Shift+S - Save As...".to_string(),
            "  Ctrl+O       - Open Document".to_string(),
            "  Ctrl+N       - New Document".to_string(),
            "  Ctrl+E       - Export Merkle Tree Data (.bqc)".to_string(),
            "  Ctrl+M       - Edit Metadata".to_string(),
            "  Alt+1..9     - Open Recent File (1-based)".to_string(),
            "  Alt+A        - Toggle Auto-Save".to_string(),
            "".to_string(),
            "Navigation & Modes:".to_string(),
            "  Tab / F2     - Toggle Edit / View Mode".to_string(),
            "  F3           - Toggle Tree View (from View mode)".to_string(),
            "  Arrow Keys   - Move Cursor (Edit) / Select (View/Dialog)".to_string(),
            "  Home/End     - Move to Start/End of Line (Edit)".to_string(),
            "  PgUp/PgDn    - Page Up/Down (Edit/View)".to_string(),
            "  Alt+L        - Toggle Line Numbers".to_string(),
            "".to_string(),
            "Editing:".to_string(),
            "  Enter        - New Line / Confirm Dialog Action".to_string(),
            "  Backspace    - Delete Character Behind Cursor".to_string(),
            "  Ctrl+Z       - Undo (basic)".to_string(),
            "".to_string(),
            "Verification:".to_string(),
            "  Ctrl+V       - Verify Merkle Tree Integrity".to_string(),
            "".to_string(),
            "Dialogs:".to_string(),
            "  Esc          - Cancel Current Action / Dialog / Quit".to_string(),
            "  Y / N        - Confirm Yes/No Dialogs".to_string(),
            "  F / Tab      - Focus Filename Input (in File Dialog)".to_string(),
            "".to_string(),
            "About BitQuill Merkle Edition:".to_string(),
            " Creates a tamper-evident document history using a".to_string(),
            " Merkle tree structure with VDF-based time attestation.".to_string(),
            " Each leaf represents a document state, providing an".to_string(),
            " efficient verification structure for document history.".to_string(),
        ]
    }

    // Prepare for shutdown
    fn shutdown(&mut self) {
        // Record any final changes before shutdown
        if self.mode == AppMode::Editing && self.buffer.has_changes_since_last_record() {
            self.document.record_change(self.buffer.get_content());
        }

        // Shutdown VDF clock thread
        self.document.shutdown();
        
        // Save recent files one last time
        self.save_recent_files();
    }

    // Perform undo action
    fn undo(&mut self) {
        if self.mode == AppMode::Editing {
            self.buffer.undo();
            // After undo, the buffer content has changed, mark document dirty
            self.document.dirty = true;
            self.message = "Undo performed".to_string();
        } else {
            self.message = "Undo only available in Editing mode".to_string();
        }
    }
}

// --- Main Function ---
fn main() -> Result<(), io::Error> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Create app state
    let mut app = App::new();

    // --- Main Loop ---
    loop {
        // Draw UI
        terminal.draw(|f| ui(f, &mut app))?; // Pass mutable app ref to ui function

        // Update application state (process VDF ticks, check idle, auto-save)
        app.update();

        // Process events with a timeout to allow for background updates
        if event::poll(Duration::from_millis(100))? { // Poll for 100ms
            if let Event::Key(key) = event::read()? {
                // --- Input Handling ---
                let mut key_handled = false; // Flag to check if input was consumed

                // 1. Handle Dialog Input (if any dialog is active)
                if app.dialog != Dialog::None {
                    key_handled = handle_dialog_input(&mut app, key);
                }

                // 2. Handle Mode-Specific Input (if not handled by dialog)
                if !key_handled {
                    key_handled = match app.mode {
                        AppMode::Editing => handle_editing_input(&mut app, key),
                        AppMode::Viewing => handle_viewing_input(&mut app, key),
                        AppMode::VerifyDetail => handle_verify_detail_input(&mut app, key),
                        AppMode::TreeView => handle_tree_view_input(&mut app, key),
                        AppMode::MetadataEdit => handle_metadata_edit_input(&mut app, key),
                        AppMode::Help => handle_help_input(&mut app, key),
                        AppMode::FileDialog => false, // Should be handled by handle_dialog_input
                    };
                }

                // 3. Handle Global Input (if not handled by dialog or mode)
                if !key_handled {
                    handle_global_input(&mut app, key);
                }
            }
            // Handle other events like mouse or resize if needed later
        }

        // If quit has been requested, break the loop
        if app.should_quit {
            break;
        }
    }

    // Prepare for shutdown (save recent files, stop VDF clock)
    app.shutdown();

    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    Ok(())
}

// --- Input Handling Functions ---

// Handle input when a dialog is active
fn handle_dialog_input(app: &mut App, key: event::KeyEvent) -> bool {
    match &app.dialog {
        Dialog::SaveAs | Dialog::Export => {
            match key.code {
                KeyCode::Esc => {
                    app.dialog = Dialog::None;
                    app.mode = AppMode::Editing; // Go back to editing on cancel
                    app.file_browser.clear_filter();
                    app.message = "Save As / Export cancelled.".to_string();
                    true // Handled
                }
                KeyCode::Enter => {
                    if app.file_browser.is_editing_filename {
                        // Finish editing filename, attempt confirm
                        app.file_browser.is_editing_filename = false;
                        if app.dialog == Dialog::SaveAs { let _ = app.confirm_save_as(); }
                        else { let _ = app.confirm_export(); }
                    } else {
                        // Try to enter directory or confirm file selection
                        if !app.file_browser.enter_directory() {
                            // If not a directory, try confirming the action
                            if app.dialog == Dialog::SaveAs { let _ = app.confirm_save_as(); }
                            else { let _ = app.confirm_export(); }
                        }
                    }
                    true // Handled
                }
                KeyCode::Up => { 
                    if !app.file_browser.is_editing_filename { 
                        app.file_browser.navigate_up(); 
                    } 
                    true 
                }
                KeyCode::Down => { 
                    if !app.file_browser.is_editing_filename { 
                        app.file_browser.navigate_down(); 
                    } 
                    true 
                }
                KeyCode::Tab | KeyCode::Char('f') | KeyCode::Char('F') => { // F or Tab to focus filename input
                    app.file_browser.is_editing_filename = !app.file_browser.is_editing_filename;
                    true
                }
                KeyCode::Char(c) if app.file_browser.is_editing_filename => {
                    app.file_browser.filename_input.push(c);
                    true
                }
                KeyCode::Backspace if app.file_browser.is_editing_filename => {
                    app.file_browser.filename_input.pop();
                    true
                }
                _ => false // Not handled by this dialog
            }
        }
        Dialog::Open => {
            match key.code {
                KeyCode::Esc => {
                    app.dialog = Dialog::None;
                    app.mode = AppMode::Editing;
                    app.file_browser.clear_filter();
                    app.message = "Open cancelled.".to_string();
                    true // Handled
                }
                KeyCode::Enter => {
                    // Try to enter directory or confirm file selection
                    if !app.file_browser.enter_directory() {
                        let _ = app.confirm_open(); // Attempt to open if not a directory
                    }
                    true // Handled (even if open fails, Enter was processed)
                }
                KeyCode::Up => { app.file_browser.navigate_up(); true }
                KeyCode::Down => { app.file_browser.navigate_down(); true }
                _ => false // Not handled by this dialog
            }
        }
        Dialog::UnsavedChanges(_) => {
            match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') => {
                    app.handle_unsaved_dialog_confirm(true); // Save first
                    true
                }
                KeyCode::Char('n') | KeyCode::Char('N') => {
                    app.handle_unsaved_dialog_confirm(false); // Discard changes
                    true
                }
                KeyCode::Esc => {
                    app.dialog = Dialog::None; // Cancel the action
                    app.message = "Action cancelled.".to_string();
                    true
                }
                _ => false
            }
        }
        Dialog::None | Dialog::NewConfirm | Dialog::Metadata => false, // These are handled elsewhere
    }
}



// Handle input in Editing mode
fn handle_editing_input(app: &mut App, key: event::KeyEvent) -> bool {
    // Ctrl+key combinations handled globally
    if key.modifiers.contains(KeyModifiers::CONTROL) { return false; }
    // Alt+key combinations handled globally
    if key.modifiers.contains(KeyModifiers::ALT) { return false; }

    match key.code {
        KeyCode::Enter => { 
            // First capture the current paragraph's text
            let current_line_idx = app.buffer.cursor_row;
            let paragraph_content = app.buffer.lines[current_line_idx].clone();
            
            // Then insert the newline normally
            app.insert_char('\n');
            
            // Create a new leaf with just the paragraph content
            if let Some(tick) = app.document.latest_tick.clone() {
                // Record only this paragraph's content
                app.document.record_paragraph(paragraph_content);
                app.document.create_leaf(tick.sequence_number);
                
                app.message = format!("New paragraph #{} created (VDF tick #{})", 
                                    app.document.leaves.len(), tick.sequence_number);
            }
            
            true 
        },
        KeyCode::Char(c) => { app.insert_char(c); true },
        KeyCode::Backspace => { app.delete_char(); true },
        KeyCode::Left => { app.buffer.move_cursor_left(); true },
        KeyCode::Right => { app.buffer.move_cursor_right(); true },
        KeyCode::Up => { app.buffer.move_cursor_up(); true },
        KeyCode::Down => { app.buffer.move_cursor_down(); true },
        KeyCode::Home => { app.buffer.move_cursor_home(); true },
        KeyCode::End => { app.buffer.move_cursor_end(); true },
        KeyCode::PageUp => { app.buffer.page_up(20); true }, // Use reasonable height
        KeyCode::PageDown => { app.buffer.page_down(20); true },
        KeyCode::Tab | KeyCode::F(2) => { app.toggle_edit_view_mode(); true }, // F2 as alternative toggle
        KeyCode::F(1) => { app.toggle_help(); true }, // F1 handled globally too, but can be mode specific
        _ => false // Not handled by editing mode specifically
    }
}

// Handle input in Viewing mode (Leaf History)
fn handle_viewing_input(app: &mut App, key: event::KeyEvent) -> bool {
    match key.code {
        KeyCode::Up => { 
            app.history_scroll = app.history_scroll.saturating_sub(1); 
            true 
        },
        KeyCode::Down => { 
            app.history_scroll = app.history_scroll.saturating_add(1); 
            true 
        },
        KeyCode::PageUp => { 
            app.history_scroll = app.history_scroll.saturating_sub(10); 
            true 
        },
        KeyCode::PageDown => { 
            app.history_scroll = app.history_scroll.saturating_add(10); 
            true 
        },
        KeyCode::Home => { 
            app.history_scroll = 0; 
            true 
        },
        KeyCode::End => { 
            app.history_scroll = app.document.leaves.len().saturating_sub(1); 
            true 
        },
        KeyCode::Tab | KeyCode::F(2) => { 
            app.toggle_edit_view_mode(); 
            true 
        },
        KeyCode::F(3) => { 
            app.toggle_tree_view(); 
            true 
        },
        KeyCode::F(1) => { 
            app.toggle_help(); 
            true 
        },
        KeyCode::Enter => { // Maybe view details of selected leaf in future? For now, toggle back.
            app.toggle_edit_view_mode();
            true
        },
        _ => false
    }
}

// Handle input in Tree View mode
fn handle_tree_view_input(app: &mut App, key: event::KeyEvent) -> bool {
    match key.code {
        KeyCode::Up => { 
            app.history_scroll = app.history_scroll.saturating_sub(1); 
            true 
        },
        KeyCode::Down => { 
            app.history_scroll = app.history_scroll.saturating_add(1); 
            true 
        },
        KeyCode::PageUp => { 
            app.history_scroll = app.history_scroll.saturating_sub(10); 
            true 
        },
        KeyCode::PageDown => { 
            app.history_scroll = app.history_scroll.saturating_add(10); 
            true 
        },
        KeyCode::Home => { 
            app.history_scroll = 0; 
            true 
        },
        KeyCode::End => {
            let tree_lines = app.document.get_tree_structure();
            app.history_scroll = tree_lines.len().saturating_sub(1);
            true
        },
        KeyCode::Tab | KeyCode::F(2) => { 
            app.toggle_edit_view_mode(); 
            true 
        },
        KeyCode::F(3) => { 
            app.toggle_tree_view(); 
            true 
        },
        KeyCode::F(1) => { 
            app.toggle_help(); 
            true 
        },
        KeyCode::Enter | KeyCode::Esc => {
            app.toggle_tree_view(); // Return to viewing mode
            true
        },
        _ => false
    }
}

// Handle input in Verify Detail mode
fn handle_verify_detail_input(app: &mut App, key: event::KeyEvent) -> bool {
    match key.code {
        KeyCode::Up => { 
            app.history_scroll = app.history_scroll.saturating_sub(1); 
            true 
        },
        KeyCode::Down => { 
            app.history_scroll = app.history_scroll.saturating_add(1); 
            true 
        },
        KeyCode::PageUp => { 
            app.history_scroll = app.history_scroll.saturating_sub(10); 
            true 
        },
        KeyCode::PageDown => { 
            app.history_scroll = app.history_scroll.saturating_add(10); 
            true 
        },
        KeyCode::Home => { 
            app.history_scroll = 0; 
            true 
        },
        KeyCode::End => {
            if let Some(v) = &app.document.last_verification {
                app.history_scroll = v.details.len().saturating_sub(1);
            }
            true
        },
        KeyCode::Tab | KeyCode::F(2) | KeyCode::Enter | KeyCode::Esc => {
            // Any of these return to Viewing mode from verification details
            app.mode = AppMode::Viewing;
            app.history_scroll = 0; // Reset scroll for viewing mode
            app.message = "Returned to Viewing mode.".to_string();
            true
        },
        KeyCode::F(3) => { 
            app.toggle_tree_view(); 
            true 
        },
        KeyCode::F(1) => { 
            app.toggle_help(); 
            true 
        },
        _ => false
    }
}

// Handle input in Metadata Edit mode
fn handle_metadata_edit_input(app: &mut App, key: event::KeyEvent) -> bool {
    if let Some(editor) = app.metadata_editor.as_mut() {
        if editor.editing {
            // Pass input directly to editor buffer handling
            editor.handle_edit_key(key.code);
            true // Assume handled by editor buffer
        } else {
            // Handle navigation between fields or starting edit
            match key.code {
                KeyCode::Up => { editor.navigate_up(); true },
                KeyCode::Down => { editor.navigate_down(); true },
                KeyCode::Enter => { editor.start_editing(); true },
                KeyCode::Esc => { app.cancel_metadata(); true },
                // Ctrl+S handled globally
                KeyCode::F(1) => { app.toggle_help(); true },
                _ => false
            }
        }
    } else {
        // Should not be in this mode without an editor, switch back
        app.mode = AppMode::Editing;
        false
    }
}

// Handle input in Help mode
fn handle_help_input(app: &mut App, key: event::KeyEvent) -> bool {
    match key.code {
        KeyCode::F(1) | KeyCode::Esc => {
            app.toggle_help();
            true
        },
        KeyCode::Up => { true } // Basic scroll placeholder
        KeyCode::Down => { true }
        _ => false // Ignore other keys in help mode
    }
}

// Handle global input shortcuts (like Ctrl+S, Ctrl+O, etc.)
fn handle_global_input(app: &mut App, key: event::KeyEvent) -> bool {
    match key.code {
        // --- Ctrl Keybindings ---
        KeyCode::Char('s') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            if key.modifiers.contains(KeyModifiers::SHIFT) {
                app.trigger_save_as_dialog();
            } else if app.mode == AppMode::MetadataEdit {
                app.save_metadata();
            } else {
                let _ = app.save_document(); // Attempt save, ignore error message here (it's set inside)
            }
            true
        },
        KeyCode::Char('o') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            app.trigger_open_dialog();
            true
        },
        KeyCode::Char('n') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            app.trigger_new_document();
            true
        },
        KeyCode::Char('v') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            app.verify_document(VerificationLevel::Standard);
            true
        },
        KeyCode::Char('e') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            app.trigger_export_dialog();
            true
        },
        KeyCode::Char('m') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            app.trigger_edit_metadata();
            true
        },
        KeyCode::Char('z') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            app.undo();
            true
        },
        // --- Alt Keybindings ---
        KeyCode::Char(c @ '1'..='9') if key.modifiers.contains(KeyModifiers::ALT) => {
            let index = (c as u8 - b'1') as usize; // 1-based index
            app.trigger_open_recent_file(index);
            true
        },
        KeyCode::Char('a') if key.modifiers.contains(KeyModifiers::ALT) => {
            app.toggle_auto_save();
            true
        },
        KeyCode::Char('l') if key.modifiers.contains(KeyModifiers::ALT) => {
            app.toggle_line_numbers();
            true
        },
        // --- F-Key Bindings ---
        KeyCode::F(1) => { // F1 global toggle for help
            app.toggle_help();
            true
        },
        KeyCode::F(2) => { // F2 global toggle for edit/view mode
            if app.mode == AppMode::Editing || app.mode == AppMode::Viewing {
                app.toggle_edit_view_mode();
                true
            } else {
                false
            }
        },
        KeyCode::F(3) => { // F3 toggle tree view
            if app.mode == AppMode::Viewing || app.mode == AppMode::VerifyDetail || app.mode == AppMode::TreeView {
                app.toggle_tree_view();
                true
            } else {
                false
            }
        },
        // --- Other Global Keys ---
        KeyCode::Esc => { // Global Esc always requests quit (with checks)
            app.request_quit();
            true
        },
        _ => false // Not a global keybinding
    }
}

// --- UI Rendering Function ---
fn ui(f: &mut tui::Frame<CrosstermBackend<io::Stdout>>, app: &mut App) {
    let size = f.size();

    // Main layout (Status, Indicator, Message, Content)
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .margin(0) // No outer margin
        .constraints(
            [
                Constraint::Length(1), // Status line
                Constraint::Length(1), // VDF Indicator line
                Constraint::Length(3), // Message bar
                Constraint::Min(0),    // Main content area
            ]
            .as_ref(),
        )
        .split(size);

    // --- Status Line ---
    let chain_status = match &app.document.last_verification {
        Some(v) if v.valid => Style::default().fg(Color::Green),
        Some(_) => Style::default().fg(Color::Red),
        None => Style::default().fg(Color::DarkGray),
    };
    let chain_text = match &app.document.last_verification {
        Some(v) if v.valid => "✓ Valid",
        Some(_) => "✗ Invalid",
        None => "? Unknown",
    };
    let cursor_pos = app.buffer.get_cursor_position();
    let file_name = app.file_path.as_ref()
        .and_then(|p| p.file_name())
        .and_then(|n| n.to_str())
        .unwrap_or("Untitled");
    let dirty_indicator = if app.document.has_unsaved_changes() { "*" } else { "" };
    let auto_save_status = if app.auto_save_enabled { ("On", Color::Green) } else { ("Off", Color::Red) };
    let mode_text = match app.mode {
        AppMode::Editing => "EDITING",
        AppMode::Viewing => "VIEWING HISTORY",
        AppMode::VerifyDetail => "VERIFY DETAILS",
        AppMode::TreeView => "TREE VIEW",
        AppMode::FileDialog => "FILE DIALOG",
        AppMode::MetadataEdit => "EDIT METADATA",
        AppMode::Help => "HELP",
    };

    let status_spans = Line::from(vec![
        Span::styled("BitQuill", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::raw(" | "),
        Span::styled(format!("Mode: {}", mode_text), Style::default().fg(Color::Yellow)),
        Span::raw(" | "),
        Span::styled(format!("File: {}{}", file_name, dirty_indicator), Style::default().fg(Color::Magenta)),
        Span::raw(" | "),
        Span::styled(format!("Ln {}, Col {}", cursor_pos.0, cursor_pos.1), Style::default().fg(Color::LightBlue)),
        Span::raw(" | "),
        Span::styled(format!("Tree: {}", chain_text), chain_status),
        Span::raw(" | "),
        Span::styled(format!("Leaves: {}", app.document.leaves.len()), Style::default().fg(Color::Blue)),
        Span::raw(" | "),
        Span::styled(format!("AutoSave: {}", auto_save_status.0), Style::default().fg(auto_save_status.1)),
    ]);
    let status_bar = Paragraph::new(status_spans).style(Style::default().bg(Color::DarkGray)); // Status bar background
    f.render_widget(status_bar, chunks[0]);

    // --- VDF Tick Indicator ---
    let tick_indicator_text = if app.show_tick_indicator {
        let tick_num = app.document.latest_tick.as_ref().map_or(0, |t| t.sequence_number);
        format!(" VDF Tick #{} Processed ", tick_num)
    } else {
        format!(" VDF Clock Running (Tick #{}) ", 
                app.document.latest_tick.as_ref().map_or(0, |t| t.sequence_number))
    };
    let indicator_style = if app.show_tick_indicator { 
        Style::default().fg(Color::Black).bg(Color::Yellow) 
    } else { 
        Style::default().fg(Color::DarkGray) 
    };
    let indicator = Paragraph::new(Span::styled(tick_indicator_text, indicator_style));
    f.render_widget(indicator, chunks[1]);

    // --- Message Bar ---
    let message_block = Block::default().borders(Borders::ALL).title("Status");
    let message_area = message_block.inner(chunks[2]); // Get inner area for text
    let message = Paragraph::new(app.message.as_str())
        .style(Style::default().fg(Color::White))
        .wrap(tui::widgets::Wrap { trim: true }); // Wrap long messages
    f.render_widget(message_block, chunks[2]);
    f.render_widget(message, message_area);

    // --- Main Content Area ---
    let content_area = chunks[3];

    // Render Dialogs First (if active) - they overlay the main content
    match &app.dialog {
        Dialog::SaveAs => {
            render_file_dialog(f, content_area, &app.file_browser, "Save Document As (.bq)", true);
            return; // Stop rendering normal UI if dialog is shown
        },
        Dialog::Open => {
            render_file_dialog(f, content_area, &app.file_browser, "Open Document (.bq)", false);
            return;
        },
        Dialog::Export => {
            render_file_dialog(f, content_area, &app.file_browser, "Export Merkle Tree Data (.bqc)", true);
            return;
        },
        Dialog::UnsavedChanges(_) => {
            render_unsaved_dialog(f, content_area, app);
            return;
        },
        // Other dialogs removed or handled differently
        Dialog::None | Dialog::NewConfirm | Dialog::Metadata => {} // Continue rendering normal mode
    }

    // Render based on current AppMode
    match app.mode {
        AppMode::Editing => {
            let editor_block = Block::default().borders(Borders::ALL).title("Editor");
            let editor_area = editor_block.inner(content_area);

            // Ensure scroll offset doesn't go beyond limits
            if app.buffer.scroll_offset >= app.buffer.lines.len() && app.buffer.lines.len() > 0 {
                app.buffer.scroll_offset = app.buffer.lines.len() - 1;
            }

            let visible_height = editor_area.height as usize;
            let display_lines = app.buffer.get_display_lines(visible_height);

            // Create TUI text from lines
            let text: Vec<Line> = display_lines.into_iter().map(Line::from).collect();

            let input = Paragraph::new(text)
                .style(Style::default().fg(Color::White));
                // Removed block here as we render the block separately

            f.render_widget(editor_block, content_area);
            f.render_widget(input, editor_area);

            // Calculate cursor position within the rendered area, accounting for line numbers and scroll
            let line_num_width = if app.buffer.line_numbers {
                app.buffer.lines.len().to_string().len() + 3 // Width + space + │ + space
            } else {
                0
            };

            // Ensure cursor row is within visible bounds relative to scroll
            if app.buffer.cursor_row >= app.buffer.scroll_offset &&
               app.buffer.cursor_row < app.buffer.scroll_offset + visible_height {
                let cursor_y = editor_area.y + (app.buffer.cursor_row - app.buffer.scroll_offset) as u16;
                let cursor_x = editor_area.x + app.buffer.cursor_col as u16 + line_num_width as u16;

                // Clamp cursor X to visible width
                let clamped_cursor_x = cursor_x.min(editor_area.x + editor_area.width.saturating_sub(1));

                f.set_cursor(clamped_cursor_x, cursor_y);
            }
        },
        AppMode::Viewing => {
            let history_block = Block::default().borders(Borders::ALL).title("Document History (Read-Only)");
            let history_area = history_block.inner(content_area);

            let history_items_str = app.document.get_leaf_history(); // Get formatted strings

            // Create ListItems from strings
            let items: Vec<ListItem> = history_items_str.iter()
                .map(|h_str| ListItem::new(h_str.as_str()))
                .collect();

            // Create the list widget
            let list = List::new(items)
                .style(Style::default().fg(Color::White))
                .highlight_style(Style::default().bg(Color::Blue).fg(Color::White))
                .highlight_symbol("> "); // Indicator for selected item

            // Create state for the list to handle scrolling/selection
            let mut list_state = tui::widgets::ListState::default();
            // Ensure scroll offset maps correctly to list selection/offset
            if !app.document.leaves.is_empty() {
                app.history_scroll = app.history_scroll.min(app.document.leaves.len() - 1); // Clamp scroll
                list_state.select(Some(app.history_scroll)); // Select the item corresponding to scroll offset
                // TUI list handles offset automatically based on selection and height
            }

            f.render_widget(history_block, content_area);
            f.render_stateful_widget(list, history_area, &mut list_state);
        },
        AppMode::TreeView => {
            let tree_block = Block::default().borders(Borders::ALL).title("Merkle Tree Structure");
            let tree_area = tree_block.inner(content_area);
            
            let tree_items_str = app.document.get_tree_structure(); // Get formatted tree structure
            
            // Create ListItems from strings
            let items: Vec<ListItem> = tree_items_str.iter()
                .map(|t_str| ListItem::new(t_str.as_str()))
                .collect();
                
            // Create the list widget
            let list = List::new(items)
                .style(Style::default().fg(Color::White))
                .highlight_style(Style::default().bg(Color::DarkGray)) // Less prominent highlight
                .highlight_symbol("→ "); // Indicator for current line
                
            // Create state for scrolling
            let mut list_state = tui::widgets::ListState::default();
            app.history_scroll = app.history_scroll.min(tree_items_str.len().saturating_sub(1)); // Clamp scroll
            list_state.select(Some(app.history_scroll)); // Use select to control view offset
            
            f.render_widget(tree_block, content_area);
            f.render_stateful_widget(list, tree_area, &mut list_state);
        },
        AppMode::VerifyDetail => {
            let verify_block = Block::default().borders(Borders::ALL).title("Verification Details");
            let verify_area = verify_block.inner(content_area);
            f.render_widget(verify_block, content_area); // Render block first

            let mut items: Vec<ListItem> = Vec::new(); // Initialize list items vector

            // --- Add Overall Status ---
            if let Some(v) = &app.document.last_verification {
                let (status_text, status_style) = if v.valid {
                    ("PASSED", Style::default().fg(Color::Green).add_modifier(Modifier::BOLD))
                } else {
                    ("FAILED", Style::default().fg(Color::Red).add_modifier(Modifier::BOLD))
                };
                let overall_summary = format!("Overall Status: {} ({:?})", status_text, v.level);
                items.push(ListItem::new(Line::from(Span::styled(overall_summary, status_style))));
                items.push(ListItem::new("-----------------------------------")); // Separator
            } else {
                items.push(ListItem::new("Overall Status: Not Yet Verified"));
                items.push(ListItem::new("-----------------------------------")); // Separator
            }
            // --- End Overall Status ---


            // Get individual details if available
            let details = if let Some(v) = &app.document.last_verification {
                v.details.clone()
            } else {
                // Provide a single item if no verification yet, already handled above
                Vec::new() // No details to add if verification hasn't run
            };

            // --- Add Individual Details ---
            for detail in details.iter() {
                 let style = if detail.valid {
                    Style::default().fg(Color::Green)
                 } else {
                    Style::default().fg(Color::Red)
                 };
                 let icon = if detail.valid { " ✓" } else { " ✗" }; // Space for alignment
                 items.push(ListItem::new(Span::styled(format!("{} {}", icon, detail.description), style)));
            }
            // --- End Individual Details ---


            // --- Render the List ---
            let list = List::new(items) // Use the combined items list
                .style(Style::default().fg(Color::White))
                // Highlight the entire line for simplicity when scrolling
                .highlight_style(Style::default().bg(Color::DarkGray))
                .highlight_symbol("→ "); // Indicator for current line

            // Create state for scrolling
            let mut list_state = tui::widgets::ListState::default();
            // Ensure scroll offset doesn't exceed list length
            let item_count = if let Some(v) = &app.document.last_verification { v.details.len() + 2 } else { 2 }; // +2 for summary lines
            app.history_scroll = app.history_scroll.min(item_count.saturating_sub(1)); // Clamp scroll based on total items
            list_state.select(Some(app.history_scroll)); // Use select to control view offset

            f.render_stateful_widget(list, verify_area, &mut list_state);

            // Adjust End key navigation in handle_verify_detail_input if needed
            // The End key logic might need to use `items.len()` or `item_count`
            // Example adjustment in handle_verify_detail_input:
            /*
            KeyCode::End => {
                let item_count = if let Some(v) = &app.document.last_verification { v.details.len() + 2 } else { 2 };
                app.history_scroll = item_count.saturating_sub(1);
                true
            },
            */
        },
        AppMode::MetadataEdit => {
            render_metadata_editor(f, content_area, app);
        },
        AppMode::Help => {
            render_help_screen(f, content_area, app);
        },
        AppMode::FileDialog => {
            // This case should ideally be handled by the dialog rendering at the start
            let error_block = Block::default().borders(Borders::ALL).title("Error");
            let inner_area = error_block.inner(content_area);

            let error_text = Paragraph::new("Invalid state: FileDialog mode without active dialog.")
                .style(Style::default().fg(Color::Red));
            f.render_widget(error_block, content_area);
            f.render_widget(error_text, inner_area);
        }
    }
}

// --- UI Helper Rendering Functions ---

// Render file browser dialog
fn render_file_dialog(
    f: &mut tui::Frame<CrosstermBackend<io::Stdout>>, 
    area: Rect, 
    browser: &FileBrowser, 
    title: &str, 
    show_filename_input: bool
) {
    let dialog_block = Block::default().borders(Borders::ALL).title(title);
    let inner_area = dialog_block.inner(area); // Area inside borders

    // Define constraints based on whether filename input is shown
    let constraints = if show_filename_input {
        vec![
            Constraint::Length(1),  // Current directory path
            Constraint::Min(0),     // File list (takes remaining space)
            Constraint::Length(1),  // Filename input line
            Constraint::Length(1),  // Hint line
        ]
    } else {
        vec![
            Constraint::Length(1),  // Current directory path
            Constraint::Min(0),     // File list
            Constraint::Length(1),  // Hint line
        ]
    };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(inner_area); // Split the inner area

    f.render_widget(dialog_block, area); // Render the block frame first

    // 1. Current Directory
    let current_dir_text = Paragraph::new(browser.current_dir.to_string_lossy().to_string())
        .style(Style::default().fg(Color::Yellow));
    f.render_widget(current_dir_text, chunks[0]);

    // 2. File List
    let entries = browser.get_entries_for_display();
    let items: Vec<ListItem> = entries.iter()
        .map(|entry_str| ListItem::new(entry_str.as_str()))
        .collect();

    let list = List::new(items)
        .style(Style::default().fg(Color::White))
        .highlight_style(Style::default().bg(Color::Blue).fg(Color::White))
        .highlight_symbol("> ");

    let mut list_state = tui::widgets::ListState::default();
    if !browser.entries.is_empty() {
        let clamped_selection = browser.selected_idx.min(browser.entries.len() - 1);
        list_state.select(Some(clamped_selection));
    }

    f.render_stateful_widget(list, chunks[1], &mut list_state);

    // 3. Filename Input (Optional)
    let hint_index = if show_filename_input {
        let filename_style = if browser.is_editing_filename {
            Style::default().fg(Color::Yellow) // Highlight if editing
        } else {
            Style::default().fg(Color::White)
        };
        let filename_text = format!("Filename: {}", browser.filename_input);
        let filename_para = Paragraph::new(filename_text).style(filename_style);
        f.render_widget(filename_para, chunks[2]);

        // Show cursor if editing filename
        if browser.is_editing_filename {
            f.set_cursor(
                chunks[2].x + 10 + browser.filename_input.len() as u16, // "Filename: ".len() = 10
                chunks[2].y
            );
        }
        3 // Hint is at index 3
    } else {
        2 // Hint is at index 2
    };

    // 4. Hint Text
    let hint_text_str = if show_filename_input {
        "Arrows: Navigate | Enter: Confirm/Select | F/Tab: Edit Filename | Esc: Cancel"
    } else {
        "Arrows: Navigate | Enter: Confirm/Select | Esc: Cancel"
    };
    let hint = Paragraph::new(hint_text_str).style(Style::default().fg(Color::DarkGray));
    f.render_widget(hint, chunks[hint_index]);
}

// Render unsaved changes dialog
fn render_unsaved_dialog(f: &mut tui::Frame<CrosstermBackend<io::Stdout>>, area: Rect, app: &App) {
    if let Dialog::UnsavedChanges(action) = &app.dialog {
        let action_desc = match action {
            UnsavedAction::New => "create a new document",
            UnsavedAction::Open => "open another document",
            UnsavedAction::Quit => "quit",
            UnsavedAction::OpenRecent(_) => "open a recent file",
        };
let text = vec![
            Line::from(Span::styled("Unsaved Changes", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD))),
            Line::from(""),
            Line::from(format!("The current document has unsaved changes.")),
            Line::from(format!("Do you want to save before you {}?", action_desc)),
            Line::from(""),
            Line::from(vec![
                Span::styled("  [Y]", Style::default().fg(Color::Green)), Span::raw("es (Save) "),
                Span::styled("  [N]", Style::default().fg(Color::Red)), Span::raw("o (Discard) "),
                Span::styled("  [Esc]", Style::default().fg(Color::Gray)), Span::raw(" Cancel"),
            ]),
        ];

        let paragraph = Paragraph::new(text)
            .alignment(tui::layout::Alignment::Center)
            .block(Block::default().borders(Borders::ALL).title("Confirm"));

        // Create a smaller centered rect for the dialog
        let dialog_area = centered_rect(60, 30, area); // 60% width, 30% height

        f.render_widget(paragraph, dialog_area);
    }
}

// Render metadata editor UI
fn render_metadata_editor(f: &mut tui::Frame<CrosstermBackend<io::Stdout>>, area: Rect, app: &mut App) {
    if let Some(editor) = &app.metadata_editor {
        let block = Block::default().borders(Borders::ALL).title("Edit Metadata");
        let inner_area = block.inner(area);
        f.render_widget(block, area);

        let fields = ["Title:", "Author:", "Keywords:", "Description:"];
        let values = [
            &editor.metadata.title,
            &editor.metadata.author,
            &editor.metadata.keywords.join(", "), // Show as comma-separated
            &editor.metadata.description,
        ];

        let mut items: Vec<ListItem> = Vec::new();
        let mut cursor_pos: Option<(u16, u16)> = None;

        for i in 0..fields.len() {
            let is_selected = i == editor.current_field;
            let is_editing = is_selected && editor.editing;

            let field_style = if is_selected && !is_editing {
                Style::default().bg(Color::Blue).fg(Color::White) // Selected field highlight
            } else {
                Style::default().fg(Color::White)
            };

            let value_style = if is_editing {
                Style::default().fg(Color::Yellow) // Editing value highlight
            } else {
                field_style // Inherit field style if not editing value
            };

            let value_text = if is_editing {
                &editor.edit_buffer
            } else {
                values[i] // We've already pre-computed the joined string in values
            };

            items.push(ListItem::new(Line::from(vec![
                Span::styled(format!("{:<12}", fields[i]), field_style), // Pad field name
                Span::styled(value_text, value_style),
            ])));

            // Set cursor position if this field is being edited
            if is_editing {
                cursor_pos = Some((
                    inner_area.x + 12 + editor.edit_buffer.len() as u16, // 12 = field width + space
                    inner_area.y + i as u16, // Y position based on field index
                ));
            }
        }

        // Add instructions
        items.push(ListItem::new("")); // Spacer
        items.push(ListItem::new(Line::from(Span::styled(
            "Arrows: Navigate | Enter: Edit/Save Field | Ctrl+S: Save All | Esc: Cancel Edit/Dialog", 
            Style::default().fg(Color::DarkGray)
        ))));

        let list = List::new(items);
        f.render_widget(list, inner_area);

        // Set cursor if editing
        if let Some((x, y)) = cursor_pos {
            f.set_cursor(x.min(inner_area.right() - 1), y); // Clamp cursor X
        }
    }
}

// Render help screen
fn render_help_screen(f: &mut tui::Frame<CrosstermBackend<io::Stdout>>, area: Rect, app: &App) {
    let block = Block::default().borders(Borders::ALL).title("Help - BitQuill Merkle Edition");
    let inner_area = block.inner(area);
    f.render_widget(block, area);

    let help_text = app.get_help_text();
    let items: Vec<ListItem> = help_text.iter()
        .map(|line| ListItem::new(line.as_str()))
        .collect();

    // Basic list display, scrolling not implemented yet for help
    let list = List::new(items).style(Style::default().fg(Color::White));
    f.render_widget(list, inner_area);
}

// Helper function to create a centered rect
fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    // Clamp percentages
    let percent_x = percent_x.min(100);
    let percent_y = percent_y.min(100);

    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints(
            [
                Constraint::Percentage((100 - percent_y) / 2),
                Constraint::Percentage(percent_y),
                Constraint::Percentage((100 - percent_y) / 2),
            ]
            .as_ref(),
        )
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints(
            [
                Constraint::Percentage((100 - percent_x) / 2),
                Constraint::Percentage(percent_x),
                Constraint::Percentage((100 - percent_x) / 2),
            ]
            .as_ref(),
        )
        .split(popup_layout[1])[1]
}
