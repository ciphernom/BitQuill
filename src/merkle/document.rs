use crate::constants::*;
use crate::error::{BitQuillError, BitQuillResult};
use crate::utils;
use crate::vdf::{VDF, VDFProof, VDFClockTick, compute_vdf_proof};
use crate::merkle::hash::{calculate_leaf_hash, calculate_node_hash, get_element_hash};
use crate::merkle::types::*;
use crate::merkle::analysis::*;
use crate::merkle::verification::*;

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
    pub fn rebuild_merkle_tree(&mut self) -> BitQuillResult<()> {
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
