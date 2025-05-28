use crate::constants::*;
use crate::error::{BitQuillError, BitQuillResult};
use crate::merkle::types::*;
use crate::vdf::VDFClockTick; // Added VDFClockTick
use sha2::Digest; // Add Digest for the sha256::digest function

use std::{
    fs,
    path::PathBuf,
    time::SystemTime,
};
use serde_json;

impl MerkleDocument {
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
            self.current_state.timestamp = std::time::Instant::now(); // Reset Instant
        } else {
            // No leaves, initialize as a new empty document state
            let genesis_hash = hex::encode(sha2::Sha256::digest(b"MerkleQuill Genesis").to_vec());
            self.current_state = DocumentState {
                content: String::new(),
                timestamp: std::time::Instant::now(),
                system_time: SystemTime::now(),
                state_hash: genesis_hash,
            };
        }
        self.last_edit_time = std::time::Instant::now(); // Reset edit time

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
                match crate::vdf::VDF::from_modulus_bytes(&modulus_bytes) {
                    Ok(vdf) => self.vdf = vdf,
                    Err(e) => return Err(BitQuillError::ValidationError(format!(
                        "Invalid VDF modulus in file: {}", e
                    )))
                }
            } else {
                // Generate new VDF if empty modulus
                match crate::vdf::VDF::new(2048) {
                    Ok(vdf) => self.vdf = vdf,
                    Err(e) => return Err(e)
                }
            }
        } else {
            // Generate new VDF if no modulus
            match crate::vdf::VDF::new(2048) {
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
}
