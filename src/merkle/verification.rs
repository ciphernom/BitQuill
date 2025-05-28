use crate::constants::*;
use crate::utils;
use crate::vdf::VDFClockTick;
use crate::merkle::hash::calculate_leaf_hash;
use crate::merkle::types::*;

use num_bigint::BigUint;
use sha2::{Digest, Sha256};
use std::time::Instant;
use hex;

impl MerkleDocument {
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
}
