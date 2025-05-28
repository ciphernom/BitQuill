use crate::merkle::types::{MerkleLeaf, MerkleTreeElement};
use crate::error::{BitQuillError, BitQuillResult};
use sha2::{Digest, Sha256};
use std::time::SystemTime;

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
