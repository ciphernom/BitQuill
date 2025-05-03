use num_bigint::BigUint;
use num_integer::Integer; // Add this
use num_traits::{One, Zero}; // Add this
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use tui::layout::Rect;

// Safely calculate 2^t for large t values
pub fn calculate_power_safely(iterations: u64) -> Result<BigUint, String> {
    if iterations > 1000 {
        // For very large iterations, use a more efficient approach
        let base = BigUint::from(2u32);
        let exp = BigUint::from(iterations);
        
        // Start with 1
        let mut result = BigUint::one(); // Now works with One trait
        let mut base_pow = base.clone();
        let mut exp_remaining = exp.clone();
        
        // Binary exponentiation algorithm (Russian peasant algorithm)
        while !exp_remaining.is_zero() { // Now works with Zero trait
            if exp_remaining.is_odd() { // Now works with Integer trait
                result = result * &base_pow;
            }
            base_pow = &base_pow * &base_pow;
            exp_remaining >>= 1;
        }
        
        Ok(result)
    } else {
        // For smaller iterations, direct calculation is fine
        Ok(BigUint::from(2u32).pow(iterations as u32))
    }
}

// Helper function to create a centered rect for dialogs
pub fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    // Clamp percentages
    let percent_x = percent_x.min(100);
    let percent_y = percent_y.min(100);

    let popup_layout = tui::layout::Layout::default()
        .direction(tui::layout::Direction::Vertical)
        .constraints(
            [
                tui::layout::Constraint::Percentage((100 - percent_y) / 2),
                tui::layout::Constraint::Percentage(percent_y),
                tui::layout::Constraint::Percentage((100 - percent_y) / 2),
            ]
            .as_ref(),
        )
        .split(r);

    tui::layout::Layout::default()
        .direction(tui::layout::Direction::Horizontal)
        .constraints(
            [
                tui::layout::Constraint::Percentage((100 - percent_x) / 2),
                tui::layout::Constraint::Percentage(percent_x),
                tui::layout::Constraint::Percentage((100 - percent_x) / 2),
            ]
            .as_ref(),
        )
        .split(popup_layout[1])[1]
}

// Get config directory path
pub fn get_config_dir() -> PathBuf {
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

// Hash-related utility functions
pub fn calculate_hash(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data).to_vec())
}

// Attack: Predict which ticks will be verified
// Defense: Use cryptographic mixing to make sampling unpredictable
pub fn select_verification_samples(ticks: &[u64], document_hash: &str) -> Vec<u64> {
    // Use document hash as seed for unpredictable but deterministic sampling
    let mut hasher = Sha256::new();
    hasher.update(document_hash.as_bytes());
    let seed = hasher.finalize();

    // Mix each tick with seed to determine if it should be sampled
    ticks.iter()
        .filter(|&&t| {
            let mut tick_hasher = Sha256::new();
            tick_hasher.update(seed.as_slice());
            tick_hasher.update(&t.to_be_bytes());
            let hash = tick_hasher.finalize();
            // Sample ~20% of ticks unpredictably based on the first byte of the hash
            hash[0] < 51 // 51/256 ≈ 19.9% probability
        })
        .cloned()
        .collect()
}

// Attack: Use weak RSA modulus
// Defense: Verify modulus properties
pub fn verify_modulus_strength(modulus: &BigUint) -> bool {
    // Verify minimum size (e.g., 1024 bits)
    if modulus.bits() < 1024 {
        return false;
    }

    // Quick primality check of modulus+1 and modulus-1
    let one = BigUint::one();
    let modulus_plus_1 = modulus + &one;
    let modulus_minus_1 = modulus - &one;

    // Use Miller-Rabin primality test with few rounds for quick check
    let rounds = 5; // Low rounds for speed, increase if needed
    if crate::vdf::is_prime(&modulus_plus_1, rounds) {
        return false; // Suspicious if either is prime
    }
    
    if crate::vdf::is_prime(&modulus_minus_1, rounds) {
        return false; // Suspicious if either is prime
    }

    true
}
