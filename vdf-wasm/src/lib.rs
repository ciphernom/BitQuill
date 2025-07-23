//! Wesolowski's Verifiable Delay Function (VDF) Implementation for WASM
//! 
//! This implementation provides cryptographically secure time-lock puzzles
//! with efficient verification. Based on the paper "Efficient Verifiable Delay Functions"
//! by Krzysztof Pietrzak (2018) and Benjamin Wesolowski (2019).

use wasm_bindgen::prelude::*;
use num_bigint::{BigUint, RandBigInt};
use num_traits::{Zero, One};
use num_integer::Integer;
use sha2::{Sha256, Digest};
use rand::thread_rng;
use base64::{Engine as _, engine::general_purpose};
use js_sys::Function;
use serde::{Serialize, Deserialize};

/// RSA-2048 modulus from the RSA Factoring Challenge
/// This modulus has unknown factorization, making it suitable for VDF
const RSA_2048_MODULUS: &str = "C7970CEEDCC3B0754490201A7AA613CD73911081C790F5F1A8726F463550BB5B7FF0DB8E1EA1189EC72F93D1650011BD721AEEACC2ACDE32A04107F0648C2813A31F5B0B7765FF8B44B4B6FFC93384B646EB09C7CF5E8592D40EA33C80039F35B4F14A04B51F7BFD781BE4D1673164BA8EB991C2C4D730BBBE35F592BDEF524AF7E8DAEFD26C66FC02C479AF89D64D373F442709439DE66CEB955F3EA37D5159F6135809F85334B5CB1813ADDC80CD05609F10AC6A95AD65872C909525BDAD32BC729592642920F24C61DC5B3C3B7923E56B16A4D9D373D8721F24A3FC0F1B3131F55615172866BCCC30F95054C824E733A5EB6817F7BC16399D48C6361CC7E5";

/// Security parameter for prime generation (bits)
const SECURITY_BITS: usize = 128;

/// Maximum allowed iterations to prevent DoS
const MAX_ITERATIONS: u64 = 100_000_000;

/// Minimum iterations for meaningful delay
const MIN_ITERATIONS: u64 = 1000;

/// Progress reporting interval
const PROGRESS_INTERVAL: u64 = 10000;

// Enable console logging for debugging
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = console)]
    fn log(s: &str);
    
    #[wasm_bindgen(js_namespace = console)]
    fn error(s: &str);
    
    #[wasm_bindgen(js_namespace = console)]
    fn warn(s: &str);
}

/// Macro for debug logging
macro_rules! debug_log {
    ($($t:tt)*) => (log(&format_args!($($t)*).to_string()))
}

/// Macro for error logging
macro_rules! error_log {
    ($($t:tt)*) => (error(&format_args!($($t)*).to_string()))
}

/// VDF Proof structure containing all verification parameters
#[wasm_bindgen]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VDFProof {
    /// Output: y = x^(2^t) mod N
    y: String,
    
    /// Proof value: π such that y = π^l * x^r mod N
    pi: String,
    
    /// Challenge prime (deterministically generated via Fiat-Shamir)
    l: String,
    
    /// Remainder: r = 2^t mod l
    r: String,
    
    /// Number of iterations (time parameter)
    iterations: u64,
    
    /// Proof generation timestamp (for audit trail)
    #[serde(skip)]
    timestamp: u64,
}

#[wasm_bindgen]
impl VDFProof {
    #[wasm_bindgen(constructor)]
    pub fn new(y: String, pi: String, l: String, r: String, iterations: u64) -> Self {
        VDFProof {
            y,
            pi,
            l,
            r,
            iterations,
            timestamp: js_sys::Date::now() as u64,
        }
    }
    
    #[wasm_bindgen(getter)]
    pub fn y(&self) -> String {
        self.y.clone()
    }
    
    #[wasm_bindgen(getter)]
    pub fn pi(&self) -> String {
        self.pi.clone()
    }
    
    #[wasm_bindgen(getter)]
    pub fn l(&self) -> String {
        self.l.clone()
    }
    
    #[wasm_bindgen(getter)]
    pub fn r(&self) -> String {
        self.r.clone()
    }
    
    #[wasm_bindgen(getter)]
    pub fn iterations(&self) -> u64 {
        self.iterations
    }
    
    /// Serialize proof to JSON
    #[wasm_bindgen]
    pub fn to_json(&self) -> Result<String, JsValue> {
        serde_json::to_string(self)
            .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))
    }
    
    /// Deserialize proof from JSON
    #[wasm_bindgen]
    pub fn from_json(json: &str) -> Result<VDFProof, JsValue> {
        serde_json::from_str(json)
            .map_err(|e| JsValue::from_str(&format!("Deserialization error: {}", e)))
    }
}

/// Main VDF computer with optimized algorithms
#[wasm_bindgen]
pub struct VDFComputer {
    modulus: BigUint,
    /// Precomputed Montgomery parameters for faster modular arithmetic
    montgomery_r: BigUint,
    montgomery_r_inv: BigUint,
}

#[wasm_bindgen]
impl VDFComputer {
    /// Create a new VDF computer with the RSA-2048 modulus
    #[wasm_bindgen(constructor)]
    pub fn new() -> VDFComputer {
        let modulus = BigUint::parse_bytes(RSA_2048_MODULUS.as_bytes(), 16)
            .expect("Failed to parse modulus");
        
        let montgomery_r = BigUint::one() << modulus.bits();
        let montgomery_r_inv = montgomery_r.clone();
        
        VDFComputer {
            modulus,
            montgomery_r,
            montgomery_r_inv,
        }
    }
    
    /// Create a VDF computer with a custom modulus (hex string)
    #[wasm_bindgen]
    pub fn with_modulus(modulus_hex: &str) -> Result<VDFComputer, JsValue> {
        let modulus = BigUint::parse_bytes(modulus_hex.as_bytes(), 16)
            .ok_or_else(|| JsValue::from_str("Invalid modulus format"))?;
        
        // Validate modulus is odd and large enough
        if modulus.is_even() || modulus.bits() < 1024 {
            return Err(JsValue::from_str("Modulus must be odd and at least 1024 bits"));
        }
        
        // Precompute Montgomery parameters (simplified for this example)
        let montgomery_r = BigUint::one() << modulus.bits();
        let montgomery_r_inv = montgomery_r.clone();
        
        Ok(VDFComputer {
            modulus,
            montgomery_r,
            montgomery_r_inv,
        })
    }
    
    /// Compute a VDF proof with progress callback
    #[wasm_bindgen]
    pub fn compute_proof(
        &self,
        input: &str,
        iterations: u64,  // wasm-bindgen handles BigInt -> u64 conversion
        on_progress: Option<Function>,  
    ) -> Result<VDFProof, JsValue> {
        self.compute_proof_internal(input, iterations, on_progress)
            .map_err(|e| JsValue::from_str(&e))
    }
    
    /// Verify a VDF proof
    #[wasm_bindgen]
    pub fn verify_proof(&self, input: &str, proof: &VDFProof) -> Result<bool, JsValue> {
        self.verify_proof_internal(input, proof)
            .map_err(|e| JsValue::from_str(&e))
    }
    
    /// Estimate iterations needed for a given time in seconds
    #[wasm_bindgen]
    pub fn estimate_iterations_for_seconds(&self, seconds: f64) -> u64 {
        // Benchmark-based estimation (should be calibrated per device)
        // Modern CPU: ~5-20M iterations/second depending on implementation
        let base_rate = 10_000_000.0;
        let iterations = (seconds * base_rate) as u64;
        iterations.clamp(MIN_ITERATIONS, MAX_ITERATIONS)
    }
    
    /// Internal proof generation with full error handling
    fn compute_proof_internal(
        &self,
        input: &str,
        iterations: u64,
        on_progress: Option<Function>,
    ) -> Result<VDFProof, String> {
        // Validate parameters
        if iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS {
            return Err(format!(
                "Iterations must be between {} and {}",
                MIN_ITERATIONS, MAX_ITERATIONS
            ));
        }
        
        if input.is_empty() {
            return Err("Input cannot be empty".to_string());
        }
        
        debug_log!("Starting VDF computation with {} iterations", iterations);
        
        // Hash input to get starting value x
        let x = self.hash_to_group(input)?;
        
        // Compute y = x^(2^t) mod N using repeated squaring
        let start_time = js_sys::Date::now();
        let y = self.compute_vdf_output(&x, iterations, &on_progress)?;
        let compute_time = js_sys::Date::now() - start_time;
        
        debug_log!("VDF computation completed in {}ms", compute_time);
        
        // Generate challenge prime l using Fiat-Shamir
        let l = self.generate_fiat_shamir_prime(&x, &y, iterations)?;
        
        // Compute remainder r = 2^t mod l
        let r = self.compute_remainder(iterations, &l)?;
        
        // Compute proof π using Wesolowski's algorithm
        let pi = self.compute_wesolowski_proof(&x, iterations, &l)?;
        
            // ADD THE DEBUGGING CODE HERE!
        debug_log!("=== VDF Proof Generation Debug ===");
        debug_log!("iterations: {}", iterations);
        debug_log!("x (first 32 chars): {}...", x.to_str_radix(16).chars().take(32).collect::<String>());
        debug_log!("y (first 32 chars): {}...", y.to_str_radix(16).chars().take(32).collect::<String>());
        debug_log!("l: {}", l);
        debug_log!("r: {}", r);
        debug_log!("pi (first 32 chars): {}...", pi.to_str_radix(16).chars().take(32).collect::<String>());
        // Verify the equation holds before encoding
        let pi_l = pi.modpow(&l, &self.modulus);
        let x_r = x.modpow(&r, &self.modulus);
        let check = (pi_l * x_r) % &self.modulus;
        debug_log!("Self-check: y == pi^l * x^r? {}", y == check);
        
        
        // Encode all values to base64
        let proof = VDFProof {
            y: general_purpose::STANDARD.encode(y.to_bytes_be()),
            pi: general_purpose::STANDARD.encode(pi.to_bytes_be()),
            l: general_purpose::STANDARD.encode(l.to_bytes_be()),
            r: general_purpose::STANDARD.encode(r.to_bytes_be()),
            iterations,
            timestamp: js_sys::Date::now() as u64,
        };
        
        // Self-verify as sanity check
        if !self.verify_proof_internal(input, &proof)? {
            return Err("Self-verification failed".to_string());
        }
        
        Ok(proof)
    }
    
    /// Hash input to a group element
    fn hash_to_group(&self, input: &str) -> Result<BigUint, String> {
        let mut hasher = Sha256::new();
        hasher.update(b"VDF_HASH_TO_GROUP_v1");
        hasher.update(input.as_bytes());
        hasher.update(&self.modulus.to_bytes_be());
        
        let mut counter = 0u32;
        loop {
            let mut h = hasher.clone();
            h.update(&counter.to_be_bytes());
            let hash = h.finalize();
            let candidate = BigUint::from_bytes_be(&hash);
            
            // Ensure we get a valid element in Z*_N
            if candidate < self.modulus && candidate > BigUint::zero() {
                // Check gcd(candidate, N) = 1 (simplified - assumes N is product of two primes)
                if candidate.gcd(&self.modulus).is_one() {
                    return Ok(candidate);
                }
            }
            
            counter += 1;
            if counter > 1000 {
                return Err("Failed to hash to group".to_string());
            }
        }
    }
    
    /// Compute VDF output y = x^(2^t) mod N
    fn compute_vdf_output(
        &self,
        x: &BigUint,
        iterations: u64,
        on_progress: &Option<Function>,
    ) -> Result<BigUint, String> {
        let mut y = x.clone();
        let mut last_progress = 0u64;
        
        for i in 0..iterations {
            // Optimized squaring: y = y^2 mod N
            y = self.mod_square(&y);
            
            // Progress reporting
            if let Some(callback) = on_progress {
                if i % PROGRESS_INTERVAL == 0 || i == iterations - 1 {
                    let progress = ((i + 1) * 100) / iterations;
                    if progress != last_progress {
                        last_progress = progress;
                        let this = JsValue::null();
                        let progress_val = JsValue::from_f64(progress as f64);
                        if let Err(e) = callback.call1(&this, &progress_val) {
                            warn(&format!("Progress callback error: {:?}", e));
                        }
                    }
                }
            }
        }
        
        Ok(y)
    }
    
    /// Optimized modular squaring
    fn mod_square(&self, x: &BigUint) -> BigUint {
        // For production, implement Montgomery multiplication
        (x * x) % &self.modulus
    }
    
    /// Generate deterministic challenge prime using Fiat-Shamir
    fn generate_fiat_shamir_prime(
        &self,
        x: &BigUint,
        y: &BigUint,
        iterations: u64,
    ) -> Result<BigUint, String> {
        let mut hasher = Sha256::new();
        hasher.update(b"VDF_FIAT_SHAMIR_v1");
        hasher.update(&x.to_bytes_be());
        hasher.update(&y.to_bytes_be());
        hasher.update(&iterations.to_be_bytes());
        hasher.update(&self.modulus.to_bytes_be());
        
       
        // Use the hash directly for deterministic generation
        for attempt in 0..1000 {
            let mut h = hasher.clone();  // Clone the original hasher
            h.update(&(attempt as u32).to_be_bytes());
            // Don't finalize h here either - we need it for the inner loop
            
            // Build a SECURITY_BITS sized number from repeated hashing
            let mut bytes = Vec::new();
            let mut counter = 0u32;
            while bytes.len() * 8 < SECURITY_BITS {
                let mut h2 = h.clone();  // Clone h each time
                h2.update(&counter.to_be_bytes());
                bytes.extend_from_slice(&h2.finalize());  // Only finalize h2
                counter += 1;
            }
            
            // Truncate to exact bit length
            let bytes_needed = (SECURITY_BITS + 7) / 8;
            bytes.truncate(bytes_needed);
            
            let mut candidate = BigUint::from_bytes_be(&bytes);
            
            // Ensure exactly SECURITY_BITS
            if SECURITY_BITS % 8 != 0 {
                candidate >>= 8 - (SECURITY_BITS % 8);
            }
            
            candidate |= BigUint::one(); // Make odd
            candidate |= BigUint::one() << (SECURITY_BITS - 1); // Set high bit
            
            if self.is_probable_prime(&candidate, 40) {
                debug_log!("Generated challenge prime in {} attempts", attempt + 1);
                return Ok(candidate);
            }
        }
        
        Err("Failed to generate challenge prime".to_string())
    }
    
    /// Compute r = 2^t mod l efficiently
    fn compute_remainder(&self, iterations: u64, l: &BigUint) -> Result<BigUint, String> {
        // Use binary exponentiation
        let base = BigUint::from(2u32);
        Ok(base.modpow(&BigUint::from(iterations), l))
    }
    
/// Compute Wesolowski proof using a correct long division algorithm
fn compute_wesolowski_proof(
    &self,
    x: &BigUint,
    iterations: u64,
    l: &BigUint,
) -> Result<BigUint, String> {
    // We compute pi = x^q, where q is the quotient of 2^t / l.
    // The bits of q are determined by a long division process.
    
    let mut pi = BigUint::one();
    let mut remainder = BigUint::zero();
    
    // We need to process t+1 bits for the number 2^t (a 1 followed by t zeros).
    // We iterate from the most significant bit downwards.
    for i in (0..=iterations).rev() { // CORRECT: from t down to 0
        // Every step in the long division corresponds to a squaring in the exponentiation.
        // This is the "square" part of the square-and-multiply algorithm.
        pi = self.mod_square(&pi);
        
        // Bring down the next bit of the dividend (2^t).
        remainder <<= 1;
        
        // The most significant bit (at position t) is 1; all others are 0.
        if i == iterations {
            remainder |= BigUint::one();
        }
        
        // Check if the divisor 'l' goes into the current remainder.
        if remainder >= *l {
            remainder -= l;
            // If it does, the quotient bit is 1. This corresponds to the "multiply"
            // part of the square-and-multiply algorithm.
            pi = (pi * x) % &self.modulus;
        }
    }
    
    Ok(pi)
}
    
    
    /// Verify a VDF proof
fn verify_proof_internal(&self, input: &str, proof: &VDFProof) -> Result<bool, String> {
    // Validate parameters
    if proof.iterations < MIN_ITERATIONS || proof.iterations > MAX_ITERATIONS {
        return Ok(false);
    }
    
    // Decode base64 values
    let y = base64_to_biguint(&proof.y)?;
    let pi = base64_to_biguint(&proof.pi)?;
    let l = base64_to_biguint(&proof.l)?;
    let r = base64_to_biguint(&proof.r)?;
    
    // Verify l is a valid prime
    if l.bits() < (SECURITY_BITS as u64 - 8) || !self.is_probable_prime(&l, 20) {
        debug_log!("Invalid challenge prime");
        return Ok(false);
    }
    
    // Hash input to get x
    let x = self.hash_to_group(input)?;
    
    // Recompute challenge to verify Fiat-Shamir
    let expected_l = self.generate_fiat_shamir_prime(&x, &y, proof.iterations)?;
    if l != expected_l {
        debug_log!("Challenge prime mismatch");
        return Ok(false);
    }
    
    // Add debugging here
    debug_log!("=== VDF Verification Debug ===");
    debug_log!("iterations: {}", proof.iterations);
    debug_log!("x (first 32 chars): {}...", x.to_str_radix(16).chars().take(32).collect::<String>());
    debug_log!("y (first 32 chars): {}...", y.to_str_radix(16).chars().take(32).collect::<String>());
    debug_log!("l: {}", l);
    debug_log!("r: {}", r);
    debug_log!("pi (first 32 chars): {}...", pi.to_str_radix(16).chars().take(32).collect::<String>());
    
    // Verify: y ≡ π^l * x^r (mod N)
    let pi_l = pi.modpow(&l, &self.modulus);
    let x_r = x.modpow(&r, &self.modulus);
    let right_side = (pi_l.clone() * x_r.clone()) % &self.modulus;
    
    debug_log!("pi^l mod N (first 32 chars): {}...", pi_l.to_str_radix(16).chars().take(32).collect::<String>());
    debug_log!("x^r mod N (first 32 chars): {}...", x_r.to_str_radix(16).chars().take(32).collect::<String>());
    debug_log!("right_side (first 32 chars): {}...", right_side.to_str_radix(16).chars().take(32).collect::<String>());
    debug_log!("y == right_side? {}", y == right_side);
    
    // Let's also verify the remainder calculation
    let two = BigUint::from(2u32);
    let computed_r = two.modpow(&BigUint::from(proof.iterations), &l);
    debug_log!("Recomputed r: {}", computed_r);
    debug_log!("r matches? {}", r == computed_r);
    
    Ok(y == right_side)
}
    
    /// Miller-Rabin primality test
     fn is_probable_prime(&self, n: &BigUint, k: usize) -> bool {
        if n <= &BigUint::one() {
            return false;
        }
        
        if n == &BigUint::from(2u32) || n == &BigUint::from(3u32) {
            return true;
        }
        
        if n.is_even() {
            return false;
        }
        
        // Write n-1 as 2^r * d
        let one = BigUint::one();
        let two = BigUint::from(2u32);
        let n_minus_1 = n - &one;
        
        let mut r = 0;
        let mut d = n_minus_1.clone();
        
        while d.is_even() {
            d >>= 1;
            r += 1;
        }
        
        // Witness loop with deterministic witnesses for small n
        let witnesses: Vec<BigUint> = if n < &BigUint::from(3317044064679887385961981u128) {
            vec![2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
                .into_iter()
                .map(|w| BigUint::from(w as u32))
                .collect()
        } else {
            // Random witnesses for large n
            let mut rng = thread_rng();
            (0..k)
                .map(|_| rng.gen_biguint_range(&two, &(n - &two)))
                .collect()
        };
        
        'witness: for a in witnesses {
            if a >= *n {
                continue;
            }
            
            let mut x = a.modpow(&d, n);  // n is already &BigUint
            
            if x == one || x == n_minus_1 {
                continue 'witness;
            }
            
            for _ in 0..r - 1 {
                x = x.modpow(&two, n);
                if x == n_minus_1 {
                    continue 'witness;
                }
            }
            
            return false;
        }
        
        true
    }
    
    /// Create a VDF computer with a custom modulus (hex string) - TEST ONLY
    /// This bypasses security validations and should only be used for testing
    #[cfg(test)]
    pub fn with_modulus_unchecked(modulus_hex: &str) -> Result<VDFComputer, JsValue> {
        let modulus = BigUint::parse_bytes(modulus_hex.as_bytes(), 16)
            .ok_or_else(|| JsValue::from_str("Invalid modulus format"))?;
        
        // For tests, we allow any odd modulus
        if modulus.is_even() {
            return Err(JsValue::from_str("Modulus must be odd"));
        }
        
        // Precompute Montgomery parameters (simplified for this example)
        let montgomery_r = BigUint::one() << modulus.bits();
        let montgomery_r_inv = montgomery_r.clone();
        
        Ok(VDFComputer {
            modulus,
            montgomery_r,
            montgomery_r_inv,
        })
    }
    
}

/// Helper function to decode base64 to BigUint
fn base64_to_biguint(b64: &str) -> Result<BigUint, String> {
    let bytes = general_purpose::STANDARD
        .decode(b64)
        .map_err(|e| format!("Base64 decode error: {}", e))?;
    
    if bytes.is_empty() {
        return Err("Empty bytes".to_string());
    }
    
    Ok(BigUint::from_bytes_be(&bytes))
}

/// Benchmark function to calibrate iterations per second
#[wasm_bindgen]
pub fn benchmark_vdf(duration_ms: u32) -> Result<f64, JsValue> {
    let computer = VDFComputer::new();
    let test_input = "benchmark_test";
    
    let start = js_sys::Date::now();
    let mut iterations = 0u64;
    
    while js_sys::Date::now() - start < duration_ms as f64 {
        iterations += 1000;
        let _ = computer.compute_proof(test_input, iterations, None)?;
        
        if iterations > 1_000_000 {
            break;
        }
    }
    
    let elapsed_seconds = (js_sys::Date::now() - start) / 1000.0;
    Ok(iterations as f64 / elapsed_seconds)
}

/// Export version information
#[wasm_bindgen]
pub fn get_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

// ===================================================================================
//                                VDF WASM TEST SUITE
// ===================================================================================
// To run these tests, use the command: `wasm-pack test --headless --firefox`
// (or --chrome, --safari)
//
// These tests validate the VDF implementation in a real WASM environment.
// ===================================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    // Configure wasm-bindgen-test to run in a browser environment
    wasm_bindgen_test_configure!(run_in_browser);


/// Real 512-bit RSA modulus generated with OpenSSL
const TEST_MODULUS_HEX: &str = "bc975c587f80c63fc038828ed7416a2c0cf209e434494b77096086f47cbafff224d6c853998f3cfb8a8fd1c847b06666561e8ef5adfe5b3e11c09ac7324c4119";

    /// Creates a VDF computer with the default RSA-2048 modulus.
    fn setup_default_computer() -> VDFComputer {
        VDFComputer::new()
    }

/// Creates a VDF computer with a small, fast modulus for testing.
fn setup_test_computer() -> VDFComputer {
    VDFComputer::with_modulus_unchecked(TEST_MODULUS_HEX).unwrap()
}

    #[wasm_bindgen_test]
    fn test_vdf_proof_generation_and_verification_happy_path() {
        let computer = setup_default_computer();
        let input = "hello world";
        let iterations = MIN_ITERATIONS; // Use minimum iterations for speed

        let proof = computer.compute_proof(input, iterations, None).unwrap();
        let is_valid = computer.verify_proof(input, &proof).unwrap();

        assert!(is_valid, "VDF proof should be valid for a correct computation");
    }

#[wasm_bindgen_test]
fn test_with_custom_modulus() {
    let computer = setup_test_computer();
    let input = "custom modulus test";
    let iterations = MIN_ITERATIONS;

    let proof = computer.compute_proof(input, iterations, None).unwrap();
    let is_valid = computer.verify_proof(input, &proof).unwrap();

    assert!(is_valid, "VDF should work with a custom modulus");
    assert_eq!(computer.modulus.bits(), 512, "Test modulus should be 512 bits");
}

    #[wasm_bindgen_test]
    fn test_proof_verification_fails_with_wrong_input() {
        let computer = setup_default_computer();
        let original_input = "correct input";
        let wrong_input = "wrong input";
        let iterations = MIN_ITERATIONS;

        let proof = computer.compute_proof(original_input, iterations, None).unwrap();
        let is_valid = computer.verify_proof(wrong_input, &proof).unwrap();

        assert!(!is_valid, "Verification should fail if the input is incorrect");
    }

    #[wasm_bindgen_test]
    fn test_proof_verification_fails_with_tampered_proof() {
        let computer = setup_default_computer();
        let input = "tamper-proof test";
        let iterations = MIN_ITERATIONS;

        let mut proof = computer.compute_proof(input, iterations, None).unwrap();
        
        // Tamper with the 'y' value
        let mut y_bytes = general_purpose::STANDARD.decode(&proof.y).unwrap();
        y_bytes[0] ^= 0xff; // Flip some bits
        proof.y = general_purpose::STANDARD.encode(&y_bytes);

        let is_valid = computer.verify_proof(input, &proof).unwrap();
        assert!(!is_valid, "Verification should fail if 'y' is tampered");
    }

    #[wasm_bindgen_test]
    fn test_iteration_bounds() {
        let computer = setup_default_computer();
        let input = "iteration bounds test";

        // Test below minimum
        let result_min = computer.compute_proof(input, MIN_ITERATIONS - 1, None);
        assert!(result_min.is_err(), "Should fail with iterations below minimum");

        // Test above maximum
        let result_max = computer.compute_proof(input, MAX_ITERATIONS + 1, None);
        assert!(result_max.is_err(), "Should fail with iterations above maximum");
    }

    #[wasm_bindgen_test]
    fn test_empty_input_fails() {
        let computer = setup_default_computer();
        let result = computer.compute_proof("", MIN_ITERATIONS, None);
        assert!(result.is_err(), "Computation should fail for empty input");
    }

    #[wasm_bindgen_test]
    fn test_proof_serialization_deserialization() {
        let computer = setup_default_computer();
        let input = "json test";
        let iterations = MIN_ITERATIONS;

        let original_proof = computer.compute_proof(input, iterations, None).unwrap();
        let json_proof = original_proof.to_json().unwrap();
        let deserialized_proof = VDFProof::from_json(&json_proof).unwrap();

        assert_eq!(original_proof.y, deserialized_proof.y);
        assert_eq!(original_proof.pi, deserialized_proof.pi);
        assert_eq!(original_proof.l, deserialized_proof.l);
        assert_eq!(original_proof.r, deserialized_proof.r);
        assert_eq!(original_proof.iterations, deserialized_proof.iterations);
        
        // Verify the deserialized proof
        let is_valid = computer.verify_proof(input, &deserialized_proof).unwrap();
        assert!(is_valid, "Deserialized proof should be valid");
    }

    #[wasm_bindgen_test]
    fn test_hash_to_group_is_deterministic() {
        let computer = setup_default_computer();
        let input = "deterministic hash";

        let hash1 = computer.hash_to_group(input).unwrap();
        let hash2 = computer.hash_to_group(input).unwrap();
        
        assert_eq!(hash1, hash2, "hash_to_group should produce the same output for the same input");
    }
    
    #[wasm_bindgen_test]
    fn test_fiat_shamir_prime_is_deterministic() {
        let computer = setup_default_computer();
        let input = "deterministic prime";
        let iterations = MIN_ITERATIONS;
        
        let x = computer.hash_to_group(input).unwrap();
        let y = computer.compute_vdf_output(&x, iterations, &None).unwrap();

        let l1 = computer.generate_fiat_shamir_prime(&x, &y, iterations).unwrap();
        let l2 = computer.generate_fiat_shamir_prime(&x, &y, iterations).unwrap();

        assert_eq!(l1, l2, "Fiat-Shamir prime generation should be deterministic");
    }
    
    #[wasm_bindgen_test]
    async fn test_progress_callback() {
        use std::cell::RefCell;
        use std::rc::Rc;

        let computer = setup_default_computer();
        let input = "progress callback test";
        let iterations = MIN_ITERATIONS + PROGRESS_INTERVAL; // Ensure it fires at least once

        let progress_log = Rc::new(RefCell::new(Vec::<f64>::new()));
        let progress_log_clone = progress_log.clone();

        let on_progress_callback = Closure::wrap(Box::new(move |p: f64| {
            progress_log_clone.borrow_mut().push(p);
        }) as Box<dyn Fn(f64)>);

        let _ = computer.compute_proof(
            input,
            iterations,
            Some(on_progress_callback.as_ref().clone().into()),
        );

        let log = progress_log.borrow();
        assert!(!log.is_empty(), "Progress callback should have been called");
        assert!(log[0] > 0.0, "First progress value should be greater than 0");
        assert_eq!(*log.last().unwrap(), 100.0, "Last progress value should be 100");
    }
}

