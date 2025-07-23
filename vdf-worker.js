// Import the WASM initializer and the VDFComputer class
import init, { VDFComputer } from './wasm/vdf_wasm.js';

// This variable will hold the initialized WASM module's exports
let wasm;

// Listen for messages from the main thread
self.onmessage = async (event) => {
  const { command, input, iterations } = event.data;

  if (command === 'start') {
    // Initialize WASM if it hasn't been already
    if (!wasm) {
      console.log('Worker: Initializing WASM...');
      wasm = await init();
    }
    
    console.log(`Worker: Starting VDF computation with ${iterations} iterations...`);
    
    // Create the VDF computer
    const computer = new VDFComputer();
    
    // Define the progress callback function
    const onProgress = (progress) => {
      // Send progress updates back to the main thread
      self.postMessage({ status: 'progress', progress: progress });
    };

try {
  // Compute the proof. This will block the worker, but not the main UI.
  const proof = computer.compute_proof(input, BigInt(iterations), onProgress);
  
  // Extract the values from the proof object - they're properties, not methods
  const proofData = {
    y: proof.y,      // No parentheses - these are properties
    pi: proof.pi,
    l: proof.l,
    r: proof.r,
    iterations: proof.iterations
  };
  
  // Send the extracted proof data back to the main thread
  self.postMessage({ status: 'complete', proof: proofData });

} catch (e) {
  console.error('Worker: VDF computation failed:', e);
  self.postMessage({ status: 'error', error: e.toString() });
}
  }
};
