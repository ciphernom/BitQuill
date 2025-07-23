import init, { VDFComputer, VDFProof } from './wasm/vdf_wasm.js';

// --- Helper function for SHA-256 ---
async function sha256(message) {
  const msgBuffer = new TextEncoder().encode(message);
  const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// --- Enhanced Proof Chain Structure ---
class EpochProof {
  constructor(epochNumber, previousHash, deltas, vdfProof, iterations, epochDuration) {
    this.epochNumber = epochNumber;
    this.previousHash = previousHash;
    this.deltas = deltas;
    
    // Fix: Handle both plain objects and objects with getters
    this.vdfProof = {
      y: typeof vdfProof.y === 'function' ? vdfProof.y() : vdfProof.y,
      pi: typeof vdfProof.pi === 'function' ? vdfProof.pi() : vdfProof.pi,
      l: typeof vdfProof.l === 'function' ? vdfProof.l() : vdfProof.l,
      r: typeof vdfProof.r === 'function' ? vdfProof.r() : vdfProof.r
    };
    
    this.iterations = iterations;
    this.epochDuration = epochDuration;
    this.timestamp = new Date().toISOString();
    this.hash = null; // Will be computed
  }

  async computeHash() {
    const content = {
      epochNumber: this.epochNumber,
      previousHash: this.previousHash,
      deltas: this.deltas,
      vdfY: this.vdfProof.y,
      iterations: this.iterations
    };
    this.hash = await sha256(JSON.stringify(content));
    return this.hash;
  }
}

// --- Modern UI Functions ---
function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.textContent = message;
  
  container.appendChild(toast);
  
  // Trigger animation
  setTimeout(() => toast.classList.add('show'), 10);
  
  // Remove after 5 seconds
  setTimeout(() => {
    toast.classList.remove('show');
    setTimeout(() => container.removeChild(toast), 300);
  }, 5000);
}

function updateWordCount(quill) {
  const text = quill.getText();
  const words = text.trim().split(/\s+/).filter(word => word.length > 0).length;
  const chars = text.length - 1; // Minus trailing newline
  
  document.getElementById('word-count').textContent = `${words} words`;
  document.getElementById('char-count').textContent = `${chars} characters`;
}

function showVerificationModal() {
  document.getElementById('modal-backdrop').classList.add('show');
  document.getElementById('verification-modal').classList.add('show');
  document.querySelector('.verification-progress').style.display = 'block';
  document.getElementById('verification-results').style.display = 'none';
}

function hideVerificationModal() {
  document.getElementById('modal-backdrop').classList.remove('show');
  document.getElementById('verification-modal').classList.remove('show');
}

function updateVerificationProgress(percent, status) {
  const circle = document.getElementById('progress-circle');
  const text = document.getElementById('progress-text');
  const statusEl = document.getElementById('verification-status');
  
  const circumference = 2 * Math.PI * 54;
  const offset = circumference - (percent / 100) * circumference;
  
  circle.style.strokeDashoffset = offset;
  text.textContent = `${Math.round(percent)}%`;
  statusEl.textContent = status;
}

function showVerificationResults(results, documentData, showLoadButton = true) {
  document.querySelector('.verification-progress').style.display = 'none';
  const resultsEl = document.getElementById('verification-results');
  resultsEl.style.display = 'block';

  const authorshipHTML = showAuthorshipAnalysis(documentData.proofChain);

  if (results.valid) {
    const loadButtonHTML = showLoadButton ? 
      `<button class="btn btn-primary" id="load-verified-doc-btn" style="margin-top: 16px;">Load Document</button>` : '';

    resultsEl.innerHTML = `
      <div style="color: var(--primary-color); margin-bottom: 16px; font-size: 18px;">
        ✓ Document verified successfully
      </div>
      <div style="margin-bottom: 8px;">Verified Epochs: ${results.verifiedEpochs}/${results.totalEpochs}</div>
      <div style="margin-bottom: 8px;">Total Duration: ${(documentData.metadata.totalDuration / 60).toFixed(1)} minutes</div>
      <div style="margin-bottom: 16px;">Final Hash: ${documentData.metadata.latestHash.substring(0, 16)}...</div>
      ${loadButtonHTML}
      ${authorshipHTML} `;

    if (showLoadButton) {
      document.getElementById('load-verified-doc-btn').addEventListener('click', loadVerifiedDocument);
    }
  } else {
    resultsEl.innerHTML = `
      <div style="color: #ff4444; margin-bottom: 16px; font-size: 18px;">
        ✗ Verification failed
      </div>
      <div style="color: #ff4444; margin-bottom: 16px;">${results.errors.join('<br>')}</div>
      ${authorshipHTML} `;
  }
}

function renderProofChain(chain, mode = 'live', verificationErrors = []) {
  const proofDisplay = document.getElementById('proof-display');
  proofDisplay.innerHTML = ''; 

  const findErrorForEpoch = (index) => {
    return verificationErrors.find(e => e.includes(`at epoch ${index}`) || e.includes(`Epoch ${index}:`)) || null;
  };

  chain.forEach((epoch, index) => {
    let statusIcon, statusColor, statusTitle;

    if (mode === 'verified') {
      const error = findErrorForEpoch(index);
      const isValid = !error;
      statusIcon = isValid ? '✓' : '✗';
      statusColor = isValid ? 'var(--primary-color)' : '#ff4444';
      statusTitle = isValid ? 'Verified' : `Error: ${error}`;
    } else { 
      statusIcon = '●';
      statusColor = 'var(--text-secondary)';
      statusTitle = 'Epoch created';
    }

    const label = epoch.epochNumber === 0 ? 'GENESIS' : `EPOCH #${epoch.epochNumber}`;
    const hash = (epoch.hash || '').substring(0, 16) + '...';
    const duration = (epoch.epochDuration || 0).toFixed(1) + 's';
    const durationInfo = epoch.epochNumber > 0 ? `<span style="color: var(--text-secondary); font-size: 11px; margin-left: 1em;">(${duration})</span>` : '';

    const entryHTML = `
      <div title="${statusTitle}" style="padding: 4px 2px; border-bottom: 1px solid var(--bg-tertiary);">
        <span style="color: ${statusColor}; font-weight: bold; margin-right: 8px;">${statusIcon}</span>
        <span>${label}: ${hash}</span>
        ${durationInfo}
      </div>
    `;
    proofDisplay.innerHTML += entryHTML;
  });

  if (mode === 'live' && proofDisplay.lastElementChild) {
    proofDisplay.lastElementChild.title = 'Current epoch';
  }

  proofDisplay.scrollTop = proofDisplay.scrollHeight;
}

// --- Authorship Analysis Functions ---
function calculateBurstVarianceRatio(epochDeltas) {
  const charCounts = epochDeltas.map(epoch => 
    epoch.deltas.reduce((sum, delta) => sum + (delta.insert?.length || 0), 0)
  );
  if (charCounts.length === 0) return 0;
  const mean = charCounts.reduce((a, b) => a + b, 0) / charCounts.length;
  const variance = charCounts.reduce((sum, count) => 
    sum + Math.pow(count - mean, 2), 0) / charCounts.length;
  return variance / (mean + 1);
}

function analyzePausePatterns(epochDeltas) {
  let pauseRuns = [];
  let currentRun = 0;
  epochDeltas.forEach(epoch => {
    if (epoch.deltas.length === 0) {
      currentRun++;
    } else if (currentRun > 0) {
      pauseRuns.push(currentRun);
      currentRun = 0;
    }
  });
  if (pauseRuns.length === 0) return { pauseRatio: 0, logNormalityScore: 0 };
  const logPauses = pauseRuns.map(p => Math.log(p + 1));
  const meanLog = logPauses.reduce((a, b) => a + b, 0) / logPauses.length;
  const stdLog = Math.sqrt(logPauses.reduce((sum, log) => 
    sum + Math.pow(log - meanLog, 2), 0) / logPauses.length);
  return { 
    pauseRatio: pauseRuns.length / epochDeltas.length,
    logNormalityScore: stdLog / (meanLog + 0.01)
  };
}

function calculateEditEntropy(epochDeltas) {
  const editTypes = epochDeltas.map(epoch => {
    const inserts = epoch.deltas.filter(d => d.insert).length;
    const deletes = epoch.deltas.filter(d => d.delete).length;
    if (inserts === 0 && deletes === 0) return 'pause';
    if (deletes > inserts) return 'revision';
    if (inserts > 10) return 'burst';
    return 'steady';
  });
  const typeCounts = {};
  editTypes.forEach(type => typeCounts[type] = (typeCounts[type] || 0) + 1);
  let entropy = 0;
  const total = editTypes.length;
  if (total === 0) return 0;
  Object.values(typeCounts).forEach(count => {
    const p = count / total;
    if (p > 0) entropy -= p * Math.log2(p);
  });
  return entropy;
}

function estimateKeystrokeDynamics(epochDeltas) {
  const productiveEpochs = epochDeltas.filter(e => e.deltas.length > 0);
  if (productiveEpochs.length === 0) return { meanCPS: 0, maxCPS: 0, speedRatio: 0, bimodalScore: 0 };
  const speeds = productiveEpochs.map(epoch => {
    const chars = epoch.deltas.reduce((sum, d) => sum + (d.insert?.length || 0), 0);
    return chars / 10;
  });
  const meanSpeed = speeds.reduce((a, b) => a + b, 0) / speeds.length;
  const maxSpeed = Math.max(...speeds);
  return {
    meanCPS: meanSpeed,
    maxCPS: maxSpeed,
    speedRatio: maxSpeed / (meanSpeed + 0.1),
    bimodalScore: detectBimodality(speeds)
  };
}

function detectBimodality(data) {
  if (data.length < 2) return 0;
  data.sort((a, b) => a - b);
  const n = data.length;
  let maxDiff = 0;
  for (let i = 0; i < n - 1; i++) {
    const empirical = (i + 1) / n;
    const uniform = data[i] / data[n - 1];
    maxDiff = Math.max(maxDiff, Math.abs(empirical - uniform));
  }
  return maxDiff;
}

function calculateHumanAuthorshipScore(proofChain) {
  const epochDeltas = proofChain.slice(1).map(proof => {
    let flatOps = [];
    if (proof.deltas) {
      proof.deltas.forEach(deltaObj => {
        if (deltaObj && deltaObj.ops) {
          flatOps = flatOps.concat(deltaObj.ops);
        }
      });
    }
    return {
      deltas: flatOps,
      duration: proof.epochDuration
    };
  });

  if (epochDeltas.length === 0) return { humanScore: 0, details: {}, metrics: {} };

  // --- Per-Epoch Anomaly Detection ---
  for (const epoch of epochDeltas) {
    if (!epoch.deltas) continue;
    
    // *** FIX: Count the number of operations, not the sum of characters. ***
    // A large delete is a single operation.
    const totalOpsInEpoch = epoch.deltas.length;

    if (totalOpsInEpoch > 200) {
      return { 
        humanScore: 0.05,
        details: { anomalyReason: "Detected an impossibly fast 'edit storm' in a single epoch." },
        metrics: {}
      };
    }
    // This check for large pastes is still valid.
    for (const op of epoch.deltas) {
      if (op.insert && op.insert.length > 100) {
        return {
          humanScore: 0.1,
          details: { anomalyReason: "Detected a large paste action in a single epoch." },
          metrics: {}
        };
      }
    }
  }
  // --- End of Anomaly Detection ---

  const bvr = calculateBurstVarianceRatio(epochDeltas);
  const pauseAnalysis = analyzePausePatterns(epochDeltas);
  const entropy = calculateEditEntropy(epochDeltas);
  const dynamics = estimateKeystrokeDynamics(epochDeltas);
  
  function sigmoid(x) { return 1 / (1 + Math.exp(-x)); }
  function gaussian(x, mean, std) { return Math.exp(-0.5 * Math.pow((x - mean) / std, 2)); }
  
  const scores = {
    burstScore: sigmoid((bvr - 0.5) * 2),
    pauseScore: sigmoid((pauseAnalysis.pauseRatio - 0.05) * 15),
    entropyScore: gaussian(entropy, 1.0, 0.7),
    speedScore: gaussian(dynamics.meanCPS, 5, 3),
    bimodalScore: sigmoid((dynamics.bimodalScore - 0.05) * 20)
  };
  
  const weights = { burstScore: 0.35, pauseScore: 0.15, entropyScore: 0.20, speedScore: 0.20, bimodalScore: 0.10 };
  const humanScore = Object.entries(scores).reduce((sum, [key, score]) => sum + score * weights[key], 0);
  
  return { humanScore, details: scores, metrics: { bvr, pauseAnalysis, entropy, dynamics } };
}

function showAuthorshipAnalysis(proofChain) {
  const analysis = calculateHumanAuthorshipScore(proofChain);
  const percentage = Math.round(analysis.humanScore * 100);
  
  return `
    <div class="authorship-analysis">
      <h3>Authorship Analysis</h3>
      <div class="human-score">${percentage}% Human Characteristics</div>
      <div class="details">
        <div>Typing Rhythm: ${Math.round((analysis.details.burstScore || 0) * 100)}%</div>
        <div>Pause Patterns: ${Math.round((analysis.details.pauseScore || 0) * 100)}%</div>
        <div>Edit Complexity: ${Math.round((analysis.details.entropyScore || 0) * 100)}%</div>
        <div>Speed Profile: ${Math.round((analysis.details.speedScore || 0) * 100)}%</div>
      </div>
    </div>
  `;
}

function updateUITimers(elapsed, targetSeconds, progress) {
  const timeEl = document.getElementById('timer-countdown');
  if (timeEl) {
    const remaining = Math.max(0, targetSeconds - elapsed);
    timeEl.textContent = `${remaining.toFixed(1)}s`;
  }
  
  const progressBar = document.getElementById('vdf-progress-bar');
  if (progressBar) {
    progressBar.style.transform = `scaleX(${progress / 100})`;
  }
}

// --- Save/Load Functions ---
async function saveDocument(quill, proofChain, currentEpochDeltas) {
  const documentData = {
    version: "2.0",
    timestamp: new Date().toISOString(),
    content: {
      html: quill.root.innerHTML,
      delta: quill.getContents()
    },
    proofChain: proofChain,
    currentEpochDeltas: currentEpochDeltas,
    metadata: {
      epochCount: proofChain.length,
      genesisHash: proofChain[0].hash,
      latestHash: proofChain[proofChain.length - 1].hash,
      totalDuration: proofChain.reduce((sum, epoch) => sum + (epoch.epochDuration || 0), 0),
      documentHash: null
    }
  };

  const dataToHash = JSON.parse(JSON.stringify(documentData));
  delete dataToHash.metadata.documentHash;
  documentData.metadata.documentHash = await sha256(JSON.stringify(dataToHash));

  const blob = new Blob([JSON.stringify(documentData, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `bitquill-doc-${Date.now()}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

async function loadDocument(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = (e) => {
      try {
        const data = JSON.parse(e.target.result);
        if (!data.proofChain || !data.content || !data.content.delta) {
          throw new Error('Invalid or corrupted document structure.');
        }
        resolve(data);
      } catch (err) {
        reject(new Error('Invalid document format. ' + err.message));
      }
    };
    reader.onerror = reject;
    reader.readAsText(file);
  });
}

async function verifyDocument(documentData, updateProgress) {
  const results = { valid: true, errors: [], verifiedEpochs: 0, totalEpochs: 0 };
  try {
    await init();
    const computer = new VDFComputer();
    const epochs = documentData.proofChain;
    results.totalEpochs = epochs.length - 1;

    if (documentData.metadata) {
      if (documentData.metadata.epochCount !== epochs.length) {
        results.errors.push("Metadata mismatch: epochCount does not match the actual number of epochs.");
        results.valid = false;
      }
      if (documentData.metadata.latestHash !== epochs[epochs.length - 1].hash) {
        results.errors.push("Metadata mismatch: latestHash does not match the final epoch hash.");
        results.valid = false;
      }
      if (documentData.metadata.documentHash) {
        const dataToHash = JSON.parse(JSON.stringify(documentData));
        delete dataToHash.metadata.documentHash;
        const expectedHash = await sha256(JSON.stringify(dataToHash));
        if (documentData.metadata.documentHash !== expectedHash) {
          results.errors.push("Document checksum failed. The file's content may have been altered.");
          results.valid = false;
        }
      } else {
        results.errors.push("Missing document checksum. Cannot verify overall file integrity.");
        results.valid = false;
      }
    }

    if (!epochs[0] || epochs[0].hash !== "0000000000000000000000000000000000000000000000000000000000000000") {
      results.errors.push("Invalid genesis hash");
      results.valid = false;
      return results;
    }

    for (let i = 1; i < epochs.length; i++) {
      const epoch = epochs[i];
      if (updateProgress) {
        updateProgress((i / (epochs.length - 1)) * 100, `Verifying epoch ${i}/${epochs.length - 1}...`);
      }
      if (epoch.previousHash !== epochs[i - 1].hash) {
        results.errors.push(`Epoch ${i}: Broken chain.`);
        results.valid = false;
        continue;
      }
      try {
        if (!epoch.vdfProof || !epoch.vdfProof.y) throw new Error("Missing VDF proof data.");
        const vdfProof = new VDFProof(epoch.vdfProof.y, epoch.vdfProof.pi, epoch.vdfProof.l, epoch.vdfProof.r, BigInt(epoch.iterations));
        const isValid = await computer.verify_proof(epoch.previousHash, vdfProof);
        if (!isValid) throw new Error("Invalid VDF proof.");
        else results.verifiedEpochs++;
      } catch (e) {
        results.errors.push(`Epoch ${i}: VDF verification error: ${e.message}`);
        results.valid = false;
      }
      const content = { epochNumber: epoch.epochNumber, previousHash: epoch.previousHash, deltas: epoch.deltas, vdfY: epoch.vdfProof.y, iterations: epoch.iterations };
      const expectedHash = await sha256(JSON.stringify(content));
      if (epoch.hash !== expectedHash) {
        results.errors.push(`Epoch ${i}: Hash mismatch.`);
        results.valid = false;
      }
    }
    results.valid = results.errors.length === 0;
  } catch (error) {
    results.valid = false;
    results.errors.push(error.message);
  }
  return results;
}

let verifiedDocumentData = null;

function loadVerifiedDocument() {
  if (verifiedDocumentData && window.quillInstance) {
    window.quillInstance.setContents(verifiedDocumentData.content.delta);
    showToast('Document loaded successfully', 'success');
    hideVerificationModal();
  }
}

// Initialize modern UI
function initModernUI(quill, getProofChain, setProofChain, getCurrentEpochDeltas, restartVdfProcess) {
  window.quillInstance = quill;
  
  quill.on('text-change', () => updateWordCount(quill));
  updateWordCount(quill);
  
  document.getElementById('save-btn').onclick = () => {
    saveDocument(quill, getProofChain(), getCurrentEpochDeltas());
    showToast('Document saved successfully', 'success');
    document.getElementById('last-saved').textContent = `Saved ${new Date().toLocaleTimeString()}`;
  };
  
  document.getElementById('load-btn').onclick = () => {
    document.getElementById('file-input').click();
  };

  document.getElementById('verify-live-btn').onclick = async () => {
    showToast('Verifying current document...', 'info');
    const liveProofChain = getProofChain();
    showVerificationModal();
    updateVerificationProgress(0, 'Starting verification...');
    const verification = await verifyDocument({ proofChain: liveProofChain }, updateVerificationProgress);
    const fakeDocData = {
      proofChain: liveProofChain,
      metadata: {
        latestHash: liveProofChain.length > 0 ? liveProofChain[liveProofChain.length - 1].hash : 'N/A',
        totalDuration: liveProofChain.reduce((sum, epoch) => sum + (epoch.epochDuration || 0), 0),
      }
    };
    showVerificationResults(verification, fakeDocData, false);
    renderProofChain(liveProofChain, 'verified', verification.errors);
  };

  // File input handler with instant verification and VDF restart
  document.getElementById('file-input').onchange = async (e) => {
    if (!e.target.files[0]) return;
    const file = e.target.files[0];
    
    showToast('Verifying and loading document...', 'info');

    try {
      const data = await loadDocument(file);
      const tempEditor = document.createElement('div');
      const tempQuill = new Quill(tempEditor);
      
      data.proofChain.slice(1).forEach(epoch => {
        if (epoch.deltas) {
          epoch.deltas.forEach(delta => tempQuill.updateContents(delta));
        }
      });

      const reconstructedDelta = tempQuill.getContents();
      const savedDelta = data.content.delta;

      if (JSON.stringify(reconstructedDelta) !== JSON.stringify(savedDelta)) {
        throw new Error("Content Mismatch: The document's history does not match its final state.");
      }

      quill.setContents(savedDelta);
      setProofChain(data.proofChain);
      
      renderProofChain(getProofChain());
      const finalEpoch = getProofChain()[getProofChain().length - 1];
      document.getElementById('epoch-number').textContent = finalEpoch.epochNumber;
      
      restartVdfProcess();
      
      showToast('Document loaded and verified. VDF timer restarted.', 'success');

    } catch (error) {
      showToast(`Error loading document: ${error.message}`, 'error');
      console.error("File loading error:", error);
    }
    e.target.value = '';
  };
  
  document.getElementById('modal-close').onclick = hideVerificationModal;
  document.getElementById('modal-backdrop').onclick = hideVerificationModal;
  
  document.getElementById('epoch-indicator').onclick = () => {
    document.getElementById('proof-panel').classList.toggle('show');
  };
  
  document.getElementById('proof-panel-close').onclick = () => {
    document.getElementById('proof-panel').classList.remove('show');
  };
}

// Main run function
async function run() {
  await init();
  
  const proofDisplay = document.getElementById('proof-display');
  proofDisplay.innerHTML = '<div style="color: var(--text-secondary);">Calibrating VDF for your system...</div>';

  const computer = new VDFComputer();
  const targetSeconds = 10;
  console.log('Starting VDF calibration...');
  const startCalibration = performance.now();
  const baselineIterations = 10000;
  const baselineStart = performance.now();
  await computer.compute_proof("calibration", BigInt(baselineIterations), null);
  const baselineTime = (performance.now() - baselineStart) / 1000;
  const iterationsPerSecond = baselineIterations / baselineTime;
  let calibratedIterations = Math.floor(iterationsPerSecond * targetSeconds);
  console.log(`Calibrated to ${calibratedIterations} iterations for ${targetSeconds} seconds`);

  // --- State Variables ---
  let epochDeltas = [];
  let proofChain = [
    { 
      epochNumber: 0, 
      hash: "0000000000000000000000000000000000000000000000000000000000000000",
      timestamp: new Date().toISOString()
    }
  ];
  let isVDFRunning = false;
  let epochStartTime = Date.now();
  let currentProgress = 0;
  let vdfWorker;

  const setProofChain = (newChain) => {
    proofChain = newChain;
  };
  
  const quill = new Quill('#editor', {
    theme: 'snow',
    placeholder: 'Start typing to create your tamper-evident document...'
  });
  
  quill.on('text-change', (delta, oldDelta, source) => {
    if (source === 'user') epochDeltas.push(delta);
  });

  function startNextEpoch() {
    console.log('Starting next VDF epoch...');
    epochStartTime = Date.now();
    isVDFRunning = true;
    currentProgress = 0;
    
    const previousEpoch = proofChain[proofChain.length - 1];
    vdfWorker.postMessage({
      command: 'start',
      input: previousEpoch.hash,
      iterations: calibratedIterations
    });
  }

  function restartVdfProcess() {
    if (vdfWorker) {
      vdfWorker.terminate();
      console.log("Terminated existing VDF worker.");
    }
    
    epochDeltas = [];

    vdfWorker = new Worker(new URL('./vdf-worker.js', import.meta.url));
    console.log("New VDF worker created.");

    vdfWorker.onmessage = async (event) => {
      const { status, proof, progress, error } = event.data;

      if (status === 'progress') {
        currentProgress = progress;
        return;
      }

      if (status === 'error') {
        console.error('VDF Worker Error:', error);
        showToast('VDF computation error', 'error');
        isVDFRunning = false;
        currentProgress = 0;
        return;
      }

      if (status === 'complete') {
        const epochDuration = (Date.now() - epochStartTime) / 1000;
        console.log(`Worker finished. Epoch duration: ${epochDuration.toFixed(2)}s`);
        currentProgress = 0;
        
        if (epochDeltas.length > 0) {
          const previousEpoch = proofChain[proofChain.length - 1];
          const epochProof = new EpochProof(
            proofChain.length,
            previousEpoch.hash,
            epochDeltas,
            proof,
            calibratedIterations,
            epochDuration
          );
          
          await epochProof.computeHash();
          proofChain.push(epochProof);
          
          document.getElementById('epoch-number').textContent = epochProof.epochNumber;
          document.getElementById('epoch-indicator').classList.add('active');
          setTimeout(() => document.getElementById('epoch-indicator').classList.remove('active'), 1000);
          
          renderProofChain(proofChain);
          proofDisplay.scrollTop = proofDisplay.scrollHeight;
          epochDeltas = [];
        } else {
          console.log("Epoch End: No changes were made.");
        }
        
        if (Math.abs(epochDuration - targetSeconds) > targetSeconds * 0.2) {
          const adjustment = targetSeconds / epochDuration;
          const newIterations = Math.floor(calibratedIterations * adjustment);
          calibratedIterations = Math.floor((calibratedIterations + newIterations) / 2);
          console.log(`Adjusting iterations to ${calibratedIterations} for better timing`);
        }
        
        startNextEpoch();
      }
    };
    
    startNextEpoch();
  }
  
  initModernUI(
    quill, 
    () => proofChain, 
    setProofChain,
    () => epochDeltas,
    restartVdfProcess
  );
  
  setInterval(() => {
    if (isVDFRunning) {
      const elapsed = (Date.now() - epochStartTime) / 1000;
      const estimatedProgress = Math.min(100, (elapsed / targetSeconds) * 100);
      const displayProgress = currentProgress > 0 ? currentProgress : estimatedProgress;
      updateUITimers(elapsed, targetSeconds, displayProgress);
    }
  }, 50);

  renderProofChain(proofChain); 
  showToast('VDF calibration complete', 'success');
  restartVdfProcess();
}

run();
