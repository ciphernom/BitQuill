import Quill from 'quill';
import 'quill/dist/quill.snow.css';
import qrcode from 'qrcode-generator';
import { jsPDF } from "jspdf";
import init, { VDFComputer, VDFProof } from './wasm/vdf_wasm.js';

// --- Helper function for SHA-256 ---
async function sha256(message) {
  const msgBuffer = new TextEncoder().encode(message);
  const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

//cryptographic helpers
const cryptoHelpers = {
  // Generates ECDSA (signing) and HKDF (encryption key derivation) keys
  async generateKeys() {
    const signingKeys = await crypto.subtle.generateKey(
      { name: 'ECDSA', namedCurve: 'P-384' },
      true, ['sign', 'verify']
    );

    // Generate random bytes as base key material for HKDF
    const baseKeyMaterial = crypto.getRandomValues(new Uint8Array(32));

    // Import as a NON-EXTRACTABLE HKDF base key
    const hkdfBaseKey = await crypto.subtle.importKey(
      'raw',
      baseKeyMaterial,
      { name: 'HKDF' },
      false, // FIX: Must be false for HKDF keys
      ['deriveKey']
    );

    const encryptionKey = await cryptoHelpers.deriveEncryptionKey(hkdfBaseKey);

    // Return the raw material separately so it can be stored
    return { signingKeys, hkdfBaseKey, encryptionKey, baseKeyMaterial };
  },

  // Exports a key to a storable format
  async exportKey(key) {
    return await crypto.subtle.exportKey('jwk', key);
  },

  // Imports a key from a stored format
  async importKey(jwk, type, usages) {
    const format = 'jwk';
    const algorithm = { name: type === 'ECDSA' ? 'ECDSA' : 'ECDH', namedCurve: 'P-384' };
    return await crypto.subtle.importKey(format, jwk, algorithm, true, usages);
  },

  // Derives a stable AES key for encryption from a private key
  async deriveEncryptionKey(hkdfBaseKey) {
    return await crypto.subtle.deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-384',
        salt: new TextEncoder().encode('bitquill-encryption-v1'),
        info: new TextEncoder().encode('aes-encryption-key')
      },
      hkdfBaseKey,
      { name: 'AES-GCM', length: 256 },
      true,
      ['encrypt', 'decrypt']
    );
  },

  // Encrypts data using AES-GCM
  async encrypt(data, key) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encodedData = new TextEncoder().encode(JSON.stringify(data));
    const encryptedContent = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      encodedData
    );
    return {
      iv: Array.from(iv),
      content: Array.from(new Uint8Array(encryptedContent))
    };
  },

  // Decrypts data using AES-GCM
  async decrypt(encryptedPayload, key) {
    const iv = new Uint8Array(encryptedPayload.iv);
    const data = new Uint8Array(encryptedPayload.content);
    const decryptedContent = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, data);
    return JSON.parse(new TextDecoder().decode(decryptedContent));
  },

  // Signs data using ECDSA
  async sign(hash, privateKey) {
    const hashBuffer = new TextEncoder().encode(hash);
    const signature = await crypto.subtle.sign(
      { name: 'ECDSA', hash: { name: 'SHA-384' } },
      privateKey,
      hashBuffer
    );
    return Array.from(new Uint8Array(signature));
  },

  // Verifies a signature
  async verify(hash, signature, publicKey) {
    const hashBuffer = new TextEncoder().encode(hash);
    const signatureBuffer = new Uint8Array(signature);
    return await crypto.subtle.verify(
      { name: 'ECDSA', hash: { name: 'SHA-384' } },
      publicKey,
      signatureBuffer,
      hashBuffer
    );
  }
};


// --- Enhanced Proof Chain Structure ---
class EpochProof {
  constructor(epochNumber, previousHash, deltas, vdfProof, iterations, epochDuration) {
    this.epochNumber = epochNumber;
    this.previousHash = previousHash;
    this.deltas = deltas;
    this.vdfProof = {
      y: typeof vdfProof.y === 'function' ? vdfProof.y() : vdfProof.y,
      pi: typeof vdfProof.pi === 'function' ? vdfProof.pi() : vdfProof.pi,
      l: typeof vdfProof.l === 'function' ? vdfProof.l() : vdfProof.l,
      r: typeof vdfProof.r === 'function' ? vdfProof.r() : vdfProof.r
    };
    this.iterations = iterations;
    this.epochDuration = epochDuration;
    this.timestamp = new Date().toISOString();
    this.hash = null;
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

// --- Local Storage Management ---
const LS_PREFIX = 'bitquill-doc-';
const LS_KEYS = 'bitquill-keys';

async function signAndSaveDocument() {
  if (!userKeys) {
    showToast("Please generate or load signing keys first.", "error");
    return;
  }
  let key = appState.currentDocumentKey || LS_PREFIX + Date.now();
  appState.currentDocumentKey = key;

  const docData = await buildDocumentData();
  // Sign the document hash
  const signature = await cryptoHelpers.sign(docData.metadata.documentHash, userKeys.signingKeys.privateKey);
  docData.metadata.signature = signature;
  docData.metadata.publicKey = await cryptoHelpers.exportKey(userKeys.signingKeys.publicKey);

  await saveToLocal(key, docData, userKeys.encryptionKey);
  appState.isDirty = false;
  appState.loadedMetadata = docData.metadata; // Update loaded metadata on save
  document.getElementById('last-saved').textContent = `Saved ${new Date().toLocaleTimeString()}`;
  showToast('Document signed and saved', 'success');
}

async function generateAndStoreKeys() {
  if (!confirm("This will overwrite existing keys. Are you sure?")) return;
  const keys = await cryptoHelpers.generateKeys();
  // userKeys holds the CryptoKey objects, not the raw material
  userKeys = { signingKeys: keys.signingKeys, hkdfBaseKey: keys.hkdfBaseKey, encryptionKey: keys.encryptionKey };

  // We can't export the key, so we use the raw material we generated
  const hkdfBase64 = btoa(String.fromCharCode(...new Uint8Array(keys.baseKeyMaterial)));

  localStorage.setItem(LS_KEYS, JSON.stringify({
    signing_private: await cryptoHelpers.exportKey(keys.signingKeys.privateKey),
    signing_public: await cryptoHelpers.exportKey(keys.signingKeys.publicKey),
    hkdf_base: hkdfBase64  // Store the raw material, not an exported key
  }));
  showToast("New signing keys generated and stored.", "success");
}

async function loadKeys() {
  const storedKeys = JSON.parse(localStorage.getItem(LS_KEYS));
  if (storedKeys) {
    const signingKeys = {
      privateKey: await cryptoHelpers.importKey(storedKeys.signing_private, 'ECDSA', ['sign']),
      publicKey: await cryptoHelpers.importKey(storedKeys.signing_public, 'ECDSA', ['verify']),
    };

    // Convert base64 back to raw bytes
    const hkdfRawKey = Uint8Array.from(atob(storedKeys.hkdf_base), c => c.charCodeAt(0));
    // Import the stored raw material as a NON-EXTRACTABLE key
    const hkdfBaseKey = await crypto.subtle.importKey(
      'raw',
      hkdfRawKey,
      { name: 'HKDF' },
      false, // FIX: Must be false here too
      ['deriveKey']
    );

    const encryptionKey = await cryptoHelpers.deriveEncryptionKey(hkdfBaseKey);
    userKeys = { signingKeys, hkdfBaseKey, encryptionKey };
    showToast("Signing keys loaded from browser.", "info");
  } else {
    showToast("No signing keys found. Please generate a new set.", "info");
  }
}

async function saveToLocal(key, data, encryptionKey) {
  try {
    const unencryptedMetadata = { title: data.title, timestamp: data.timestamp };
    const encryptedPayload = await cryptoHelpers.encrypt(data, encryptionKey);
    const storableData = {
      metadata: unencryptedMetadata,
      payload: encryptedPayload
    };
    localStorage.setItem(key, JSON.stringify(storableData));
  } catch (e) {
    console.error("Error saving to local storage:", e);
    showToast("Could not save document. Storage may be full.", "error");
  }
}

async function loadFromLocal(key, encryptionKey) {
  const storableData = JSON.parse(localStorage.getItem(key));
  if (!storableData || !storableData.payload) return null;
  try {
    return await cryptoHelpers.decrypt(storableData.payload, encryptionKey);
  } catch (e) {
    console.error("Decryption failed for key:", key, e);
    showToast(`Could not decrypt document "${storableData.metadata.title}". Wrong key?`, "error");
    return null; // Indicates decryption failure
  }
}

function listLocalDocs() {
  const docs = [];
  for (let i = 0; i < localStorage.length; i++) {
    const key = localStorage.key(i);
    if (key.startsWith(LS_PREFIX)) {
      try {
        const doc = JSON.parse(localStorage.getItem(key));
        if (doc && doc.metadata && doc.metadata.title) {
          docs.push({ key, title: doc.metadata.title, timestamp: doc.metadata.timestamp });
        }
      } catch (e) { console.error(`Could not parse doc metadata for key ${key}:`, e); }
    }
  }
  return docs.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
}

function deleteFromLocal(key) {
  localStorage.removeItem(key);
}

// --- Modern UI Functions ---
function showToast(message, type = 'info') {
  const container = document.getElementById('toast-container');
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.textContent = message;
  container.appendChild(toast);
  setTimeout(() => toast.classList.add('show'), 10);
  setTimeout(() => {
    toast.classList.remove('show');
    setTimeout(() => container.removeChild(toast), 300);
  }, 5000);
}

function updateWordCount(quill) {
  const text = quill.getText();
  const words = text.trim().split(/\s+/).filter(word => word.length > 0).length;
  const chars = text.length - 1;
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
  document.getElementById('export-pdf-btn').style.display = 'none';
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

function renderProofChain(chain, mode = 'live', verificationErrors = []) {
  const proofDisplay = document.getElementById('proof-display');
  proofDisplay.innerHTML = '';
  const findErrorForEpoch = (index) => verificationErrors.find(e => e.includes(`at epoch ${index}`) || e.includes(`Epoch ${index}:`)) || null;
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
    const entryHTML = `<div title="${statusTitle}" style="padding: 4px 2px; border-bottom: 1px solid var(--bg-tertiary);"><span style="color: ${statusColor}; font-weight: bold; margin-right: 8px;">${statusIcon}</span><span>${label}: ${hash}</span>${durationInfo}</div>`;
    proofDisplay.innerHTML += entryHTML;
  });
  if (mode === 'live' && proofDisplay.lastElementChild) {
    proofDisplay.lastElementChild.title = 'Current epoch';
  }
  proofDisplay.scrollTop = proofDisplay.scrollHeight;
}


// Enhanced Human Authorship Scoring System
function calculateEnhancedHumanAuthorshipScore(proofChain) {
  const epochDeltas = proofChain.slice(1).map(proof => {
    let flatOps = [];
    if (proof.deltas) {
      proof.deltas.forEach(deltaObj => {
        if (deltaObj && deltaObj.ops) flatOps = flatOps.concat(deltaObj.ops);
      });
    }
    return {
      deltas: flatOps,
      duration: proof.epochDuration,
      epochNumber: proof.epochNumber,
      timestamp: proof.timestamp
    };
  });

  if (epochDeltas.length === 0) return { humanScore: 0, details: {}, metrics: {} };

  // Early anomaly detection
  for (const epoch of epochDeltas) {
    if (!epoch.deltas) continue;
    const totalOpsInEpoch = epoch.deltas.length;
    if (totalOpsInEpoch > 200) return {
      humanScore: 0.05,
      details: { anomalyReason: "Edit storm detected." },
      metrics: {}
    };
    for (const op of epoch.deltas) {
      if (op.insert && op.insert.length > 100) return {
        humanScore: 0.1,
        details: { anomalyReason: "Large paste detected." },
        metrics: {}
      };
    }
  }

  // 1. Micro-burst Pattern Analysis
  function analyzeMicroBursts(epochs) {
    let allBurstMetrics = [];

    epochs.forEach(epoch => {
      if (epoch.deltas.length < 2) return;

      // Calculate inter-operation spacing based on content position
      let cumulativeChars = 0;
      const totalChars = epoch.deltas.reduce((sum, d) => sum + (d.insert?.length || 0), 0);
      let burstGroups = [];
      let currentBurst = [];

      epoch.deltas.forEach((delta, i) => {
        const charLength = delta.insert?.length || delta.delete || 0;
        const relativePosition = totalChars > 0 ? cumulativeChars / totalChars : 0;
        const estimatedTime = relativePosition * epoch.duration;

        if (currentBurst.length > 0) {
          const lastTime = currentBurst[currentBurst.length - 1].time;
          const timeDiff = estimatedTime - lastTime;

          // New burst if gap > 2 seconds
          if (timeDiff > 2) {
            if (currentBurst.length > 1) burstGroups.push(currentBurst);
            currentBurst = [];
          }
        }

        currentBurst.push({
          time: estimatedTime,
          chars: charLength,
          type: delta.insert ? 'insert' : 'delete'
        });

        cumulativeChars += charLength;
      });

      if (currentBurst.length > 1) burstGroups.push(currentBurst);

      // Analyze burst characteristics
      burstGroups.forEach(burst => {
        const burstDuration = burst[burst.length - 1].time - burst[0].time;
        const burstChars = burst.reduce((sum, op) => sum + op.chars, 0);
        const burstOps = burst.length;

        allBurstMetrics.push({
          duration: burstDuration,
          chars: burstChars,
          ops: burstOps,
          charsPerSecond: burstDuration > 0 ? burstChars / burstDuration : 0,
          opsPerSecond: burstDuration > 0 ? burstOps / burstDuration : 0
        });
      });
    });

    // Calculate burstiness score
    if (allBurstMetrics.length === 0) return 0.5;

    const avgCharsPerSecond = allBurstMetrics.reduce((sum, m) => sum + m.charsPerSecond, 0) / allBurstMetrics.length;
    const variance = allBurstMetrics.reduce((sum, m) => sum + Math.pow(m.charsPerSecond - avgCharsPerSecond, 2), 0) / allBurstMetrics.length;

    // Humans have moderate variance (not too consistent, not too random)
    const normalizedVariance = Math.sqrt(variance) / (avgCharsPerSecond + 1);
    return 1 / (1 + Math.exp(-4 * (normalizedVariance - 0.3) + 2));
  }

  // 2. Revision Coherence Analysis
  function analyzeRevisionCoherence(epochs) {
    let revisionPatterns = {
      typoCorrections: 0,      // Delete 1-3 chars
      wordReplacements: 0,     // Delete 4-20 chars  
      sentenceRevisions: 0,    // Delete >20 chars
      immediateCorrections: 0, // Delete followed by insert within same position
      totalRevisions: 0
    };

    epochs.forEach(epoch => {
      for (let i = 0; i < epoch.deltas.length; i++) {
        const delta = epoch.deltas[i];

        if (delta.delete) {
          revisionPatterns.totalRevisions++;

          const deleteLength = delta.delete;
          if (deleteLength <= 3) {
            revisionPatterns.typoCorrections++;

            // Check if followed by immediate insert
            if (i + 1 < epoch.deltas.length && epoch.deltas[i + 1].insert) {
              revisionPatterns.immediateCorrections++;
            }
          } else if (deleteLength <= 20) {
            revisionPatterns.wordReplacements++;
          } else {
            revisionPatterns.sentenceRevisions++;
          }
        }
      }
    });

    if (revisionPatterns.totalRevisions === 0) return 0.7; // Some revision is human-like

    // Calculate coherence score based on revision distribution
    const typoRatio = revisionPatterns.typoCorrections / revisionPatterns.totalRevisions;
    const immediateRatio = revisionPatterns.immediateCorrections / revisionPatterns.totalRevisions;
    const sentenceRatio = revisionPatterns.sentenceRevisions / revisionPatterns.totalRevisions;

    // Humans mostly make small corrections, some word replacements, few sentence revisions
    const typoScore = 1 / (1 + Math.exp(-10 * (typoRatio - 0.6)));
    const immediateScore = 1 / (1 + Math.exp(-8 * (immediateRatio - 0.3)));
    const balanceScore = 1 - Math.abs(sentenceRatio - 0.1) * 5;

    return (typoScore + immediateScore + balanceScore) / 3;
  }

  // 3. Momentum Analysis
  function analyzeMomentum(epochs) {
    if (epochs.length < 3) return 0.5;

    const charRates = epochs.map(e => {
      const chars = e.deltas.reduce((sum, d) => sum + (d.insert?.length || 0), 0);
      return chars / e.duration;
    });

    // Detect warmup pattern (first 5 epochs)
    let warmupScore = 0;
    if (epochs.length >= 5) {
      const firstFive = charRates.slice(0, 5);
      let increasing = 0;
      for (let i = 1; i < firstFive.length; i++) {
        if (firstFive[i] > firstFive[i - 1] * 0.9) increasing++;
      }
      warmupScore = increasing / 4; // Expecting gradual increase
    }

    // Detect fatigue (declining performance over time)
    let fatigueScore = 0;
    if (epochs.length >= 10) {
      const segments = [];
      const segmentSize = Math.floor(epochs.length / 5);

      for (let i = 0; i < 5; i++) {
        const segment = charRates.slice(i * segmentSize, (i + 1) * segmentSize);
        segments.push(segment.reduce((a, b) => a + b, 0) / segment.length);
      }

      // Check for gradual decline
      let declining = 0;
      for (let i = 1; i < segments.length; i++) {
        if (segments[i] < segments[i - 1] * 1.1) declining++;
      }

      fatigueScore = epochs.length > 20 ? declining / 4 : 0.5;
    }

    // Detect recovery after pauses
    let recoveryScore = 0;
    let pauseRecoveries = [];

    epochs.forEach((epoch, i) => {
      if (i > 0 && epoch.deltas.length === 0) {
        // Found a pause, check recovery pattern
        if (i + 3 < epochs.length) {
          const beforePause = i > 1 ? charRates[i - 1] : charRates[0];
          const recovery = [charRates[i + 1], charRates[i + 2], charRates[i + 3]];

          // Humans don't instantly return to full speed
          const immediateReturn = recovery[0] / beforePause;
          const gradualReturn = recovery[2] / beforePause;

          if (immediateReturn < 0.8 && gradualReturn > 0.7) {
            pauseRecoveries.push(1);
          } else {
            pauseRecoveries.push(0);
          }
        }
      }
    });

    if (pauseRecoveries.length > 0) {
      recoveryScore = pauseRecoveries.reduce((a, b) => a + b, 0) / pauseRecoveries.length;
    } else {
      recoveryScore = 0.5;
    }

    return (warmupScore + fatigueScore + recoveryScore) / 3;
  }

  // 4. Semantic Coherence Analysis
  function analyzeSemanticCoherence(epochs) {
    let allText = '';
    let sentenceLengths = [];
    let punctuationCounts = { periods: 0, commas: 0, questions: 0, exclamations: 0 };
    let capitalPatterns = { sentences: 0, midSentence: 0, consecutive: 0 };

    // Build complete text and analyze patterns
    epochs.forEach(epoch => {
      let epochText = '';
      epoch.deltas.forEach(delta => {
        if (delta.insert && typeof delta.insert === 'string') {
          epochText += delta.insert;
          allText += delta.insert;
        }
      });

      // Extract sentences (simple approach)
      const sentences = epochText.split(/[.!?]+/);
      sentences.forEach(sentence => {
        const trimmed = sentence.trim();
        if (trimmed.length > 0) {
          sentenceLengths.push(trimmed.split(/\s+/).length);
        }
      });

      // Count punctuation
      punctuationCounts.periods += (epochText.match(/\./g) || []).length;
      punctuationCounts.commas += (epochText.match(/,/g) || []).length;
      punctuationCounts.questions += (epochText.match(/\?/g) || []).length;
      punctuationCounts.exclamations += (epochText.match(/!/g) || []).length;

      // Analyze capitalization
      const words = epochText.split(/\s+/);
      words.forEach((word, i) => {
        if (word.length > 0) {
          if (/^[A-Z]/.test(word)) {
            if (i === 0 || words[i - 1].endsWith('.') || words[i - 1].endsWith('!') || words[i - 1].endsWith('?')) {
              capitalPatterns.sentences++;
            } else if (/^[A-Z]{2,}/.test(word)) {
              capitalPatterns.consecutive++;
            } else {
              capitalPatterns.midSentence++;
            }
          }
        }
      });
    });

    // Calculate coherence metrics
    let coherenceScore = 0;

    // Sentence length variation (humans vary, bots are consistent)
    if (sentenceLengths.length > 2) {
      const avgLength = sentenceLengths.reduce((a, b) => a + b, 0) / sentenceLengths.length;
      const variance = sentenceLengths.reduce((sum, len) => sum + Math.pow(len - avgLength, 2), 0) / sentenceLengths.length;
      const cv = Math.sqrt(variance) / (avgLength + 1); // Coefficient of variation

      // Humans typically have CV between 0.4 and 0.8
      coherenceScore += 1 / (1 + Math.exp(-10 * (cv - 0.2))) * (1 / (1 + Math.exp(10 * (cv - 1))));
    }

    // Punctuation ratio (humans use varied punctuation)
    const totalPunctuation = Object.values(punctuationCounts).reduce((a, b) => a + b, 0);
    if (totalPunctuation > 0) {
      const punctuationDiversity = Object.values(punctuationCounts).filter(c => c > 0).length / 4;
      coherenceScore += punctuationDiversity * 0.5;
    }

    // Capitalization patterns (proper at sentence starts, occasional proper nouns)
    const totalCaps = capitalPatterns.sentences + capitalPatterns.midSentence + capitalPatterns.consecutive;
    if (totalCaps > 0) {
      const properCapRatio = capitalPatterns.sentences / totalCaps;
      const properNounRatio = capitalPatterns.midSentence / totalCaps;

      // Good pattern: mostly sentence capitals, some proper nouns, few all-caps
      if (properCapRatio > 0.6 && properNounRatio > 0.1 && properNounRatio < 0.4) {
        coherenceScore += 0.5;
      }
    }

    return Math.min(coherenceScore, 1);
  }

  // 5. Cross-Epoch Correlation
  function analyzeCrossEpochPatterns(epochs) {
    if (epochs.length < 5) return 0.5;

    // Calculate per-epoch style metrics
    const epochMetrics = epochs.map(epoch => {
      const chars = epoch.deltas.reduce((sum, d) => sum + (d.insert?.length || 0), 0);
      const dels = epoch.deltas.filter(d => d.delete).length;
      const ops = epoch.deltas.length;

      return {
        charsPerOp: ops > 0 ? chars / ops : 0,
        deleteRatio: ops > 0 ? dels / ops : 0,
        opsPerSecond: ops / epoch.duration,
        avgOpSize: ops > 0 ? chars / ops : 0
      };
    });

    // Calculate consistency scores
    const metrics = ['charsPerOp', 'deleteRatio', 'opsPerSecond', 'avgOpSize'];
    let consistencyScores = [];

    metrics.forEach(metric => {
      const values = epochMetrics.map(e => e[metric]);
      const mean = values.reduce((a, b) => a + b, 0) / values.length;
      const variance = values.reduce((sum, v) => sum + Math.pow(v - mean, 2), 0) / values.length;
      const cv = mean > 0 ? Math.sqrt(variance) / mean : 0;

      // Humans show moderate consistency (CV between 0.2 and 0.6)
      const score = 1 / (1 + Math.exp(-10 * (cv - 0.1))) * (1 / (1 + Math.exp(10 * (cv - 0.8))));
      consistencyScores.push(score);
    });

    // Check for natural progression/evolution
    let evolutionScore = 0;
    const windowSize = Math.min(5, Math.floor(epochs.length / 3));

    if (epochs.length >= windowSize * 3) {
      const early = epochMetrics.slice(0, windowSize);
      const middle = epochMetrics.slice(Math.floor(epochs.length / 2 - windowSize / 2), Math.floor(epochs.length / 2 + windowSize / 2));
      const late = epochMetrics.slice(-windowSize);

      // Calculate average metrics for each period
      const periods = [early, middle, late].map(period => ({
        avgCharsPerOp: period.reduce((sum, e) => sum + e.charsPerOp, 0) / period.length,
        avgOpsPerSecond: period.reduce((sum, e) => sum + e.opsPerSecond, 0) / period.length
      }));

      // Natural patterns: might speed up initially, slow down toward end
      if (periods[1].avgOpsPerSecond > periods[0].avgOpsPerSecond * 0.9 &&
        periods[2].avgOpsPerSecond < periods[1].avgOpsPerSecond * 1.1) {
        evolutionScore = 0.8;
      } else {
        evolutionScore = 0.4;
      }
    }

    const avgConsistency = consistencyScores.reduce((a, b) => a + b, 0) / consistencyScores.length;
    return (avgConsistency + evolutionScore) / 2;
  }

  // Calculate all component scores
  const microBurstScore = analyzeMicroBursts(epochDeltas);
  const revisionScore = analyzeRevisionCoherence(epochDeltas);
  const momentumScore = analyzeMomentum(epochDeltas);
  const semanticScore = analyzeSemanticCoherence(epochDeltas);
  const crossEpochScore = analyzeCrossEpochPatterns(epochDeltas);

  // Also calculate original metrics for comparison
  const charCounts = epochDeltas.map(e => e.deltas.reduce((s, d) => s + (d.insert?.length || 0), 0));
  const meanChars = charCounts.reduce((s, v) => s + v, 0) / charCounts.length || 0;
  const bvr = charCounts.reduce((a, c) => a + Math.pow(c - meanChars, 2), 0) / charCounts.length / (meanChars + 1);
  const pauseRatio = epochDeltas.filter(e => e.deltas.length === 0).length / epochDeltas.length;

  const editTypes = epochDeltas.map(e =>
    e.deltas.filter(d => d.insert).length > 10 ? 'burst' :
      e.deltas.filter(d => d.delete).length > e.deltas.filter(d => d.insert).length ? 'revision' :
        e.deltas.length === 0 ? 'pause' : 'steady'
  );
  const typeCounts = editTypes.reduce((a, c) => { a[c] = (a[c] || 0) + 1; return a }, {});
  const entropy = -Object.values(typeCounts).reduce((s, c) => s - (c / editTypes.length) * Math.log2(c / editTypes.length), 0);

  const speeds = epochDeltas.filter(e => e.deltas.length > 0).map(e => e.deltas.reduce((s, d) => s + (d.insert?.length || 0), 0) / 10);
  const meanSpeed = speeds.reduce((s, v) => s + v, 0) / speeds.length || 0;

  // Original score components
  const sigmoid = (x) => 1 / (1 + Math.exp(-x));
  const gaussian = (x, mean, std) => Math.exp(-0.5 * Math.pow((x - mean) / std, 2));

  const originalScores = {
    burstScore: sigmoid((bvr - 0.5) * 2),
    pauseScore: sigmoid((pauseRatio - 0.05) * 15),
    entropyScore: gaussian(entropy, 1.0, 0.7),
    speedScore: gaussian(meanSpeed, 5, 3),
  };

  // Combine all scores with weights
  const enhancedScores = {
    ...originalScores,
    microBurstScore,
    revisionScore,
    momentumScore,
    semanticScore,
    crossEpochScore
  };

  // New weighted combination
  const weights = {
    burstScore: 0.15,
    pauseScore: 0.10,
    entropyScore: 0.10,
    speedScore: 0.10,
    microBurstScore: 0.15,
    revisionScore: 0.15,
    momentumScore: 0.10,
    semanticScore: 0.10,
    crossEpochScore: 0.05
  };

  const humanScore = Object.entries(enhancedScores).reduce((sum, [key, score]) => sum + score * weights[key], 0);

  return {
    humanScore,
    details: enhancedScores,
    metrics: {
      totalEpochs: epochDeltas.length,
      totalChars: charCounts.reduce((a, b) => a + b, 0),
      avgCharsPerEpoch: meanChars,
      pauseRatio,
      editEntropy: entropy
    }
  };
}

// Update the display function to show enhanced metrics
function showEnhancedAuthorshipAnalysis(proofChain) {
  const analysis = calculateEnhancedHumanAuthorshipScore(proofChain);
  const percentage = Math.round(analysis.humanScore * 100);

  return `
    <div class="authorship-analysis">
      <h3>Enhanced Authorship Analysis</h3>
      <div class="human-score">${percentage}% Human Characteristics</div>
      <div class="details">
        <div>Typing Rhythm: ${Math.round((analysis.details.burstScore || 0) * 100)}%</div>
        <div>Pause Patterns: ${Math.round((analysis.details.pauseScore || 0) * 100)}%</div>
        <div>Edit Complexity: ${Math.round((analysis.details.entropyScore || 0) * 100)}%</div>
        <div>Speed Profile: ${Math.round((analysis.details.speedScore || 0) * 100)}%</div>
        <div>Micro-bursts: ${Math.round((analysis.details.microBurstScore || 0) * 100)}%</div>
        <div>Revision Quality: ${Math.round((analysis.details.revisionScore || 0) * 100)}%</div>
        <div>Writing Momentum: ${Math.round((analysis.details.momentumScore || 0) * 100)}%</div>
        <div>Semantic Coherence: ${Math.round((analysis.details.semanticScore || 0) * 100)}%</div>
        <div>Style Consistency: ${Math.round((analysis.details.crossEpochScore || 0) * 100)}%</div>
      </div>
      <div style="margin-top: 12px; font-size: 12px; color: var(--text-secondary);">
        ${analysis.metrics.totalEpochs} epochs analyzed, ${analysis.metrics.totalChars} total characters
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

async function verifyDocument(documentData, updateProgress) {
  const results = { valid: true, errors: [], verifiedEpochs: 0, totalEpochs: 0, signatureValid: false };
  try {
    // 1. Verify VDF Chain
    await init();
    const computer = new VDFComputer();
    const epochs = documentData.proofChain;
    results.totalEpochs = epochs.length - 1;
    for (let i = 1; i < epochs.length; i++) {
      const epoch = epochs[i];
      if (updateProgress) updateProgress((i / (epochs.length - 1)) * 90, `Verifying epoch ${i}...`);
      if (epoch.previousHash !== epochs[i - 1].hash) { results.errors.push(`Epoch ${i}: Broken chain.`); results.valid = false; continue; }
      const vdfProof = new VDFProof(epoch.vdfProof.y, epoch.vdfProof.pi, epoch.vdfProof.l, epoch.vdfProof.r, BigInt(epoch.iterations));
      if (!(await computer.verify_proof(epoch.previousHash, vdfProof))) { results.errors.push(`Epoch ${i}: Invalid VDF proof.`); results.valid = false; } else { results.verifiedEpochs++; }
      const content = { epochNumber: epoch.epochNumber, previousHash: epoch.previousHash, deltas: epoch.deltas, vdfY: epoch.vdfProof.y, iterations: epoch.iterations };
      if (epoch.hash !== await sha256(JSON.stringify(content))) { results.errors.push(`Epoch ${i}: Hash mismatch.`); results.valid = false; }
    }

    // 2. Verify Signature
    if (updateProgress) updateProgress(95, 'Verifying signature...');
    const { publicKey, signature, documentHash } = documentData.metadata;
    if (publicKey && signature && documentHash) {
      const pubKey = await cryptoHelpers.importKey(publicKey, 'ECDSA', ['verify']);
      results.signatureValid = await cryptoHelpers.verify(documentHash, signature, pubKey);
      if (!results.signatureValid) {
        results.errors.push("Author signature is invalid.");
      }
    } else {
      results.errors.push("Document is not signed.");
    }

    results.valid = results.errors.length === 0;
    if (updateProgress) updateProgress(100, 'Verification complete.');
  } catch (error) {
    results.valid = false;
    results.errors.push(error.message);
  }
  return results;
}

// Declare state variables and helper functions in the global scope
let userKeys = null;
let appState = {
  currentDocumentKey: null,
  isDirty: false,
  loadedMetadata: null // Add this line to store original metadata
};
let proofChain = [];
let quill;

async function buildDocumentData() {
  const title = document.getElementById('document-title').value || "Untitled Document";
  const docData = {
    title, version: "2.1-crypto", timestamp: new Date().toISOString(),
    content: { html: quill.root.innerHTML, delta: quill.getContents() },
    proofChain,
    metadata: {
      epochCount: proofChain.length,
      genesisHash: proofChain[0]?.hash,
      latestHash: proofChain[proofChain.length - 1]?.hash,
      totalDuration: proofChain.reduce((s, e) => s + (e.epochDuration || 0), 0),
      documentHash: null, publicKey: null, signature: null
    }
  };
  const dataToHash = { ...docData, metadata: { ...docData.metadata, documentHash: null, signature: null } };
  docData.metadata.documentHash = await sha256(JSON.stringify(dataToHash));
  return docData;
}


// --- Main App Logic ---
async function run() {
  await init();

  const computer = new VDFComputer();
  const targetSeconds = 10;
  let calibratedIterations = 100000; // Fallback
  try {
    console.log('Starting VDF calibration...');
    const baselineIterations = 10000;
    const baselineStart = performance.now();
    await computer.compute_proof("calibration", BigInt(baselineIterations), null);
    const baselineTime = (performance.now() - baselineStart) / 1000;
    const iterationsPerSecond = baselineIterations / baselineTime;
    calibratedIterations = Math.floor(iterationsPerSecond * targetSeconds);
    console.log(`Calibrated to ${calibratedIterations} iterations for ${targetSeconds}s`);
  } catch (e) {
    console.error("VDF calibration failed, using fallback.", e);
    showToast("VDF calibration failed, using default timing.", "error");
  }

  let epochDeltas = [];
  let isVDFRunning = false;
  let epochStartTime = Date.now();
  let currentProgress = 0;
  let vdfWorker;

  // Initialize the globally declared quill instance
  quill = new Quill('#editor', { theme: 'snow', placeholder: 'Start writing...' });

  // --- PDF Generation ---
  function exportToVerifiedPDF(results, documentData) {
    const doc = new jsPDF();
    const content = quill.getText();
    doc.setProperties({ title: documentData.title, subject: 'Verified BitQuill Document' });
    doc.setFont('times', 'normal');
    doc.setFontSize(12);
    doc.text(content, 15, 20, { maxWidth: 180 });

    const pageHeight = doc.internal.pageSize.getHeight();
    const stampY = pageHeight - 65;
    doc.setDrawColor(150);
    doc.line(15, stampY, 195, stampY);

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(12);
    doc.text('✓ Document Verified', 15, stampY + 8);

    doc.setFont('courier', 'normal');
    doc.setFontSize(9);
    doc.text(`Verification Date: ${new Date().toLocaleString()}`, 15, stampY + 16);
    doc.text(`Epochs Verified:   ${results.verifiedEpochs}/${results.totalEpochs}`, 15, stampY + 21);
    doc.text(`Author Signature:  ${results.signatureValid ? 'VALID' : 'INVALID'}`, 15, stampY + 26);
    doc.text(`Final Hash:        ${documentData.metadata.documentHash.substring(0, 48)}...`, 15, stampY + 31);

    // QR Code Generation
    const qrData = JSON.stringify({
      title: documentData.title,
      hash: documentData.metadata.documentHash,
      publicKey: documentData.metadata.publicKey,
      signature: documentData.metadata.signature
    });
    try {
      const qr = qrcode(0, 'L');
      qr.addData(qrData);
      qr.make();
      const qrImgData = qr.createDataURL(4);
      doc.addImage(qrImgData, 'PNG', 150, stampY + 8, 40, 40);
    } catch (e) {
      console.error("QR Code generation failed:", e);
      doc.text("QR Gen Error", 160, stampY + 28);
    }

    doc.save(`${documentData.title.replace(/\s/g, '_')}_verified.pdf`);
  }

  // --- MOVED FUNCTION ---
  function showVerificationResults(results, documentData) {
    document.querySelector('.verification-progress').style.display = 'none';
    const resultsEl = document.getElementById('verification-results');
    resultsEl.style.display = 'block';

    const authorshipHTML = showEnhancedAuthorshipAnalysis(documentData.proofChain);

    const signatureColor = results.signatureValid ? 'var(--primary-color)' : '#ff4444';
    const signatureText = results.signatureValid ? 'VALID' : 'INVALID / MISSING';

    if (results.valid && results.signatureValid) {
      resultsEl.innerHTML = `<div style="color: var(--primary-color); margin-bottom: 16px; font-size: 18px;">✓ Document verified successfully</div>`;
    } else {
      resultsEl.innerHTML = `<div style="color: #ff4444; margin-bottom: 16px; font-size: 18px;">✗ Verification failed</div>
                             <div style="color: #ff4444; margin-bottom: 16px;">${results.errors.join('<br>')}</div>`;
    }

    resultsEl.innerHTML += `
        <div style="margin-bottom: 8px;">Verified Epochs: ${results.verifiedEpochs}/${results.totalEpochs}</div>
        <div style="margin-bottom: 8px;">Author Signature: <span style="color:${signatureColor};">${signatureText}</span></div>
        <div style="margin-bottom: 16px;">Final Hash: ${documentData.metadata.latestHash.substring(0, 16)}...</div>
        ${authorshipHTML}`; // Display the analysis

    if (results.valid && results.signatureValid) {
      document.getElementById('export-pdf-btn').style.display = 'block';
      document.getElementById('export-pdf-btn').onclick = () => exportToVerifiedPDF(results, documentData);
    } else {
      document.getElementById('export-pdf-btn').style.display = 'none';
    }
  }

  function startNextEpoch() {
    if (!proofChain || proofChain.length === 0) return;
    isVDFRunning = true;
    epochStartTime = Date.now();
    currentProgress = 0;
    const previousEpoch = proofChain[proofChain.length - 1];
    vdfWorker.postMessage({ command: 'start', input: previousEpoch.hash, iterations: calibratedIterations });
  }

  function restartVdfProcess() {
    if (vdfWorker) vdfWorker.terminate();
    epochDeltas = [];
    vdfWorker = new Worker(new URL('./vdf-worker.js', import.meta.url));
    vdfWorker.onmessage = async (event) => {
      const { status, proof, progress, error } = event.data;
      if (status === 'progress') {
        currentProgress = progress;
        return;
      }
      if (status === 'error') {
        console.error('VDF Worker Error:', error);
        isVDFRunning = false;
        return;
      }
      if (status === 'complete') {
        const epochDuration = (Date.now() - epochStartTime) / 1000;
        if (epochDeltas.length > 0) {
          const prev = proofChain[proofChain.length - 1];
          const epoch = new EpochProof(proofChain.length, prev.hash, epochDeltas, proof, calibratedIterations, epochDuration);
          await epoch.computeHash();
          proofChain.push(epoch);
          document.getElementById('epoch-number').textContent = epoch.epochNumber;
          renderProofChain(proofChain);
          epochDeltas = [];
          appState.isDirty = true;
        }
        startNextEpoch();
      }
    };
    startNextEpoch();
  }

  function loadDocumentState(docData, key) {
    quill.setContents(docData.content.delta);
    proofChain = docData.proofChain;
    document.getElementById('document-title').value = docData.title || 'Untitled Document';
    appState.currentDocumentKey = key;
    appState.isDirty = false;

    // **FIX**: Store the original document's metadata
    appState.loadedMetadata = docData.metadata;

    const lastEpoch = docData.proofChain[docData.proofChain.length - 1];
    document.getElementById('epoch-number').textContent = lastEpoch.epochNumber;
    document.getElementById('last-saved').textContent = `Saved ${new Date(docData.timestamp).toLocaleTimeString()}`;
    renderProofChain(proofChain);
    updateWordCount(quill);
    restartVdfProcess();
  }

  function createNewDocument() {
    if (appState.isDirty && !confirm("You have unsaved changes. Are you sure you want to create a new document?")) return;
    quill.setContents([{ insert: '\n' }]);
    appState.currentDocumentKey = null;
    appState.isDirty = false;

    // **FIX**: Clear the metadata for a new document
    appState.loadedMetadata = null;

    document.getElementById('document-title').value = "Untitled Document";
    document.getElementById('last-saved').textContent = 'Not saved';
    proofChain = [{ epochNumber: 0, hash: "0000000000000000000000000000000000000000000000000000000000000000", timestamp: new Date().toISOString() }];
    renderProofChain(proofChain);
    restartVdfProcess();
    showToast("New document created.", "info");
  }

  // --- UI Event Handlers ---
  quill.on('text-change', (delta, oldDelta, source) => {
    if (source === 'user') {
      epochDeltas.push(delta);
      appState.isDirty = true;
    }
    updateWordCount(quill);
  });

  document.getElementById('generate-keys-btn').onclick = generateAndStoreKeys;
  document.getElementById('new-doc-btn').onclick = createNewDocument;
  document.getElementById('save-btn').onclick = signAndSaveDocument;
  document.getElementById('import-btn').onclick = () => document.getElementById('file-input').click();

  document.getElementById('verify-live-btn').onclick = async () => {
    // **FIX**: This entire handler is replaced with the correct logic.
    showToast('Verifying document...', 'info');

    // Check if there is metadata from a loaded/saved document.
    if (!appState.loadedMetadata || !appState.loadedMetadata.signature) {
      showToast("Cannot verify. The document has not been signed.", "error");
      return;
    }

    // Build the document from the current on-screen content to check for modifications.
    const currentDocData = await buildDocumentData();

    // The document hash to be verified is the one from the ORIGINAL metadata,
    // as that's what the signature was created from.
    const docDataToVerify = {
      ...currentDocData,
      metadata: {
        ...currentDocData.metadata,
        signature: appState.loadedMetadata.signature,
        publicKey: appState.loadedMetadata.publicKey,
        documentHash: appState.loadedMetadata.documentHash
      }
    };

    // Warn the user if the content has changed since it was signed.
    if (currentDocData.metadata.documentHash !== appState.loadedMetadata.documentHash) {
      showToast("Warning: Document has been modified since signing.", "warning");
    }

    // Proceed with verification using the original signature data.
    showVerificationModal();
    updateVerificationProgress(0, 'Starting verification...');
    const verification = await verifyDocument(docDataToVerify, updateVerificationProgress);
    showVerificationResults(verification, docDataToVerify);
    renderProofChain(proofChain, 'verified', verification.errors);
  };

  const fileBrowserModal = document.getElementById('file-browser-modal');
  const modalBackdrop = document.getElementById('modal-backdrop');

  const showFileBrowser = () => {
    const listEl = document.getElementById('file-browser-list');
    listEl.innerHTML = '';
    const docs = listLocalDocs();
    if (docs.length === 0) {
      listEl.innerHTML = '<p style="color: var(--text-secondary);">No documents saved in this browser.</p>';
    } else {
      docs.forEach(doc => {
        const item = document.createElement('div');
        item.className = 'file-browser-item';
        item.innerHTML = `
          <div class="file-item-info" data-key="${doc.key}">
            <div class="file-browser-title">${doc.title}</div>
            <div class="file-browser-timestamp">Saved: ${new Date(doc.timestamp).toLocaleString()}</div>
          </div>
          <div class="file-browser-actions">
            <button class="btn-icon export-btn" title="Export to File" data-key="${doc.key}"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path><polyline points="7 10 12 15 17 10"></polyline><line x1="12" y1="15" x2="12" y2="3"></line></svg></button>
            <button class="btn-icon delete-btn" title="Delete" data-key="${doc.key}"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"></polyline><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"></path></svg></button>
          </div>`;
        listEl.appendChild(item);
      });
    }
    modalBackdrop.classList.add('show');
    fileBrowserModal.classList.add('show');
  };
  const hideFileBrowser = () => {
    modalBackdrop.classList.remove('show');
    fileBrowserModal.classList.remove('show');
  };

  document.getElementById('browse-local-btn').onclick = showFileBrowser;
  document.getElementById('file-browser-close').onclick = hideFileBrowser;

  document.getElementById('file-browser-list').addEventListener('click', async (e) => {
    const target = e.target.closest('[data-key]');
    if (!target) return;
    const key = target.getAttribute('data-key');

    if (e.target.closest('.delete-btn')) {
      if (confirm(`Are you sure you want to delete this document? This cannot be undone.`)) {
        deleteFromLocal(key);
        showToast("Document deleted", "info");
        showFileBrowser();
      }
    } else if (e.target.closest('.export-btn')) {
      if (!userKeys) { showToast("Please load keys to export documents.", "error"); return; }
      const docData = await loadFromLocal(key, userKeys.encryptionKey);
      if (docData) {
        const blob = new Blob([JSON.stringify(docData, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${docData.title.replace(/[^a-z0-9]/gi, '_').toLowerCase()}.json`;
        a.click();
        URL.revokeObjectURL(url);
        showToast("Exporting document...", "info");
      }
    } else if (e.target.closest('.file-item-info')) {
      if (!userKeys) { showToast("Please load keys to decrypt documents.", "error"); return; }
      if (appState.isDirty && !confirm("You have unsaved changes that will be lost. Load document anyway?")) return;

      const docData = await loadFromLocal(key, userKeys.encryptionKey);
      if (docData) { // loadFromLocal returns null on decryption failure
        loadDocumentState(docData, key);
        hideFileBrowser();
        showToast(`Loaded "${docData.title}"`, "success");
      }
    }
  });

  document.getElementById('file-input').onchange = async (e) => {
    if (!e.target.files[0]) return;
    showToast('Importing and verifying...', 'info');
    try {
      const fileContent = await e.target.files[0].text();
      const data = JSON.parse(fileContent);
      if (appState.isDirty && !confirm("You have unsaved changes that will be lost. Import anyway?")) return;
      loadDocumentState(data, null); // Imported docs don't have a local key yet
      showToast('Document imported successfully', 'success');
    } catch (error) {
      showToast(`Error importing file: ${error.message}`, 'error');
    } finally {
      e.target.value = '';
    }
  };

  document.getElementById('epoch-indicator').onclick = () => document.getElementById('proof-panel').classList.toggle('show');
  document.getElementById('proof-panel-close').onclick = () => document.getElementById('proof-panel').classList.remove('show');
  modalBackdrop.onclick = () => { hideVerificationModal(); hideFileBrowser(); };
  document.getElementById('modal-close').onclick = hideVerificationModal;

  // --- App Initialization ---
  await loadKeys();
  createNewDocument();
  showToast('VDF calibration complete', 'success');
  setInterval(() => {
    if (isVDFRunning) {
      const elapsed = (Date.now() - epochStartTime) / 1000;
      const displayProgress = currentProgress > 0 ? currentProgress : Math.min(100, (elapsed / targetSeconds) * 100);
      updateUITimers(elapsed, targetSeconds, displayProgress);
    }
  }, 50);
}

run();
