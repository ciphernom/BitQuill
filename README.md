# BitQuill: A Merkle Tree Verification System for Digital Authenticity

![BitQuill](https://img.shields.io/badge/BitQuill-v1.0-blue)
![Rust](https://img.shields.io/badge/Rust-1.70%2B-orange)
![License](https://img.shields.io/badge/license-GPLv3-blue)

## The Challenge of Digital Authenticity

In today's world, we face an unprecedented challenge: **how can we prove digital documents are genuine, human-authored works?**

Throughout history, the integrity of written information has been safeguarded by physical properties and social conventions - the texture of papyrus, the mark of seals, the flow of ink. These physical constructs formed the bedrock of trust in written records for millennia.

Digitization has stripped away these inherent security properties. With the rapid rise of Large Language Models capable of producing increasingly convincing text, we need new methods to verify human authorship.

## BitQuill: A Digital Witness to Human Creation

BitQuill provides a solution through a novel application of Verifiable Delay Functions (VDFs) and Merkle trees, creating a tamper-evident record of document creation that captures the temporal nature of human writing.

**Key concept**: If authors can demonstrate they've spent time and effort creating text in a verifiable way, the likelihood of machine forgery diminishes significantly.

## How BitQuill Works

BitQuill creates a verifiable timeline of document creation through:

1. **VDF Clock**: A cryptographic timer that produces sequential, non-parallelizable "ticks" that require a fixed amount of real-world time to compute.

2. **Merkle Tree Structure**: Document states are stored as leaves in a Merkle tree, each bound to VDF ticks, creating a cryptographically verifiable history.

3. **Multi-level Verification**: From basic integrity checks to forensic analysis of writing patterns, BitQuill offers varying degrees of verification.

4. **Content-Time Binding**: Each document state is cryptographically tied to VDF ticks, making it impossible to fabricate a history of changes.

## Installation

### Prerequisites

- Rust 1.70+ (`rustup` recommended)
- Cargo build system

### Getting Started

```bash
# Clone the repository
git clone https://github.com/ciphernom/BitQuill
cd BitQuill

# Build the application
cargo build --release

# Run BitQuill
./target/release/bitquill
```

## Features

- **Terminal-based Editor**: Fully featured text editor with line numbering
- **Real-time VDF Integration**: Document changes are automatically anchored to VDF ticks
- **Temporal Proof System**: Creates verifiable evidence of time spent writing
- **Merkle Tree Verification**: Four levels of verification depth:
  - *Basic*: Quick integrity check
  - *Standard*: Comprehensive document verification
  - *Thorough*: Detailed chain-of-custody verification
  - *Forensic*: Writing pattern analysis & statistical validation
- **Exportable Proofs**: Share compact verification data without exposing content
- **Writing Pattern Analysis**: Detect suspicious editing patterns that might indicate non-human authorship

## Usage

### Keyboard Commands

#### File Operations
- `Ctrl+S` - Save document
- `Ctrl+Shift+S` - Save As
- `Ctrl+O` - Open document
- `Ctrl+N` - New document
- `Ctrl+E` - Export verification data
- `Ctrl+M` - Edit metadata
- `Alt+A` - Toggle auto-save
- `Alt+1-9` - Open recent files

#### Navigation & Modes
- `Tab / F2` - Toggle Edit/View mode
- `F3` - Toggle Tree View
- `Arrow Keys` - Navigate
- `Home/End` - Go to start/end of line
- `Page Up/Down` - Scroll page
- `Alt+L` - Toggle line numbers

#### Verification
- `Ctrl+V` - Verify document integrity

#### Editing
- `Ctrl+Z` - Undo
- `Esc` - Cancel/Exit

## Technical Overview

BitQuill utilizes several advanced cryptographic mechanisms:

### Verifiable Delay Functions (VDFs)
- Sequential squaring in an RSA group provides a guaranteed time delay
- Wesolowski's efficient verification system ensures proof validity
- Adaptive difficulty adjustment maintains consistent timing

### Merkle Tree Authentication
- Tamper-evident structure for verifying document history
- Efficient authentication paths for selective verification
- Chained commitments bind content to temporal proofs

### Writing Pattern Analysis
- Statistical modeling of edit intervals
- Detection of anomalous writing patterns
- Flagging of potentially non-human authorship signals

## Roadmap

- [ ] Web and mobile interfaces
- [ ] Collaborative editing with multi-author verification
- [ ] Integration with common document formats
- [ ] Enhanced writing pattern analysis
- [ ] Optimized VDF implementations
- [ ] External timestamp authority integration

## License

GPLv3 License - See LICENSE file for details

## Citation

If you use BitQuill in your research or applications, please cite:

```
@software{BitQuill2023,
  author = {CipherNom},
  title = {BitQuill: A Merkle Tree Verification System for Digital Authenticity},
  url = {https://github.com/ciphernom/BitQuill},
  year = {2023}
}
```

## Contributing

Contributions are welcome! Please see CONTRIBUTING.md for details.

## Acknowledgments

BitQuill builds on foundational work in verifiable delay functions by Wesolowski and the application of Merkle trees to document authentication.
