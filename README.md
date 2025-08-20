# BitQuill - A Digital Observer Protocol

**Live Demo: [https://ciphernom.github.io/BitQuill/](https://ciphernom.github.io/BitQuill/)**

## The Problem: Authenticity in the Age of AI

Large language models (LLMs) are now capable of generating incredibly convincing human-like text, and they can do so at a scale and speed that is difficult to comprehend. This technological shift presents a profound challenge to the authenticity of digital documents and raises concerns about the outsourcing of high-level thought in academia and professional fields.

Prior to the digital age, the medium itself often served as a testament to the creation process. Ink smeared, wax blotted, and clay was carved and baked. These physical artifacts carried inherent proof of the time and effort invested by a human author. The imperfections were a feature, not a bug.

## The Solution: Capturing the Process

**BitQuill** aims to restore this lost authenticity by capturing the one thing that is difficult to fake: the *process* of writing itself.

By creating a cryptographically secure, time-stamped record of a document's evolution, BitQuill makes the duration and nature of the writing process verifiable. It provides a "digital observer" that attests to the document's creation over a proven period, re-establishing a link between the author, their effort, and the final text.

### How It Works

1.  **Temporal Proofs**: As you write, the document's changes are bundled into snapshots called "epochs." Each epoch represents approximately 10 seconds of work.
2.  **Cryptographic Anchors**: Each epoch is cryptographically chained to the previous one using a **Verifiable Delay Function (VDF)**. This creates an immutable, time-locked history of the document.
3.  **Authorship Analysis**: Because the entire writing process is recorded—keystrokes, pauses, revisions, and all—the system can perform statistical analysis on these patterns. This allows it to generate an "authorship score," which helps distinguish the nuanced, imperfect rhythm of a human writer from the uniform, high-speed output of a machine.

### Cryptographic Deep Dive: The VDF Implementation

The VDF is the cryptographic heart of BitQuill. It's a special kind of mathematical function with three key properties that make it perfect for proving the passage of time:

1.  **Slow to Compute**: A VDF requires a specific, predictable number of sequential steps to solve.
2.  **Not Parallelizable**: You cannot speed up the computation by throwing more processors at the problem.
3.  **Fast to Verify**: Once the computation is finished, anyone can verify that the result is correct almost instantly.

**VDF Construction:**
BitQuill implements the VDF proposed by Pietrzak (2018) and Wesolowski (2019). The core function is **repeated squaring** in a group of unknown order. Specifically, for an input `x`, we compute `y = x^(2^t)` where `t` is the time parameter.

**Why Wesolowski's Proof Scheme?**
While the computation of `y` is slow, we need a way to prove it was done correctly without re-doing the entire computation. This is where proof schemes come in. BitQuill uses **Wesolowski's scheme** because it generates a very small, constant-size proof. This is ideal for our use case, as it keeps the final document size manageable and makes the verification process extremely fast for anyone wanting to check the document's history.

**Why the RSA-2048 Challenge Modulus?**
The security of this VDF relies on the computation being performed in a "group of unknown order." The simplest way to achieve this is to use an RSA modulus `N = p * q` where the prime factors `p` and `q` are unknown. If an attacker knew the factorization, they could use properties of modular arithmetic (Carmichael's theorem) to compute the result almost instantly, breaking the "slow to compute" property.

To ensure no one knows the factors, BitQuill uses the **RSA-2048 modulus from the original RSA Factoring Challenge**. This is a standard, trusted practice in cryptography. Using a well-known public challenge number provides a strong "nothing up my sleeve" guarantee that the developers (or anyone else) do not know the factorization and cannot forge the time-based proofs.

## Features

-   **Secure, Client-Side Operation**: All cryptographic operations and document storage happen directly in your browser. Nothing is sent to a server.
-   **Verifiable Proof Chain**: Every BitQuill document contains its own history, allowing anyone to verify its creation timeline.
-   **Import and Verify**: You can import a `.json` file from another BitQuill user and independently verify its authenticity and history.
-   **Authorship Score**: Gain insights into the writing process with a score that analyzes human-like characteristics.
-   **Modern Text Editor**: Built with the reliable and feature-rich Quill.js editor.

## Prerequisites

Before you begin, ensure you have the following installed on your system.

  * **Node.js and npm**: Required for managing project dependencies and running the local server. You can download them from [nodejs.org](https://nodejs.org/).

  * **Git**: Required for cloning the repository. You can download it from [git-scm.com](https://git-scm.com/).

  * **Rust & wasm-pack**: The core cryptography is written in Rust and compiled to WebAssembly. The easiest way to set this up is with the following commands:

    1.  **Install Rust** using `rustup` (the official toolchain installer):

        ```bash
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
        ```
        *(Follow the on-screen instructions to complete the installation.)*


    2.  **Install `wasm-pack`** to build the WebAssembly module:

        ```bash
        cargo install wasm-pack
        ```

-----

## Running Locally

Once the prerequisites are in place, you can get the project running with the following commands.

```bash
# 1. Clone the repository and enter the directory
git clone https://github.com/ciphernom/BitQuill.git
cd BitQuill

# 2. Install the JavaScript dependencies
npm install

# 3. Compile the Rust/WASM module and build the application
(cd vdf-wasm && wasm-pack build --target web --out-dir ../wasm --release) && npm run build

# 4. Start the local development server
npm run start
```

The application will now be running on your local machine, typically at **`http://localhost:8080`**.
   

## Technology Stack

-   **Cryptography**: Rust compiled to WebAssembly (WASM) for high-performance Verifiable Delay Functions.
-   **Frontend**: Vanilla JavaScript (ES6 Modules), HTML5, CSS3.
-   **Bundler**: Webpack 5.
-   **Text Editor**: Quill.js.

## License

This project is licensed under the GNU General Public License v3.0.
