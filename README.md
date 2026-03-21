# Tartarus Hasher

**An ultra-secure, memory-hard, and GPU-resistant Password Key Derivation Function (KDF) and CLI Tool.**

Tartarus is a state-of-the-art cryptographic hashing engine designed to protect user passwords against the most brutal hardware attacks (GPUs, ASICs, and FPGA clusters). Built on the foundational principles of modern KDFs like Argon2id, Tartarus forces attackers into a memory-bound labyrinth, making brute-force and dictionary attacks economically unfeasible.

## 🛡️ Why Tartarus? (The Merits)

Standard hashing algorithms like SHA-256 or SHA-512 are dangerously fast. A modern GPU cluster can guess billions of passwords per second. Tartarus levels the playing field by being **Memory-Hard**. 

Instead of just doing math, Tartarus allocates a massive pool of memory (128 MB by default) and forces the processor to jump unpredictably through it using a cryptographic sponge construction.

* **ASIC & GPU Resistant:** By requiring large, pseudo-random memory reads and writes, it bottlenecks the fast memory architectures of graphics cards.
* **Military-Grade Primitives:** Built on the proven **ChaCha20** stream cipher and **HMAC-SHA512**, completely avoiding homemade, untested ARX operations.
* **TMTO Defeated:** Implements an asymmetrical "Cross-Pass Labyrinth" that strictly prevents Time-Memory Trade-Off (TMTO) attacks. Attackers cannot compute the hash without paying the full memory cost.
* **Constant-Time Verification:** The built-in `tartarus_verify` function prevents side-channel timing attacks when comparing hashes during user login.
* **Strict Domain Separation:** Prevents length-extension and collision attacks between passwords, salts, and peppers.

## 🚀 Getting Started

### Prerequisites
You need a C compiler (`gcc`) and the OpenSSL development libraries installed on your system.
* **Linux:** `sudo apt install gcc libssl-dev`
* **Windows:** Use MSYS2 to install `mingw-w64-ucrt-x86_64-gcc` and `mingw-w64-ucrt-x86_64-openssl`.

### Compilation
Clone the repository and compile the `tartarus_cli.c` file:

```bash
gcc tartarus_cli.c -o tartarus_cli -O3 -lcrypto -Wno-deprecated-declarations
```
*(Note: `-Wno-deprecated-declarations` is used to silence OpenSSL 3.0 transition warnings regarding HMAC structures, ensuring a clean compilation).*

## 💻 Using Tartarus CLI

The `tartarus_cli` tool requires a **Pepper** (a global server-side secret) to operate. This ensures that even if your database is stolen, the hashes cannot be cracked without the server's environment variable.

### 1. Set your Pepper
Set the environment variable in your terminal before running the CLI:

**On Linux / macOS:**
```bash
export TARTARUS_PEPPER="Your_Ultra_Secure_Server_Secret_Key_Here"
```
**On Windows (PowerShell):**
```powershell
$env:TARTARUS_PEPPER="Your_Ultra_Secure_Server_Secret_Key_Here"
```

(On Windows you can also create this environment variable permanently by adding it to the user's section in the system's environment variables)

### 2. Hash a New Password (Registration)
To create a new user, simply pass the password to the `hash` command. Tartarus will automatically securely generate a 16-byte random salt.

```bash
./tartarus_cli hash "MySuperSecretPassword123!"
```
**Output:**
```text
[*] Hashing a new password...

[+] SUCCESS! NEW PASSWORD SUCCESSFULLY HASHED.
--------------------------------------------------------------------------------
Salt : 7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d
Hash : 629c26355d302c38a7023b685855e062708ada1d8290e621a... (128 chars)
--------------------------------------------------------------------------------
```
*You would then store the `Salt` and the `Hash` in your database.*

### 3. Verify a Password (Login)
To check if a user's password is correct, use the `verify` command followed by the password attempt, the saved salt, and the saved hash.

```bash
./tartarus_cli verify "MySuperSecretPassword123!" "7a8b9c0d..." "629c2635..."
```
**Output:**
```text
[*] Computing Hash for verification (Parameters: 128 MB, 3 Iterations)...

[+] ACCESS GRANTED: The password is valid! [MATCH]
```

## 🗺️ Roadmap

Tartarus is currently in version `v1.0.0`. Here is the roadmap for upcoming features and final 100% industrial certification:

- [ ] **Custom Salt Input for Hashing:** Update the CLI to allow hashing with a manually provided salt (e.g., `tartarus_cli hash <password> --salt <custom_salt>`). This is highly useful for specific backend server flows or database migrations.
- [ ] **Multi-threading (Lanes):** Implement `pthread` support to allow Tartarus to utilize multiple CPU cores simultaneously (similar to Argon2 lanes), improving execution speed for legitimate users while maintaining GPU resistance.
- [ ] **Formal Statistical Validation:** Generate a 1GB raw output stream to be run through the `dieharder` military statistical test suite to formally prove the avalanche effect and the absence of diffusion bias.
- [ ] **Shared Library Export (`.so` / `.dll`):** Separate the CLI from the core engine to allow easy bindings for Python, Node.js, Rust, and Go backends.
- [ ] **Formal Whitepaper Specification:** Publish the mathematical pseudo-code for independent cryptographic peer review.

## ⚠️ Disclaimer
*Tartarus is an advanced cryptographic research project. While it implements industry-standard primitives (ChaCha20, HMAC-SHA512) and best practices, it has not yet undergone a multi-year formal public audit. Do not use in critical production environments.*
```
