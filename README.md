# PQC Chart Tool - Post-Quantum Cryptography Chart Tool

A post-quantum cryptography dual signature tool based on NIST FIPS 204/203 standards, using Ed25519 signature, ML-KEM key encapsulation, and AES-GCM encryption.

## Core Principles

### Cryptographic Suite

| Component | Algorithm Standard | Go Standard Library | Description |
|-----------|-------------------|---------------------|-------------|
| **Persistent Identity** | Ed25519 | `crypto/ed25519` | Efficient elliptic curve signature, 64-byte signature |
| **Ephemeral Session** | ML-KEM-768 | `crypto/mlkem` | NIST FIPS 203, 1088-byte ciphertext |
| **Symmetric Encryption** | AES-256-GCM | `crypto/aead` | 32-byte key, derived from HKDF |
| **Key Derivation** | HKDF-SHA256 | `crypto/hkdf` | Derives session key from shared secret |

### Design Goals

1. **Forward security**: Ephemeral ML-KEM key pairs are destroyed immediately after use
2. **Dual verification**: Clients verify each other's identity mutually
3. **Quantum resistance**: ML-KEM provides quantum-safe key exchange
4. **Privacy protection**: Persistent private keys are stored encrypted, never appear in cleartext on the network

---

## Transport Architecture

### Two-Phase WebSocket Design

All communication uses WebSocket (`github.com/coder/websocket`). A connection is split into two phases, each using its own WebSocket:

```
┌──────────────────────────────────────────────────────────────────┐
│                    Two-Phase WebSocket Transport                  │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Phase 1 — Handshake WebSocket  (/ws/handshake)                  │
│  ┌──────────────┐                          ┌──────────────┐      │
│  │   Initiator  │                          │   Responder  │      │
│  │   (client)   │                          │   (server)   │      │
│  └──────┬───────┘                          └───────┬──────┘      │
│         │                                          │             │
│         │  WS Connect → ws://host:port/ws/handshake │             │
│         ├─────────────────────────────────────────->│             │
│         │                                          │             │
│         │  ML-KEM key exchange (3 messages)        │             │
│         │  Identity verification (6 messages)      │             │
│         │  All within this single WS, AES-GCM enc  │             │
│         │                                          │             │
│         │<─────────────────────────────────────────│ Session token│
│         │  MsgSessionToken(AES-GCM(sessionKey))    │ (one-time,   │
│         │                                          │  30s TTL)    │
│         │  WebSocket #1 closes                     │             │
│         │                                  ┌───────┘             │
│         │                                  │ Store: token→key    │
│         │                                  │ (SessionStore)      │
│         │                                                        │
│         │  ─ ─ ─ ─ ─ ─ ─ gap ─ ─ ─ ─ ─ ─ ─ ─                       │
│         │                                                        │
│  Phase 2 — Message WebSocket  (/ws/message?session=<token>)      │
│         │                                                          │
│         │  WS Connect → ws://host:port/ws/message?session=xxx     │
│         ├─────────────────────────────────────────->│             │
│         │                                          │             │
│         │  Server validates + consumes token        │             │
│         │  (one-time use, TTL expiry)               │             │
│         │                                          │             │
│         │  SecureChannel established                │             │
│         │  Encrypted application messages           │             │
│         │<────────────────────────────────────────->│             │
│         │                                          │             │
│         │  format: nonce(12B) + ciphertext + tag(16B)             │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

**Why two WebSocket connections?**

| Concern | Benefit |
|---------|---------|
| **Clean separation** | Handshake logic is isolated from message I/O; each WS has a single responsibility |
| **Token gate** | The message endpoint rejects any connection without a valid, unconsumed token |
| **Replay prevention** | Tokens are one-time use with 30-second TTL; an intercepted token is useless after first consumption |
| **Resource cleanup** | Phase 1 WS closes immediately after token issuance; Phase 2 WS is the only long-lived connection |

### Session Token Lifecycle

```
  Handshake completes           Token consumed
        │                             │
        ▼                             ▼
┌───────────────┐   /ws/message   ┌──────────┐
│  SessionStore │   ?session=xxx  │  Deleted  │
│  token → key  │<────────────────│  (one-time)│
│  TTL: 30s     │   Consume()     └──────────┘
└───────────────┘
        │
        │  30s elapsed, unconsumed
        ▼
   Expired & purged
```

- **32 bytes** crypto-random, hex-encoded for URL safety
- **Encrypted** with `AES-GCM(sessionKey, token)` before sending over Phase 1 WS
- **One-time use**: `Consume()` deletes the token atomically; a second connection with the same token fails
- **TTL-bound**: expires after 30 seconds regardless of consumption

---

## Protocol Flow

### Overall Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         PQC Dual Signature Protocol                     │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  Phase 1: Bidirectional ML-KEM Encapsulation (Establish Encrypted Pipe) │
│   ┌──────────────┐                    ┌──────────────┐                  │
│   │  Client A    │                    │  Client B    │                  │
│   └──────┬───────┘                    └───────┬──────┘                  │
│          │                                    │                         │
│          │  ① HandshakeRequest (pubA)         │                         │
│          ├───────────────────────────────────>│                         │
│          │                                    │                         │
│          │  ② HandshakeAgree (pubB, ctA)      │                         │
│          │<───────────────────────────────────┤                         │
│          │                                    │                         │
│          │  ③ HandshakeFinish (ctB)           │                         │
│          ├───────────────────────────────────>│                         │
│          │                                    │                         │
│          │    Bidirectional shared secret established: ss_A2B, ss_B2A   │
│          │    Derive session key: session_key = HKDF(ss_A2B || ss_B2A)  │
│                                                                         │
│  Phase 2: Bidirectional Identity Verification (Within Encrypted Pipe)   │
│   ┌──────────────┐                   ┌──────────────┐                   │
│   │  Client A    │                   │  Client B    │                   │
│   └──────┬───────┘                   └───────┬──────┘                   │
│          │                                   │                           │
│          │  ④ IdentityMsg (EncDSA_pubA)      │                           │
│          ├──────────────────────────────────>│                           │
│          │                                   │                           │
│          │  ⑤ Challenge (Enc_nonce_B)        │                           │
│          │<──────────────────────────────────┤                           │
│          │                                   │ Verify: Verify(pubA, nonce_B│
│          │  ⑥ SignatureResponse (Enc_sig_A)  │              || binding, sig_A)│
│          ├──────────────────────────────────>│                           │
│          │                                   │                           │
│          │  ⑦ IdentityMsg (EncDSA_pubB)      │                           │
│          │<──────────────────────────────────┤                           │
│          │                                   │                           │
│          │  ⑧ Challenge (Enc_nonce_A)        │                           │
│          ├──────────────────────────────────>│                           │
│          │                                   │                           │
│          │  ⑨ SignatureResponse (Enc_sig_B)  │                           │
│          │<──────────────────────────────────┤                           │
│          │ Verify: Verify(pubB, nonce_A      │                           │
│          │        || binding, sig_B)         │                           │
│          │                                   │                           │
│  Token Handoff: Server issues one-time session token (encrypted)         │
│   │  ⑩ MsgSessionToken(AES-GCM(token))      │                           │
│   │<─────────────────────────────────────────│                           │
│   │  WS #1 closes                           │                           │
│                                                                         │
│   Phase 3: Encrypted Data Transfer (new WebSocket with session token)   │
│   ┌──────────────┐                   ┌──────────────┐                    │
│   │  Client A    │                   │  Client B    │                    │
│   └──────┬───────┘                   └───────┬──────┘                    │
│         │  WS Connect: /ws/message?session=xxx                          │
│         ├───────────────────────────────────>│                           │
│         │  Token validated + consumed        │                           │
│         │                                   │                            │
│         │  ⑪ EncryptedData                  │                            │
│         ├──────────────────────────────────>│                            │
│         │  Format: nonce(12B) + ciphertext + tag(16B)                    │
│         │                                   │                            │
│         │  ⑫ EncryptedData                  │                            │
│         │<──────────────────────────────────┤                            │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## Detailed Process Description

### Phase 1: Bidirectional ML-KEM Encapsulation (Establish Encrypted Pipe)

```
Goal: Establish shared key on insecure network, ensuring forward security

Step 1: Initiator sends ephemeral public key
┌─────────────┐
│  Client A   │
└──────┬──────┘
       │ Generate ephemeral ML-KEM key pair (tmp_priv_A, tmp_pub_A)
       │
       │ HandshakeRequest {
       │   KEMPublicKey: tmp_pub_A        // 1184 bytes
       │   AlgorithmSuite: "ML-KEM-768"
       │ }
       │
       ├─────────────────────────────────────────>
       │                                          │
       │                          ┌─────────────┐ │
       │                          │  Client B   │ │
       │                          └──────┬──────┘ │
       │                                 │        │

Step 2: Responder encapsulates and sends own public key
                                          │ Generate ephemeral key pair (tmp_priv_B, tmp_pub_B)
                                          │ Encapsulate using tmp_pub_A: ct_A, ss_B2A
                                          │
       │<────────────────────────────────│ HandshakeAgree {
       │                                  │   KEMPublicKey: tmp_pub_B   // 1184 bytes
       │                                  │   PeerCiphertext: ct_A      // 1088 bytes
       │                                  │ }
       │                                  │
       │  Decapsulate ct_A using tmp_priv_B
       │  Obtain ss_B2A                    │ Save ss_B2A (shared secret)

Step 3: Initiator completes encapsulation
       │ Encapsulate using tmp_pub_B: ct_B, ss_A2B
       │
       │ HandshakeFinish {
       │   Ciphertext: ct_B                // 1088 bytes
       │ }
       │
       ├─────────────────────────────────>│
       │                                    │ Save ss_A2B
       │                                    │
       │ Save ss_A2B                        │
       │                                    │
       ▼                                    ▼
    Derive session key                  Derive session key
    session_key = HKDF(ss_B2A || ss_A2B)   session_key = HKDF(ss_B2A || ss_A2B)
                                             │
                          ┌──────────────────┴──────────────────┐
                          │   Encrypted pipe established       │
                          │   - All subsequent messages encrypted
                          │   - Ephemeral private keys securely wiped
                          └─────────────────────────────────────┘
```

**Key Features:**
- **Forward security**: Ephemeral keys are wiped immediately after use
- **Bidirectional contribution**: Both parties contribute to the shared key, preventing unilateral control
- **Key separation**: ss_A2B and ss_B2A are derived independently, enhancing security
- **Channel binding**: `ChannelBinding() = initiator_pub || responder_pub` — canonical ordering on both sides, included in identity signatures to bind verification to this specific session

---

### Phase 2: Bidirectional Identity Verification (Within Encrypted Pipe)

```
Prerequisites:
- Session key session_key is established
- Both parties have exchanged peer ID_Hash (SHAKE-256 hash of persistent public key) via out-of-band method

Step 4-6: Client A verifies Client B's identity

┌─────────────┐                          ┌─────────────┐
│  Client A   │                          │  Client B   │
└──────┬──────┘                          └──────┬──────┘
       │                                         │
       │ Send persistent Ed25519 public key (encrypted)
       │ IdentityMsg {                           │
       │   PublicKeyEncrypted: AES-GCM(DSA_pub_A)│
       │ }                                       │
       ├────────────────────────────────────────>│
       │                                         │
       │                                         │ Decrypt to obtain DSA_pub_A
       │                                         │ Verify: SHAKE256(DSA_pub_A) == peer_id_hash_A
       │                                         │ ✓ Identity confirmed
       │                                         │
       │                                         │ Generate random challenge nonce_B (32 bytes)
       │                                         │ Store plaintext nonce_B for verification
       │                                         │
       │                                         │ Challenge {
       │<────────────────────────────────────────│   NonceEncrypted: AES-GCM(nonce_B)
       │                                         │ }
       │                                         │
       │ Decrypt to obtain nonce_B               │
       │                                         │
       │ Sign challenge:                         │
       │ message = nonce_B || channelBinding     │
       │         || sessionID                    │
       │ sig_A = Ed25519Sign(DSA_priv_A, message)│
       │                                         │
       │ SignatureResponse {                     │
       │   SignatureEncrypted: AES-GCM(sig_A)   │
       │ }                                       │
       ├────────────────────────────────────────>│
       │                                         │
       │                                         │ Decrypt to obtain sig_A
       │                                         │ Reconstruct message with stored nonce_B
       │                                         │ Verify: Ed25519Verify(DSA_pub_A, message, sig_A)
       │                                         │ ✓ Signature valid → Client A identity confirmed
       │                                         │


Step 7-9: Client B verifies Client A's identity (symmetric process)

       │                                         │ Send persistent Ed25519 public key (encrypted)
       │<────────────────────────────────────────│ IdentityMsg {
       │                                         │   PublicKeyEncrypted: AES-GCM(DSA_pub_B)
       │                                         │ }
       │                                         │
       │ Decrypt to obtain DSA_pub_B              │
       │ Verify: SHAKE256(DSA_pub_B) == peer_id_hash_B
       │ ✓ Identity confirmed                    │
       │                                         │
       │ Generate random challenge nonce_A        │
       │ Store plaintext nonce_A for verification │
       │                                         │
       │ Challenge {                             │
       │   NonceEncrypted: AES-GCM(nonce_A)      │
       │ }                                       │
       ├────────────────────────────────────────>│
       │                                         │
       │                                         │ Decrypt to obtain nonce_A
       │                                         │ Sign challenge
       │                                         │
       │                                         │ SignatureResponse {
       │<────────────────────────────────────────│   SignatureEncrypted: AES-GCM(sig_B)
       │                                         │ }
       │                                         │
       │ Decrypt to obtain sig_B                  │
       │ Reconstruct message with stored nonce_A  │
       │ Verify: Ed25519Verify(DSA_pub_B, message, sig_B)
       │ ✓ Signature valid → Client B identity confirmed
       │                                         │
       ▼                                         ▼
    ┌──────────────────────────────────────────────────┐
    │         Bidirectional identity verification completed
    │   ✓ Both parties confirmed each other's persistent public key
    │   ✓ Both parties proved ownership of private key
    │   ✓ Challenge-response mechanism prevents replay attacks
    │   ✓ Channel binding ensures session integrity
    └──────────────────────────────────────────────────┘
```

**Security Features:**
- **Verification within encrypted pipe**: Persistent public keys are only transmitted within encrypted pipe, preventing eavesdropping
- **Out-of-band hash verification**: ID_Hash is exchanged via out-of-band method, preventing man-in-the-middle attacks
- **Challenge-response**: Uses random 32-byte nonce, making each signature unique and preventing replay
- **Channel binding**: Signature includes `initiator_pub || responder_pub`, binding to specific session

### Token Handoff

After Phase 2 completes, the responder (server) issues a session token:

```
       │                                         │
       │  Generate 32-byte random token           │
       │  Store: token → sessionKey (TTL 30s)     │
       │                                         │
       │  Encrypt: AES-GCM(sessionKey, token)     │
       │                                         │
       │  MsgSessionToken {                       │
       │<────────────────────────────────────────│   EncryptedToken: AES-GCM(token)
       │  }                                       │
       │                                         │
       │  Decrypt with sessionKey → token         │
       │  WebSocket #1 closes                     │
       │                                          │
```

---

### Phase 3: Encrypted Data Transfer (New WebSocket)

```
Client opens a new WebSocket connection using the session token:

       │  WS Connect: /ws/message?session=<token>  │
       ├──────────────────────────────────────────->│
       │                                           │
       │                                           │ Consume token (one-time, TTL check)
       │                                           │ Retrieve sessionKey
       │                                           │ ✓ Token valid → upgrade to WS
       │                                           │
       │  SecureChannel established                 │
       │                                           │

Data format: Each message is independently encrypted with AES-256-GCM

Sender encryption process:
┌─────────────┐
│  Client A   │
└──────┬──────┘
       │ plaintext = "Hello secure world"
       │
       │ Generate random nonce (12 bytes)
       │
       │ ciphertext = AES-GCM-Seal(
       │   key: session_key,
       │   nonce: random_nonce,
       │   plaintext: plaintext
       │ ) → nonce || ciphertext || tag(16B)
       │
       ├─────────────────────────────────────────>
       │                                          │


Receiver decryption process:
                                              ┌─────────────┐
                                              │  Client B   │
                                              └──────┬──────┘
                                                     │
                                                     │ Parse: nonce (12B) || ciphertext || tag (16B)
                                                     │
                                                     │ plaintext = AES-GCM-Open(
                                                     │   key: session_key,
                                                     │   nonce: nonce,
                                                     │   ciphertext: ciphertext,
                                                     │   tag: tag
                                                     │ )
                                                     │
                                                     │ ✓ Decrypt successfully, obtain plaintext
                                                     │ ✗ Decrypt failed (authentication failed) → Reject message
                                                     │
                          ┌──────────────────────────┴──────────────────┐
                          │   Features of each message                 │
                          │   • Independent random nonce, preventing pattern analysis
                          │   • AEAD authentication tag, detecting tampering
                          │   • Decrypt failure results in discarding, leaking no information
                          └─────────────────────────────────────────────┘
```

---

## Key Management

### Key Types and Purposes

```
┌────────────────────────────────────────────────────────────────┐
│                        Key Types                                │
├────────────────────────────────────────────────────────────────┤
│                                                                 │
│  1. Persistent Identity Key Pair (Ed25519)                     │
│     ┌─────────────────────────────────────────────────┐       │
│     │  Purpose: Long-term identity verification        │       │
│     │  Generation: Generated once at client startup    │       │
│     │  Storage: Private key stored encrypted           │       │
│     │  Distribution: Exchange ID_Hash = SHAKE256(pub)  │       │
│     │  Lifecycle: Permanent (unless manually revoked)  │       │
│     └─────────────────────────────────────────────────┘       │
│                                                                 │
│  2. Ephemeral Session Key Pair (ML-KEM-768)                    │
│     ┌─────────────────────────────────────────────────┐       │
│     │  Purpose: Single handshake, derive session key  │       │
│     │  Generation: Dynamically generated per handshake│       │
│     │  Storage: Memory only, destroyed after use      │       │
│     │  Distribution: Transmitted in cleartext in handshake messages (safe)
│     │  Lifecycle: Single handshake (forward security) │       │
│     └─────────────────────────────────────────────────┘       │
│                                                                 │
│  3. Session Key (AES-256-GCM)                                  │
│     ┌─────────────────────────────────────────────────┐       │
│     │  Purpose: Data transfer within encrypted pipe   │       │
│     │  Generation: HKDF(ss_A2B || ss_B2A)             │       │
│     │  Storage: Memory only, destroyed after session  │       │
│     │  Distribution: Not transmitted, derived independently   │
│     │  Lifecycle: Single session                      │       │
│     └─────────────────────────────────────────────────┘       │
│                                                                 │
│  4. Session Token (One-Time, TTL-Bound)                        │
│     ┌─────────────────────────────────────────────────┐       │
│     │  Purpose: Authorize Phase 2 message WS          │       │
│     │  Generation: 32 bytes crypto-random             │       │
│     │  Storage: In-memory SessionStore (token→key)     │       │
│     │  Distribution: AES-GCM(sessionKey, token) via WS │       │
│     │  Lifecycle: Single use, 30-second TTL            │       │
│     └─────────────────────────────────────────────────┘       │
│                                                                 │
└────────────────────────────────────────────────────────────────┘
```

### ID_Hash Calculation and Distribution

```
When generating identity:
┌─────────────────────────┐
│  Generate Ed25519 key pair│
│  (priv, pub)             │
└──────────┬──────────────┘
           │
           ▼
    ┌──────────────┐
    │ Calculate ID_Hash│
    │ SHAKE256(pub)│
    └──────┬───────┘
           │
           ▼
    ┌─────────────────────────┐
    │  Local storage          │
    │  • pub: Cleartext .pub file│
    │  • priv: Encrypted .priv file│
    │  • id_hash: Displayed to user│
    └─────────────────────────┘

Out-of-band distribution:
┌───────────────┐              ┌───────────────┐
│  Client A    │              │  Client B    │
│  ID_Hash:    │              │  ID_Hash:    │
│  a1b2c3...   │              │  d4e5f6...   │
└───────┬───────┘              └───────┬───────┘
         │                              │
         │  Exchange via secure channel│
         │  (SMS, email, in-person, etc.)│
         │                              │
         ├──────────────────────────────>│
         │  Obtain peer's ID_Hash       │
         │                              │
         ▼                              ▼
   Verification: SHAKE256(peer_pub) == peer_id_hash
```

---

## Security Features

### 1. Forward Security
- Ephemeral ML-KEM key pairs are regenerated for each handshake
- Ephemeral private keys are securely wiped after handshake completion
- Historical communications cannot be decrypted even if recorded

### 2. Quantum Resistance
- ML-KEM-768 is based on Module-LWE problem, no known polynomial algorithm on quantum computers
- Can seamlessly switch to ML-DSA in the future (when Go standard library is available)

### 3. Replay Attack Prevention
- Challenge-response mechanism uses random 32-byte nonce
- Session tokens are one-time use with 30-second TTL
- Token is encrypted with session key before transmission

### 4. Man-in-the-Middle Attack Prevention
- Out-of-band ID_Hash exchange verifies persistent public key
- Channel binding (`initiator_pub || responder_pub`) binds signature to specific session

### 5. Perfect Forward Secrecy
- Session key is derived from contributions from both parties
- Single-party compromise cannot derive historical session keys

---

## Installation

```bash
# Build
./build.sh

# Or use go build directly
go build -o bin/pqc-chart-tool ./cmd/pqc-chart-tool
```

## Usage

### Operation Modes

The tool supports automatic mode detection based on provided parameters:

1. **Server mode** (default): Starts WebSocket server for incoming connections
2. **Client mode**: Connects to a peer when `-c` and `-p` are specified
3. **Generate mode**: Generates a new identity keypair with `-g`
4. **Show ID mode**: Displays your ID hash with `-i`

### Detailed Usage Examples

#### 1. Server Mode (No Parameters)
Start server mode that accepts any incoming connection:

```bash
pqc-client
```

This will:
- Auto-generate identity if none exists
- Listen on port 18080 (default) via WebSocket
- Accept connections from any peer
- Display your ID hash for sharing

#### 2. Server Mode (Specific Peer)
Start server mode that only accepts connections from a specific peer:

```bash
pqc-client -p <peer-id-hash>
```

Example:
```bash
pqc-client -p d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3
```

#### 3. Server Mode (Custom Port)
Start server mode on a custom port:

```bash
pqc-client --port 19090
```

Or with specific peer:
```bash
pqc-client -p <peer-id-hash> --port 19090
```

#### 4. Client Mode (Interactive Chat)
Connect to a peer for interactive chat:

```bash
pqc-client -c <target> -p <peer-id-hash>
```

Where `<target>` is a WebSocket URL or host address:
- `192.168.1.100` — auto-expanded to `ws://192.168.1.100:18080`
- `192.168.1.100:19090` — auto-expanded to `ws://192.168.1.100:19090`
- `ws://192.168.1.100:19090` — used as-is

Examples:
```bash
# Connect to default port (auto-expanded to ws://)
pqc-client -c 192.168.1.100 -p a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3

# Connect with explicit port
pqc-client -c 192.168.1.100:19090 -p a1b2c3...

# Full WebSocket URL
pqc-client -c ws://relay.example.com:8080 -p a1b2c3...
```

#### 5. Client Mode (Single Message)
Send a single message and exit:

```bash
pqc-client -c <target> -p <peer-id-hash> -m "Hello World"
```

This will:
- Connect to the peer via two-phase WebSocket
- Send the specified message
- Wait for and display the response
- Exit after receiving the response

#### 6. Generate Identity
Generate a new Ed25519 keypair:

```bash
pqc-client -g
```

This will:
- Generate a new Ed25519 key pair
- Calculate and display your ID hash (32-byte hex string)
- Prompt for a master password to encrypt the private key
- Store keys in `~/.pqc-client/` directory

#### 7. Show ID Hash
Display your current ID hash:

```bash
pqc-client -i
```

This will:
- Prompt for your master password
- Decrypt and load your identity
- Display your ID hash for sharing with peers

#### 8. Accept Any Peer (Server Mode)
Start server mode that accepts connections from any peer:

```bash
pqc-client --accept
```

Or with custom port:
```bash
pqc-client --accept --port 19090
```

### Complete Workflow Example

**Terminal 1 - Server:**
```bash
# First time: generate identity
pqc-client -g
# Output: Your ID Hash: a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3

# Start server (now auto-generates if needed)
pqc-client
# Output: WebSocket server listening on 0.0.0.0:18080
#         Your ID Hash: a1b2c3...
#         Waiting for incoming connections...
```

**Terminal 2 - Client:**
```bash
# First time: generate identity
pqc-client -g
# Output: Your ID Hash: d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3

# Connect to server (interactive chat)
pqc-client -c 127.0.0.1 -p a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3

# Or send a single message
pqc-client -c 127.0.0.1 -p a1b2c3... -m "Hello from client!"
# Output: Response: Hello from server!
```

### Connection Flow (Internal)

When a client connects, the following happens automatically:

```
1. Normalize target URL
   "192.168.1.100" → "ws://192.168.1.100:18080"
   "192.168.1.100:19090" → "ws://192.168.1.100:19090"

2. Phase 1 — Handshake WebSocket
   Dial ws://host:port/ws/handshake
   ├─ ML-KEM key exchange (3 messages)
   ├─ Identity verification (6 messages)
   └─ Receive encrypted session token
   WebSocket #1 closes

3. Phase 2 — Message WebSocket
   Dial ws://host:port/ws/message?session=<token>
   ├─ Server validates + consumes token
   └─ SecureChannel established for encrypted messaging
```

### Command Line Options

| Option | Short | Description | Default |
|--------|-------|-------------|---------|
| `--generate` | `-g` | Generate new identity keypair | - |
| `--show-id` | `-i` | Display your ID hash | - |
| `--connect` | `-c` | Connect to peer (client mode) | - |
| `--peer` | `-p` | Peer ID hash | - |
| `--message` | `-m` | Send single message (client mode) | - |
| `--port` | `-P` | Listening port (server mode) | 18080 |
| `--accept` | `-a` | Accept any peer (server mode) | false |
| `--help` | `-h` | Show help message | - |

## Development Notes

### Project Structure
```
pqc-chart-tool/
├── cmd/pqc-chart-tool/          # Main program entry point
│   ├── cli.go                   # CLI flag parsing
│   ├── commands.go              # Server/client command orchestration
│   ├── interactive.go           # Interactive chat loop
│   ├── integration_test.go      # Crypto/identity unit tests
│   └── ws_integration_test.go   # End-to-end PQC handshake + message test
├── pkg/
│   ├── crypto/                  # Cryptographic primitives
│   │   ├── mlkem.go             # ML-KEM-768 encapsulation/decapsulation
│   │   ├── mldsa.go             # Ed25519 signature (ML-DSA placeholder)
│   │   ├── aesgcm.go            # AES-GCM encryption
│   │   ├── kdf.go               # HKDF, SHAKE-256
│   │   └── memory.go            # Sensitive memory wiping
│   ├── protocol/                # Protocol state machine
│   │   ├── handshake.go         # ML-KEM handshake + ChannelBinding()
│   │   ├── messages.go           # Message definitions (incl. SessionTokenMsg)
│   │   └── fragment.go          # Fragment processing
│   ├── identity/                # Identity management
│   │   ├── store.go             # Key storage
│   │   └── verifier.go          # Identity verification (challenge-response)
│   ├── client/                  # Client-side orchestration
│   │   ├── client.go            # Handshake initiator/responder + WS Connect
│   │   └── channel.go           # SecureChannel (Transport + sessionKey)
│   └── transport/               # Transport layer
│       ├── ws.go                # Two-phase WS: WSTransport, SessionStore, WSServer, WSDial
│       └── ws_test.go           # WS transport tests
├── go.mod
├── Makefile
└── README.md
```

### Implementation Status
- ✅ ML-KEM-768: Using Go standard library `crypto/mlkem`
- ✅ Ed25519 signature: Using Go standard library `crypto/ed25519`
- ✅ AES-256-GCM: Using Go standard library `crypto/aead`
- ✅ Complete handshake protocol: Bidirectional ML-KEM + identity verification
- ✅ Two-phase WebSocket transport: Handshake WS + message WS with session token
- ✅ Session token: One-time use, 30s TTL, AES-GCM encrypted
- ✅ Channel binding: Canonical `initiator_pub || responder_pub` ordering
- ✅ Fragment processing: Supports large message fragmentation
- ✅ Test coverage: Unit tests + end-to-end PQC integration test

### Testing
```bash
# Run all tests
make test

# Run specific package tests
go test -v ./pkg/crypto/...

# Run end-to-end integration test
go test -v -run TestWSFullHandshake ./cmd/pqc-chart-tool/
```

## Tech Stack
- **Language**: Go 1.26.2
- **PQC algorithm**: ML-KEM-768 (FIPS 203)
- **Signature algorithm**: Ed25519 (temporary replacement for ML-DSA)
- **Symmetric encryption**: AES-256-GCM
- **Transport**: WebSocket (`github.com/coder/websocket`)
- **WS endpoints**: `/ws/handshake` (Phase 1), `/ws/message?session=<token>` (Phase 2)

## Security Notes

1. **Before Production Deployment**:
   - Review all cryptographic implementations
   - Conduct independent security audit
   - Test edge cases and error handling

2. **Key Management**:
   - Protect master password (used to encrypt stored private keys)
   - Regularly backup key files
   - Revoke compromised identities

3. **Out-of-Band Exchange**:
   - Use secure channel to exchange ID_Hash
   - Carefully verify when confirming ID_Hash
   - Prevent social engineering attacks

## License

This project is for learning and research purposes only. Before using in production environments, please conduct a comprehensive security audit.
