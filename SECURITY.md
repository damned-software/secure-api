# Secure API - Maximum Security Implementation

## Overview

ระบบ API ที่มีความปลอดภัยสูงสุด ป้องกันการโจมตีหลายรูปแบบ

```
┌─────────────────────────────────────────────────────────────────┐
│                    Security Architecture                        │
├─────────────────────────────────────────────────────────────────┤
│  🔐 ECDH Key Exchange          → Perfect Forward Secrecy        │
│  🔏 ECDSA Digital Signatures   → Anti-MITM                      │
│  🔒 AES-256-GCM Encryption     → Data Protection                │
│  🎫 Challenge-Response Auth    → Anti-Fake-Client               │
│  🔄 Nonce + Timestamp + Seq    → Anti-Replay                    │
│  📍 Session Fingerprint        → Anti-Hijacking                 │
└─────────────────────────────────────────────────────────────────┘
```

---

## Security Features

### 1. 🔐 ECDH Key Exchange (Perfect Forward Secrecy)

**วัตถุประสงค์:** สร้าง shared secret ที่ไม่สามารถ decrypt ได้แม้ private key จะรั่วไหลในอนาคต

**Algorithm:** `prime256v1` (P-256)

**การทำงาน:**
```
Client                              Server
  │                                    │
  │  Generate ECDH Key Pair            │  Generate ECDH Key Pair
  │  (clientPublicKey, clientPrivKey)  │  (serverPublicKey, serverPrivKey)
  │                                    │
  │────── clientPublicKey ────────────►│
  │                                    │
  │◄───── serverPublicKey ─────────────│
  │                                    │
  │  sharedSecret = ECDH(              │  sharedSecret = ECDH(
  │    clientPrivKey,                  │    serverPrivKey,
  │    serverPublicKey                 │    clientPublicKey
  │  )                                 │  )
  │                                    │
  └──── ทั้งสองฝั่งได้ sharedSecret เดียวกัน ────┘
```

**Code:**
```javascript
export function generateKeyPair() {
  const ecdh = crypto.createECDH(CONFIG.curve);
  ecdh.generateKeys();
  return {
    publicKey: ecdh.getPublicKey('base64'),
    privateKey: ecdh.getPrivateKey('base64')
  };
}

export function deriveSharedSecret(privateKey, peerPublicKey) {
  const ecdh = crypto.createECDH(CONFIG.curve);
  ecdh.setPrivateKey(Buffer.from(privateKey, 'base64'));
  const shared = ecdh.computeSecret(Buffer.from(peerPublicKey, 'base64'));
  return crypto.createHash('sha256').update(shared).digest();
}
```

---

### 2. 🔏 ECDSA Digital Signatures (Anti-MITM)

**วัตถุประสงค์:** ป้องกัน Man-in-the-Middle attack โดยการ sign ทุก message

**Algorithm:** `ECDSA` with `SHA-256`

**การทำงาน:**
```
┌──────────────────────────────────────────────────────────────────┐
│                        Message Signing                           │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Sender:                                                         │
│  ┌─────────────────┐    ┌─────────────────┐                     │
│  │   Message       │───►│  Sign with      │───► signature       │
│  │   (encrypted)   │    │  Private Key    │                     │
│  └─────────────────┘    └─────────────────┘                     │
│                                                                  │
│  Receiver:                                                       │
│  ┌─────────────────┐    ┌─────────────────┐                     │
│  │   Message +     │───►│  Verify with    │───► valid/invalid   │
│  │   signature     │    │  Public Key     │                     │
│  └─────────────────┘    └─────────────────┘                     │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

**Code:**
```javascript
export function generateSigningKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: CONFIG.signCurve,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  });
  return { publicKey, privateKey };
}

export function sign(data, privateKey) {
  const signer = crypto.createSign('SHA256');
  const payload = typeof data === 'string' ? data : JSON.stringify(data);
  signer.update(payload);
  return signer.sign(privateKey, 'base64');
}

export function verify(data, signature, publicKey) {
  try {
    const verifier = crypto.createVerify('SHA256');
    const payload = typeof data === 'string' ? data : JSON.stringify(data);
    verifier.update(payload);
    return verifier.verify(publicKey, signature, 'base64');
  } catch {
    return false;
  }
}
```

---

### 3. 🔒 AES-256-GCM Encryption

**วัตถุประสงค์:** เข้ารหัสข้อมูลทั้งหมดระหว่าง Client และ Server

**Algorithm:** `AES-256-GCM` (Authenticated Encryption)

**Parameters:**
- Key Size: 256 bits
- IV Length: 12 bytes (96 bits)
- Auth Tag Length: 16 bytes (128 bits)

**Message Structure:**
```javascript
{
  iv: "base64...",      // Initialization Vector (random)
  data: "base64...",    // Encrypted ciphertext
  tag: "base64...",     // Authentication tag
  nonce: "uuid",        // Unique identifier
  ts: 1772434124843,    // Timestamp
  seq: 1,               // Sequence number
  sig: "base64..."      // ECDSA signature
}
```

**Code:**
```javascript
export function encrypt(payload, sharedSecret, sequence = 0) {
  const plaintext = typeof payload === 'object' 
    ? JSON.stringify(payload) 
    : String(payload);

  const iv = crypto.randomBytes(CONFIG.ivLength);
  const nonce = uuidv4();
  const timestamp = Date.now();

  const cipher = crypto.createCipheriv(CONFIG.algorithm, sharedSecret, iv, {
    authTagLength: CONFIG.authTagLength
  });

  // AAD protects nonce, timestamp, and sequence from tampering
  const aad = Buffer.from(JSON.stringify({ nonce, timestamp, sequence }));
  cipher.setAAD(aad);

  const ciphertext = Buffer.concat([
    cipher.update(plaintext, 'utf8'),
    cipher.final()
  ]);

  return {
    iv: iv.toString('base64'),
    data: ciphertext.toString('base64'),
    tag: cipher.getAuthTag().toString('base64'),
    nonce,
    ts: timestamp,
    seq: sequence
  };
}
```

---

### 4. 🎫 Challenge-Response Authentication (Anti-Fake-Client)

**วัตถุประสงค์:** ป้องกัน client ปลอมที่พยายามสร้าง session

**การทำงาน:**
```
Client                                   Server
  │                                         │
  │  1. Request Init                        │
  │────────────────────────────────────────►│
  │                                         │  Generate random challenge
  │◄────────────────────────────────────────│
  │         challenge (32 bytes random)     │
  │                                         │
  │  2. Sign challenge with private key     │
  │  signature = sign(challenge, privKey)   │
  │                                         │
  │─────── challenge + signature ──────────►│
  │                                         │  3. Verify signature
  │                                         │  verify(challenge, sig, pubKey)
  │                                         │
  │                                         │  If valid: Create session
  │◄────── sessionId + fingerprint ─────────│  If invalid: Reject
  │                                         │
```

**Server Validation:**
```javascript
// Step 3: Complete authentication with challenge-response
app.post('/auth/session', (req, res) => {
  const { 
    clientEcdhPublicKey, 
    clientSigningPublicKey, 
    challenge,
    challengeSignature
  } = req.body;

  // Verify client signed the challenge (proves client has private key)
  const isValid = verify(challenge, challengeSignature, clientSigningPublicKey);
  if (!isValid) {
    console.log('⚠️  Challenge verification failed - fake client detected');
    return res.status(403).json({ error: 'Challenge verification failed' });
  }

  // Create session...
});
```

---

### 5. 🔄 Replay Attack Prevention

**วัตถุประสงค์:** ป้องกันการ capture และส่ง request เดิมซ้ำ

**3 Layers Protection:**

| Layer | Method | Protection |
|-------|--------|------------|
| 1 | **Timestamp** | Request ต้องไม่เกิน 30 วินาที |
| 2 | **Nonce (UUID)** | Unique identifier ที่ใช้ได้ครั้งเดียว |
| 3 | **Sequence Number** | ลำดับที่ต้องเพิ่มขึ้นเสมอ |

**Code:**
```javascript
export class NonceValidator {
  validate(nonce, timestamp, sessionId = null, sequence = null) {
    const now = Date.now();
    
    // 1. Check timestamp (time-based validation)
    if (Math.abs(now - timestamp) > CONFIG.timestampTolerance) {
      return { valid: false, error: 'Request expired (timestamp out of range)' };
    }

    // 2. Check nonce (prevents exact replay)
    if (this.usedNonces.has(nonce)) {
      return { valid: false, error: 'Duplicate nonce (replay attack prevented)' };
    }

    // 3. Check sequence number (prevents out-of-order replay)
    if (sessionId !== null && sequence !== null) {
      const lastSeq = this.sequences.get(sessionId) || 0;
      
      if (sequence <= lastSeq) {
        return { valid: false, error: 'Invalid sequence (replay or out-of-order)' };
      }
      
      this.sequences.set(sessionId, sequence);
    }

    // Mark nonce as used
    this.usedNonces.set(nonce, timestamp);
    return { valid: true };
  }
}
```

---

### 6. 📍 Session Fingerprint Binding (Anti-Hijacking)

**วัตถุประสงค์:** ป้องกันการขโมย session ID ไปใช้

**Fingerprint Generation:**
```javascript
export function generateClientFingerprint(clientPublicKey, signingPublicKey, userAgent = '') {
  const data = `${clientPublicKey}:${signingPublicKey}:${userAgent}`;
  return crypto.createHash('sha256').update(data).digest('hex');
}
```

**Validation:**
```javascript
// In secureEndpoint middleware
if (session.fingerprint !== clientFingerprint) {
  console.log('⚠️  Fingerprint mismatch - possible session hijacking');
  return res.status(403).json({ error: 'Session binding failed' });
}
```

---

## Authentication Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Complete Authentication Flow                         │
└─────────────────────────────────────────────────────────────────────────────┘

Client                                                              Server
  │                                                                    │
  │  ┌──────────────────────────────────┐                             │
  │  │ 1. Generate Keys                 │                             │
  │  │    - ECDH key pair (encryption)  │                             │
  │  │    - ECDSA key pair (signing)    │                             │
  │  └──────────────────────────────────┘                             │
  │                                                                    │
  │  POST /auth/init                                                  │
  │  { clientEcdhPublicKey, clientSigningPublicKey, clientId }        │
  │───────────────────────────────────────────────────────────────────►│
  │                                                                    │
  │                                      ┌─────────────────────────┐  │
  │                                      │ Generate challenge      │  │
  │                                      │ (32 bytes random)       │  │
  │                                      └─────────────────────────┘  │
  │                                                                    │
  │◄───────────────────────────────────────────────────────────────────│
  │  { challenge, serverEcdhPublicKey, serverSigningPublicKey }       │
  │                                                                    │
  │  ┌──────────────────────────────────┐                             │
  │  │ 2. Sign Challenge                │                             │
  │  │    sig = sign(challenge, privKey)│                             │
  │  └──────────────────────────────────┘                             │
  │                                                                    │
  │  POST /auth/session                                               │
  │  { ..., challenge, challengeSignature }                           │
  │───────────────────────────────────────────────────────────────────►│
  │                                                                    │
  │                                      ┌─────────────────────────┐  │
  │                                      │ 3. Verify Challenge     │  │
  │                                      │ 4. Derive Shared Secret │  │
  │                                      │ 5. Create Session       │  │
  │                                      │ 6. Generate Fingerprint │  │
  │                                      │ 7. Sign Response        │  │
  │                                      └─────────────────────────┘  │
  │                                                                    │
  │◄───────────────────────────────────────────────────────────────────│
  │  { sessionId, fingerprint, serverSignature }                      │
  │                                                                    │
  │  ┌──────────────────────────────────┐                             │
  │  │ 8. Verify Server Signature       │                             │
  │  │ 9. Derive Shared Secret          │                             │
  │  │ 10. Store Session Info           │                             │
  │  └──────────────────────────────────┘                             │
  │                                                                    │
  │                    ✅ Secure Session Established                   │
  │════════════════════════════════════════════════════════════════════│
```

---

## API Request Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         Secure API Request Flow                              │
└─────────────────────────────────────────────────────────────────────────────┘

Client                                                              Server
  │                                                                    │
  │  1. Build Secure Message:                                         │
  │  ┌────────────────────────────────────┐                           │
  │  │ payload = { action: 'get' }        │                           │
  │  │ encrypted = AES-256-GCM(payload)   │                           │
  │  │ signature = ECDSA-sign(encrypted)  │                           │
  │  │ sequence++                         │                           │
  │  └────────────────────────────────────┘                           │
  │                                                                    │
  │  POST /api/profile                                                │
  │  Headers:                                                         │
  │    X-Session-Id: sessionId                                        │
  │    X-Client-Fingerprint: fingerprint                              │
  │  Body: { iv, data, tag, nonce, ts, seq, sig }                     │
  │───────────────────────────────────────────────────────────────────►│
  │                                                                    │
  │                                      ┌─────────────────────────┐  │
  │                                      │ 2. Security Validation  │  │
  │                                      │   ✓ Session exists      │  │
  │                                      │   ✓ Fingerprint match   │  │
  │                                      │   ✓ Signature valid     │  │
  │                                      │   ✓ Timestamp valid     │  │
  │                                      │   ✓ Nonce unique        │  │
  │                                      │   ✓ Sequence valid      │  │
  │                                      │ 3. Decrypt payload      │  │
  │                                      │ 4. Process request      │  │
  │                                      │ 5. Encrypt response     │  │
  │                                      │ 6. Sign response        │  │
  │                                      └─────────────────────────┘  │
  │                                                                    │
  │◄───────────────────────────────────────────────────────────────────│
  │  { iv, data, tag, nonce, ts, seq, sig }                           │
  │                                                                    │
  │  7. Verify Server Signature                                       │
  │  8. Decrypt Response                                              │
  │  9. Return Plain Data                                             │
  │                                                                    │
```

---

## Security Test Results

### Test 1: Replay Attack Prevention ✅

```
📤 First request (legitimate)...
   ✅ Success: { user: 'attacker', ... }

📤 Second request (replay attack - same data)...
   ✅ Blocked: Duplicate nonce (replay attack prevented)

🛡️  Replay attack was prevented!
```

### Test 2: Session Hijacking Prevention ✅

```
📤 Legitimate request...
   ✅ Success: { user: 'victim', ... }

📤 Attacker trying to use stolen session ID with wrong fingerprint...
   ✅ Blocked: Session binding failed - fingerprint mismatch

🛡️  Session hijacking was prevented!
```

### Test 3: Fake Client Prevention ✅

```
📤 Attacker trying to create session without proper challenge signature...
   ✅ Blocked: Challenge verification failed - invalid client

🛡️  Fake client was rejected!
```

### Test 4: MITM Attack Prevention ✅

```
📤 Normal request (properly signed)...
   ✅ Success: { user: 'victim', ... }

📤 MITM trying to modify encrypted data...
   ✅ Blocked: Invalid signature - MITM attack detected

🛡️  MITM attack was prevented!
```

---

## Configuration

```javascript
export const CONFIG = {
  // ECDH Curve for key exchange
  curve: 'prime256v1',
  
  // ECDSA Curve for signing
  signCurve: 'prime256v1',
  
  // AES-GCM settings
  algorithm: 'aes-256-gcm',
  ivLength: 12,
  authTagLength: 16,
  
  // Replay attack prevention
  timestampTolerance: 30000,  // 30 seconds
  maxSequenceGap: 100,        // Max allowed sequence gap
  
  // Session settings
  sessionTTL: 3600000,        // 1 hour
  
  // Server
  port: 3001,
  baseUrl: 'http://localhost:3001'
};
```

---

## File Structure

```
secure-api/
├── crypto.js      # Security functions & classes
├── server.js      # Express server with security middleware
├── client.js      # Secure API client with tests
├── package.json   # Dependencies
└── SECURITY.md    # This documentation
```

---

## Dependencies

```json
{
  "dependencies": {
    "express": "^4.x",
    "axios": "^1.x",
    "uuid": "^9.x"
  }
}
```

---

## Usage

### Start Server

```bash
node server.js
```

### Run Client & Tests

```bash
node client.js
```

---

## API Endpoints

### Public Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/auth/pubkey` | Get server public keys |
| POST | `/auth/init` | Get challenge for authentication |
| POST | `/auth/session` | Create secure session |
| POST | `/auth/logout` | Destroy session |

### Secure Endpoints (Encrypted + Signed)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/profile` | Get user profile |
| POST | `/api/orders` | Submit order |
| POST | `/api/transfer` | Transfer money |
| POST | `/api/secrets` | Get sensitive data |

---

## Security Summary

| Attack Type | Protection Method | Status |
|-------------|-------------------|--------|
| **Eavesdropping** | AES-256-GCM Encryption | ✅ Protected |
| **Data Tampering** | Authentication Tag (GCM) | ✅ Protected |
| **MITM Attack** | ECDSA Digital Signatures | ✅ Protected |
| **Replay Attack** | Nonce + Timestamp + Sequence | ✅ Protected |
| **Fake Client** | Challenge-Response Auth | ✅ Protected |
| **Session Hijacking** | Fingerprint Binding | ✅ Protected |
| **Key Compromise** | Perfect Forward Secrecy (ECDH) | ✅ Protected |
| **Session Expiry** | TTL + Auto Cleanup | ✅ Protected |

---

## License

MIT
