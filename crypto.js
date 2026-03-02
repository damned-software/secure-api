import crypto from 'crypto';
import { v4 as uuidv4 } from 'uuid';

// ==========================================
// CONFIGURATION
// ==========================================

export const CONFIG = {
  // ECDH Curve for key exchange
  curve: 'prime256v1',
  
  // ECDSA Curve for signing (same curve for simplicity)
  signCurve: 'prime256v1',
  
  // AES-GCM settings
  algorithm: 'aes-256-gcm',
  ivLength: 12,
  authTagLength: 16,
  
  // Replay attack prevention
  timestampTolerance: 30000, // 30 seconds
  maxSequenceGap: 100,       // Max allowed sequence gap
  
  // Session settings
  sessionTTL: 3600000,       // 1 hour
  
  // Server
  port: 3001,
  baseUrl: 'http://localhost:3001'
};

// ==========================================
// ECDSA SIGNING KEY PAIR (for authentication)
// ==========================================

export function generateSigningKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: CONFIG.signCurve,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  });
  return { publicKey, privateKey };
}

// ==========================================
// ECDH KEY EXCHANGE (for encryption)
// ==========================================

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
  // Use HKDF for better key derivation
  return crypto.createHash('sha256').update(shared).digest();
}

// ==========================================
// DIGITAL SIGNATURES (Anti-MITM & Auth)
// ==========================================

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

// ==========================================
// ENCRYPTION / DECRYPTION (AES-256-GCM)
// ==========================================

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

export function decrypt(message, sharedSecret) {
  const { iv, data, tag, nonce, ts, seq = 0 } = message;

  const decipher = crypto.createDecipheriv(
    CONFIG.algorithm,
    sharedSecret,
    Buffer.from(iv, 'base64'),
    { authTagLength: CONFIG.authTagLength }
  );

  decipher.setAAD(Buffer.from(JSON.stringify({ nonce, timestamp: ts, sequence: seq })));
  decipher.setAuthTag(Buffer.from(tag, 'base64'));

  const plaintext = Buffer.concat([
    decipher.update(Buffer.from(data, 'base64')),
    decipher.final()
  ]).toString('utf8');

  try {
    return { payload: JSON.parse(plaintext), nonce, timestamp: ts, sequence: seq };
  } catch {
    return { payload: plaintext, nonce, timestamp: ts, sequence: seq };
  }
}

// ==========================================
// SIGNED & ENCRYPTED MESSAGE
// ==========================================

export function encryptAndSign(payload, sharedSecret, signingPrivateKey, sequence = 0) {
  const encrypted = encrypt(payload, sharedSecret, sequence);
  
  // Sign the entire encrypted message (prevents tampering)
  const signature = sign(encrypted, signingPrivateKey);
  
  return {
    ...encrypted,
    sig: signature
  };
}

export function verifyAndDecrypt(message, sharedSecret, signingPublicKey) {
  const { sig, ...encrypted } = message;
  
  // Verify signature first (anti-MITM)
  if (!sig || !verify(encrypted, sig, signingPublicKey)) {
    throw new Error('Invalid signature - possible MITM attack');
  }
  
  // Then decrypt
  return decrypt(encrypted, sharedSecret);
}

// ==========================================
// CLIENT FINGERPRINT (Session Binding)
// ==========================================

export function generateClientFingerprint(clientPublicKey, signingPublicKey, userAgent = '') {
  const data = `${clientPublicKey}:${signingPublicKey}:${userAgent}`;
  return crypto.createHash('sha256').update(data).digest('hex');
}

// ==========================================
// CHALLENGE-RESPONSE (Mutual Authentication)
// ==========================================

export function generateChallenge() {
  return crypto.randomBytes(32).toString('base64');
}

export function signChallenge(challenge, privateKey) {
  return sign(challenge, privateKey);
}

export function verifyChallenge(challenge, signature, publicKey) {
  return verify(challenge, signature, publicKey);
}

// ==========================================
// REPLAY ATTACK PREVENTION (Enhanced)
// ==========================================

export class NonceValidator {
  constructor(windowMs = 60000) {
    this.usedNonces = new Map();  // nonce -> timestamp
    this.sequences = new Map();    // sessionId -> lastSequence
    this.windowMs = windowMs;
    
    // Cleanup old nonces periodically
    setInterval(() => this.cleanup(), windowMs);
  }

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
      
      if (sequence > lastSeq + CONFIG.maxSequenceGap) {
        return { valid: false, error: 'Sequence gap too large' };
      }
      
      this.sequences.set(sessionId, sequence);
    }

    // Mark nonce as used
    this.usedNonces.set(nonce, timestamp);
    return { valid: true };
  }

  cleanup() {
    const cutoff = Date.now() - this.windowMs;
    for (const [nonce, ts] of this.usedNonces) {
      if (ts < cutoff) this.usedNonces.delete(nonce);
    }
  }
  
  removeSession(sessionId) {
    this.sequences.delete(sessionId);
  }
}

// ==========================================
// SESSION MANAGER (Secure Sessions)
// ==========================================

export class SecureSessionManager {
  constructor() {
    this.sessions = new Map();
    
    // Cleanup expired sessions periodically
    setInterval(() => this.cleanup(), 60000);
  }

  create(sessionId, data) {
    const session = {
      ...data,
      createdAt: Date.now(),
      lastActivity: Date.now(),
      sequence: 0
    };
    this.sessions.set(sessionId, session);
    return session;
  }

  get(sessionId) {
    const session = this.sessions.get(sessionId);
    if (!session) return null;
    
    // Check expiration
    if (Date.now() - session.createdAt > CONFIG.sessionTTL) {
      this.sessions.delete(sessionId);
      return null;
    }
    
    // Update last activity
    session.lastActivity = Date.now();
    return session;
  }

  validateFingerprint(sessionId, fingerprint) {
    const session = this.get(sessionId);
    if (!session) return false;
    return session.fingerprint === fingerprint;
  }

  delete(sessionId) {
    this.sessions.delete(sessionId);
  }

  cleanup() {
    const now = Date.now();
    for (const [id, session] of this.sessions) {
      if (now - session.createdAt > CONFIG.sessionTTL) {
        this.sessions.delete(id);
        console.log(`🗑️  Session expired: ${id}`);
      }
    }
  }

  list() {
    return Array.from(this.sessions.entries()).map(([id, s]) => ({
      sessionId: id,
      clientId: s.clientId,
      createdAt: new Date(s.createdAt).toISOString(),
      lastActivity: new Date(s.lastActivity).toISOString()
    }));
  }
}

// ==========================================
// SECURE MESSAGE BUILDER
// ==========================================

export class SecureMessageBuilder {
  constructor(sharedSecret, signingPrivateKey) {
    this.sharedSecret = sharedSecret;
    this.signingPrivateKey = signingPrivateKey;
    this.sequence = 0;
  }

  build(payload) {
    this.sequence++;
    return encryptAndSign(payload, this.sharedSecret, this.signingPrivateKey, this.sequence);
  }

  getSequence() {
    return this.sequence;
  }
}

// ==========================================
// KEY ROTATION MANAGER
// ==========================================

export class KeyRotationManager {
  constructor(rotationIntervalMs = 24 * 60 * 60 * 1000) { // Default: 24 hours
    this.keys = new Map(); // keyId -> { ecdhKeys, signingKeys, createdAt }
    this.currentKeyId = null;
    this.rotationInterval = rotationIntervalMs;
    this.gracePeriod = rotationIntervalMs * 2; // Keep old keys for 2 rotation periods
    
    // Create initial keys
    this.rotate();
    
    // Auto-rotate
    this.rotationTimer = setInterval(() => this.rotate(), rotationIntervalMs);
  }

  rotate() {
    const keyId = crypto.randomUUID();
    const ecdhKeys = generateKeyPair();
    const signingKeys = generateSigningKeyPair();
    
    this.keys.set(keyId, {
      ecdhKeys,
      signingKeys,
      createdAt: Date.now()
    });
    
    const previousKeyId = this.currentKeyId;
    this.currentKeyId = keyId;
    
    console.log(`🔄 Key rotated: ${keyId.substring(0, 8)}...`);
    if (previousKeyId) {
      console.log(`   Previous key ${previousKeyId.substring(0, 8)}... still valid for grace period`);
    }
    
    // Cleanup old keys
    this.cleanup();
    
    return keyId;
  }

  getCurrentKeyId() {
    return this.currentKeyId;
  }

  getCurrentKeys() {
    return this.keys.get(this.currentKeyId);
  }

  getKeys(keyId) {
    return this.keys.get(keyId);
  }

  isValidKeyId(keyId) {
    return this.keys.has(keyId);
  }

  cleanup() {
    const cutoff = Date.now() - this.gracePeriod;
    for (const [id, key] of this.keys) {
      if (key.createdAt < cutoff && id !== this.currentKeyId) {
        this.keys.delete(id);
        console.log(`🗑️  Old key retired: ${id.substring(0, 8)}...`);
      }
    }
  }

  // Get info for debugging/admin
  getStatus() {
    return {
      currentKeyId: this.currentKeyId,
      totalKeys: this.keys.size,
      keys: Array.from(this.keys.entries()).map(([id, k]) => ({
        keyId: id,
        isCurrent: id === this.currentKeyId,
        createdAt: new Date(k.createdAt).toISOString(),
        expiresAt: new Date(k.createdAt + this.gracePeriod).toISOString()
      }))
    };
  }

  // Manual rotation trigger
  forceRotate() {
    console.log('⚠️  Force key rotation triggered');
    return this.rotate();
  }

  // Stop auto-rotation
  stop() {
    if (this.rotationTimer) {
      clearInterval(this.rotationTimer);
      this.rotationTimer = null;
    }
  }
}
