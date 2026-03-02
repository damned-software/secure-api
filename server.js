import crypto from 'crypto';
import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import {
  generateKeyPair,
  generateSigningKeyPair,
  deriveSharedSecret,
  encryptAndSign,
  verifyAndDecrypt,
  sign,
  verify,
  generateChallenge,
  generateClientFingerprint,
  NonceValidator,
  SecureSessionManager,
  KeyRotationManager,
  CONFIG
} from './crypto.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
app.use(express.json());

// Serve static files for web client
app.use(express.static(path.join(__dirname, 'public')));

// CORS for browser
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Content-Type, X-Session-Id, X-Client-Fingerprint');
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

// ==========================================
// SERVER STATE (Maximum Security + Key Rotation)
// ==========================================

// Key Rotation Manager - rotates every 1 minute for demo (use 24h in production)
const keyManager = new KeyRotationManager(60 * 1000); // 1 minute for demo

// Secure session manager with auto-expiry
const sessionManager = new SecureSessionManager();

// Enhanced nonce validator with sequence tracking
const nonceValidator = new NonceValidator();

// Helper to get current server keys
function getServerKeys() {
  const keys = keyManager.getCurrentKeys();
  return {
    keyId: keyManager.getCurrentKeyId(),
    ecdhKeys: keys.ecdhKeys,
    signingKeys: keys.signingKeys
  };
}

// Helper to get keys by ID (for existing sessions)
function getServerKeysBySession(session) {
  const keys = keyManager.getKeys(session.serverKeyId);
  if (!keys) {
    // Key expired, need to re-auth
    return null;
  }
  return {
    keyId: session.serverKeyId,
    ecdhKeys: keys.ecdhKeys,
    signingKeys: keys.signingKeys
  };
}

console.log('🔐 Initial Key ID:', keyManager.getCurrentKeyId().substring(0, 8) + '...');

// ==========================================
// MIDDLEWARE: Maximum Security Validation
// ==========================================

function secureEndpoint(req, res, next) {
  const sessionId = req.headers['x-session-id'];
  const clientFingerprint = req.headers['x-client-fingerprint'];
  
  // 1. Validate session exists
  const session = sessionManager.get(sessionId);
  if (!session) {
    console.log('⚠️  Invalid session attempt');
    return res.status(401).json({ error: 'Invalid or expired session' });
  }

  // 2. Validate client fingerprint (anti-client-spoofing)
  if (session.fingerprint !== clientFingerprint) {
    console.log('⚠️  Fingerprint mismatch - possible session hijacking');
    return res.status(403).json({ error: 'Session binding failed - fingerprint mismatch' });
  }

  // 3. Get server keys for this session (key rotation support)
  const serverKeys = getServerKeysBySession(session);
  if (!serverKeys) {
    console.log('⚠️  Server key expired - client needs to re-authenticate');
    return res.status(401).json({ error: 'Server key rotated - please re-authenticate' });
  }

  try {
    // 4. Verify signature & decrypt (anti-MITM)
    const { payload, nonce, timestamp, sequence } = verifyAndDecrypt(
      req.body,
      session.sharedSecret,
      session.clientSigningPublicKey
    );

    // 5. Validate against replay attack (nonce + timestamp + sequence)
    const validation = nonceValidator.validate(nonce, timestamp, sessionId, sequence);
    if (!validation.valid) {
      console.log(`⚠️  Blocked: ${validation.error}`);
      return res.status(403).json({ error: validation.error });
    }

    // Attach decrypted data to request
    req.secureBody = payload;
    req.session = session;
    req.sessionId = sessionId;
    req.serverKeys = serverKeys;

    // Override res.json to auto-encrypt & sign responses
    const originalJson = res.json.bind(res);
    session.responseSequence = (session.responseSequence || 0) + 1;
    
    res.json = (data) => {
      const encrypted = encryptAndSign(
        data,
        session.sharedSecret,
        serverKeys.signingKeys.privateKey,
        session.responseSequence
      );
      return originalJson(encrypted);
    };

    next();
  } catch (err) {
    console.error('Security validation failed:', err.message);
    
    if (err.message.includes('signature')) {
      return res.status(403).json({ error: 'Invalid signature - MITM attack detected' });
    }
    
    return res.status(400).json({ error: 'Invalid encrypted payload' });
  }
}

// ==========================================
// AUTHENTICATION ENDPOINTS
// ==========================================

// Step 1: Get server's public keys (ECDH + Signing)
app.get('/auth/pubkey', (req, res) => {
  const serverKeys = getServerKeys();
  res.json({
    keyId: serverKeys.keyId,
    ecdhPublicKey: serverKeys.ecdhKeys.publicKey,
    signingPublicKey: serverKeys.signingKeys.publicKey
  });
});

// Step 2: Initiate session with challenge
app.post('/auth/init', (req, res) => {
  const { clientEcdhPublicKey, clientSigningPublicKey, clientId } = req.body;

  if (!clientEcdhPublicKey || !clientSigningPublicKey) {
    return res.status(400).json({ error: 'Missing client public keys' });
  }

  // Get current server keys
  const serverKeys = getServerKeys();

  // Generate challenge for client to sign
  const challenge = generateChallenge();

  res.json({
    challenge,
    keyId: serverKeys.keyId,
    serverEcdhPublicKey: serverKeys.ecdhKeys.publicKey,
    serverSigningPublicKey: serverKeys.signingKeys.publicKey
  });
});

// Step 3: Complete authentication with challenge-response
app.post('/auth/session', (req, res) => {
  const { 
    clientEcdhPublicKey, 
    clientSigningPublicKey, 
    clientId,
    challenge,
    challengeSignature,
    userAgent = ''
  } = req.body;

  if (!clientEcdhPublicKey || !clientSigningPublicKey) {
    return res.status(400).json({ error: 'Missing client public keys' });
  }

  if (!challenge || !challengeSignature) {
    return res.status(400).json({ error: 'Missing challenge response' });
  }

  try {
    // Get current server keys
    const serverKeys = getServerKeys();

    // Verify client signed the challenge (proves client has private key)
    const isValid = verify(challenge, challengeSignature, clientSigningPublicKey);
    if (!isValid) {
      console.log('⚠️  Challenge verification failed - fake client detected');
      return res.status(403).json({ error: 'Challenge verification failed - invalid client' });
    }

    // Derive shared secret for encryption
    const sharedSecret = deriveSharedSecret(serverKeys.ecdhKeys.privateKey, clientEcdhPublicKey);

    // Generate session ID and fingerprint
    const sessionId = crypto.randomUUID();
    const fingerprint = generateClientFingerprint(
      clientEcdhPublicKey,
      clientSigningPublicKey,
      userAgent
    );

    // Create secure session with server key ID for rotation support
    sessionManager.create(sessionId, {
      sharedSecret,
      clientId: clientId || 'anonymous',
      clientSigningPublicKey,
      clientEcdhPublicKey,
      fingerprint,
      userAgent,
      serverKeyId: serverKeys.keyId, // Store which server key was used
      responseSequence: 0
    });

    // Sign the session response (proves server identity)
    const responseData = {
      sessionId,
      fingerprint,
      keyId: serverKeys.keyId,
      serverEcdhPublicKey: serverKeys.ecdhKeys.publicKey,
      expiresIn: CONFIG.sessionTTL / 1000
    };
    
    const serverSignature = sign(responseData, serverKeys.signingKeys.privateKey);

    console.log(`✅ Secure session: ${sessionId} for ${clientId || 'anonymous'}`);
    console.log(`   Key ID: ${serverKeys.keyId.substring(0, 8)}...`);
    console.log(`   Fingerprint: ${fingerprint.substring(0, 32)}...`);

    res.json({
      ...responseData,
      serverSignature,
      serverSigningPublicKey: serverKeys.signingKeys.publicKey
    });
  } catch (err) {
    console.error('Session creation failed:', err.message);
    res.status(400).json({ error: 'Invalid public key or signature' });
  }
});

// Logout / Destroy session
app.post('/auth/logout', (req, res) => {
  const sessionId = req.headers['x-session-id'];
  
  if (sessionId) {
    sessionManager.delete(sessionId);
    nonceValidator.removeSession(sessionId);
    console.log(`🚪 Session terminated: ${sessionId}`);
  }
  
  res.json({ success: true });
});

// ==========================================
// SECURE API ENDPOINTS (Encrypted + Signed)
// ==========================================

// Example: Get user profile
app.post('/api/profile', secureEndpoint, (req, res) => {
  console.log('📥 Profile request:', req.secureBody);
  
  res.json({
    user: req.session.clientId,
    email: 'user@example.com',
    createdAt: new Date().toISOString(),
    security: 'Maximum'
  });
});

// Example: Submit order
app.post('/api/orders', secureEndpoint, (req, res) => {
  const { items, total } = req.secureBody;
  
  console.log('📥 New order:', { items, total });

  const orderId = `ORD-${Date.now()}`;

  res.json({
    success: true,
    orderId,
    message: 'Order placed successfully'
  });
});

// Example: Transfer money (sensitive operation)
app.post('/api/transfer', secureEndpoint, (req, res) => {
  const { to, amount, currency } = req.secureBody;

  console.log('💸 Transfer request:', { to, amount, currency });

  res.json({
    success: true,
    transactionId: `TXN-${Date.now()}`,
    from: req.session.clientId,
    to,
    amount,
    currency,
    timestamp: new Date().toISOString()
  });
});

// Example: Get sensitive data
app.post('/api/secrets', secureEndpoint, (req, res) => {
  res.json({
    apiKey: 'sk_live_xxxxxxxxxxxx',
    dbPassword: 'super-secret-password',
    note: 'Protected with maximum security!'
  });
});

// ==========================================
// ADMIN / DEBUG
// ==========================================

app.get('/admin/sessions', (req, res) => {
  res.json(sessionManager.list());
});

// Key rotation status
app.get('/admin/keys', (req, res) => {
  res.json(keyManager.getStatus());
});

// Force key rotation (for testing)
app.post('/admin/rotate', (req, res) => {
  const newKeyId = keyManager.forceRotate();
  res.json({ 
    success: true, 
    newKeyId,
    message: 'Keys rotated. Existing sessions will continue to work during grace period.'
  });
});

// ==========================================
// START
// ==========================================

app.listen(CONFIG.port, () => {
  console.log('');
  console.log('╔════════════════════════════════════════════════════════════╗');
  console.log('║         Secure API Server (MAXIMUM SECURITY)               ║');
  console.log('╠════════════════════════════════════════════════════════════╣');
  console.log('║  🔐 ECDH Key Exchange (Perfect Forward Secrecy)            ║');
  console.log('║  🔏 ECDSA Digital Signatures (Anti-MITM)                   ║');
  console.log('║  🔒 AES-256-GCM Encryption                                 ║');
  console.log('║  🛡️  Challenge-Response Auth (Anti-Fake-Client)            ║');
  console.log('║  🔄 Nonce + Timestamp + Sequence (Anti-Replay)             ║');
  console.log('║  📍 Session Binding (Anti-Hijacking)                       ║');
  console.log('║  🔑 Auto Key Rotation (every 1 minute for demo)            ║');
  console.log('╚════════════════════════════════════════════════════════════╝');
  console.log('');
  console.log(`🚀 Running on ${CONFIG.baseUrl}`);
  console.log(`🌐 Web Client: ${CONFIG.baseUrl}/`);
  console.log('');
  console.log('📋 Auth Endpoints:');
  console.log('   GET  /auth/pubkey    - Get server public keys');
  console.log('   POST /auth/init      - Get challenge for auth');
  console.log('   POST /auth/session   - Create secure session');
  console.log('   POST /auth/logout    - Destroy session');
  console.log('');
  console.log('🔐 Secure Endpoints:');
  console.log('   POST /api/profile    - Get user profile');
  console.log('   POST /api/orders     - Submit order');
  console.log('   POST /api/transfer   - Transfer money');
  console.log('   POST /api/secrets    - Get sensitive data');
  console.log('');
  console.log('🔧 Admin Endpoints:');
  console.log('   GET  /admin/sessions - List active sessions');
  console.log('   GET  /admin/keys     - Key rotation status');
  console.log('   POST /admin/rotate   - Force key rotation');
  console.log('');
});
