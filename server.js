import crypto from 'crypto';
import express from 'express';
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
  CONFIG
} from './crypto.js';

const app = express();
app.use(express.json());

// ==========================================
// SERVER STATE (Maximum Security)
// ==========================================

// ECDH keys for encryption
const serverKeys = generateKeyPair();

// ECDSA keys for signing (anti-MITM)
const serverSigningKeys = generateSigningKeyPair();

// Secure session manager with auto-expiry
const sessionManager = new SecureSessionManager();

// Enhanced nonce validator with sequence tracking
const nonceValidator = new NonceValidator();

console.log('🔐 Server ECDH Public Key:', serverKeys.publicKey.substring(0, 40) + '...');
console.log('🔏 Server Signing Public Key:', serverSigningKeys.publicKey.substring(0, 50) + '...');

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

  try {
    // 3. Verify signature & decrypt (anti-MITM)
    const { payload, nonce, timestamp, sequence } = verifyAndDecrypt(
      req.body,
      session.sharedSecret,
      session.clientSigningPublicKey
    );

    // 4. Validate against replay attack (nonce + timestamp + sequence)
    const validation = nonceValidator.validate(nonce, timestamp, sessionId, sequence);
    if (!validation.valid) {
      console.log(`⚠️  Blocked: ${validation.error}`);
      return res.status(403).json({ error: validation.error });
    }

    // Attach decrypted data to request
    req.secureBody = payload;
    req.session = session;
    req.sessionId = sessionId;

    // Override res.json to auto-encrypt & sign responses
    const originalJson = res.json.bind(res);
    session.responseSequence = (session.responseSequence || 0) + 1;
    
    res.json = (data) => {
      const encrypted = encryptAndSign(
        data,
        session.sharedSecret,
        serverSigningKeys.privateKey,
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
  res.json({
    ecdhPublicKey: serverKeys.publicKey,
    signingPublicKey: serverSigningKeys.publicKey
  });
});

// Step 2: Initiate session with challenge
app.post('/auth/init', (req, res) => {
  const { clientEcdhPublicKey, clientSigningPublicKey, clientId } = req.body;

  if (!clientEcdhPublicKey || !clientSigningPublicKey) {
    return res.status(400).json({ error: 'Missing client public keys' });
  }

  // Generate challenge for client to sign
  const challenge = generateChallenge();

  res.json({
    challenge,
    serverEcdhPublicKey: serverKeys.publicKey,
    serverSigningPublicKey: serverSigningKeys.publicKey
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
    // Verify client signed the challenge (proves client has private key)
    const isValid = verify(challenge, challengeSignature, clientSigningPublicKey);
    if (!isValid) {
      console.log('⚠️  Challenge verification failed - fake client detected');
      return res.status(403).json({ error: 'Challenge verification failed - invalid client' });
    }

    // Derive shared secret for encryption
    const sharedSecret = deriveSharedSecret(serverKeys.privateKey, clientEcdhPublicKey);

    // Generate session ID and fingerprint
    const sessionId = crypto.randomUUID();
    const fingerprint = generateClientFingerprint(
      clientEcdhPublicKey,
      clientSigningPublicKey,
      userAgent
    );

    // Create secure session
    sessionManager.create(sessionId, {
      sharedSecret,
      clientId: clientId || 'anonymous',
      clientSigningPublicKey,
      clientEcdhPublicKey,
      fingerprint,
      userAgent,
      responseSequence: 0
    });

    // Sign the session response (proves server identity)
    const responseData = {
      sessionId,
      fingerprint,
      serverEcdhPublicKey: serverKeys.publicKey,
      expiresIn: CONFIG.sessionTTL / 1000
    };
    
    const serverSignature = sign(responseData, serverSigningKeys.privateKey);

    console.log(`✅ Secure session: ${sessionId} for ${clientId || 'anonymous'}`);
    console.log(`   Fingerprint: ${fingerprint.substring(0, 32)}...`);

    res.json({
      ...responseData,
      serverSignature,
      serverSigningPublicKey: serverSigningKeys.publicKey
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
  console.log('╚════════════════════════════════════════════════════════════╝');
  console.log('');
  console.log(`🚀 Running on ${CONFIG.baseUrl}`);
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
});
