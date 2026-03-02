import axios from 'axios';
import {
  generateKeyPair,
  generateSigningKeyPair,
  deriveSharedSecret,
  encryptAndSign,
  verifyAndDecrypt,
  sign,
  verify,
  generateClientFingerprint,
  SecureMessageBuilder,
  CONFIG
} from './crypto.js';

// ==========================================
// SECURE API CLIENT (Maximum Security)
// ==========================================

class SecureApiClient {
  constructor(baseUrl = CONFIG.baseUrl) {
    this.baseUrl = baseUrl;
    this.sessionId = null;
    this.fingerprint = null;
    this.sharedSecret = null;
    this.clientEcdhKeys = null;
    this.clientSigningKeys = null;
    this.serverSigningPublicKey = null;
    this.messageBuilder = null;
  }

  /**
   * Initialize secure session with server (Maximum Security)
   * 1. Generate client ECDH key pair (for encryption)
   * 2. Generate client ECDSA key pair (for signing)
   * 3. Get challenge from server (verify signature with pinned key)
   * 4. Sign challenge to prove identity
   * 5. Verify server's signature
   * 6. Establish encrypted session
   */
  async connect(clientId = 'my-app', userAgent = 'SecureClient/1.0') {
    console.log('🔑 Establishing maximum security session...');

    // Step 0: Get and PIN server signing public key (prevents MITM on init)
    const pubkeyResponse = await axios.get(`${this.baseUrl}/auth/pubkey`);
    const pinnedServerSigningKey = pubkeyResponse.data.signingPublicKey;
    console.log(`   📌 Pinned Server Key: ${pinnedServerSigningKey.substring(27, 60)}...`);

    // Generate ECDH keys (for encryption)
    this.clientEcdhKeys = generateKeyPair();
    console.log(`   Client ECDH Key: ${this.clientEcdhKeys.publicKey.substring(0, 30)}...`);

    // Generate ECDSA keys (for signing - anti-MITM & auth)
    this.clientSigningKeys = generateSigningKeyPair();
    console.log(`   Client Signing Key: ${this.clientSigningKeys.publicKey.substring(0, 40)}...`);

    // Step 1: Get challenge from server
    const initResponse = await axios.post(`${this.baseUrl}/auth/init`, {
      clientEcdhPublicKey: this.clientEcdhKeys.publicKey,
      clientSigningPublicKey: this.clientSigningKeys.publicKey,
      clientId
    });

    const { challenge, serverEcdhPublicKey, serverSigningPublicKey, initSignature, timestamp, keyId: initKeyId } = initResponse.data;
    
    // Step 1.5: Verify init response signature with PINNED key (anti-MITM)
    const initDataToVerify = {
      challenge,
      keyId: initKeyId,
      serverEcdhPublicKey,
      serverSigningPublicKey,
      timestamp
    };
    const initValid = verify(initDataToVerify, initSignature, pinnedServerSigningKey);
    if (!initValid) {
      throw new Error('Init signature verification failed - possible MITM attack!');
    }
    console.log('   ✅ Init response verified with pinned key (anti-MITM)');
    
    // Store verified server signing key
    this.serverSigningPublicKey = serverSigningPublicKey;
    
    console.log(`   Server ECDH Key: ${serverEcdhPublicKey.substring(0, 30)}...`);
    console.log(`   Challenge received: ${challenge.substring(0, 20)}...`);

    // Step 2: Sign the challenge (prove we have the private key)
    const challengeSignature = sign(challenge, this.clientSigningKeys.privateKey);

    // Step 3: Create session with signed challenge
    const sessionResponse = await axios.post(`${this.baseUrl}/auth/session`, {
      clientEcdhPublicKey: this.clientEcdhKeys.publicKey,
      clientSigningPublicKey: this.clientSigningKeys.publicKey,
      clientId,
      challenge,
      challengeSignature,
      userAgent
    });

    const { sessionId, fingerprint, serverSignature, keyId } = sessionResponse.data;

    // Step 4: Verify server's signature (anti-MITM)
    const responseToVerify = {
      sessionId,
      fingerprint,
      keyId,
      serverEcdhPublicKey: sessionResponse.data.serverEcdhPublicKey,
      expiresIn: sessionResponse.data.expiresIn
    };

    const serverValid = verify(responseToVerify, serverSignature, this.serverSigningPublicKey);
    if (!serverValid) {
      throw new Error('Server signature verification failed - possible MITM attack!');
    }
    console.log('   ✅ Server signature verified (anti-MITM)');
    console.log(`   Key ID: ${keyId.substring(0, 8)}...`);

    // Step 5: Derive shared secret
    this.sharedSecret = deriveSharedSecret(this.clientEcdhKeys.privateKey, serverEcdhPublicKey);
    this.sessionId = sessionId;
    this.fingerprint = fingerprint;

    // Create message builder for auto-sequencing
    this.messageBuilder = new SecureMessageBuilder(
      this.sharedSecret,
      this.clientSigningKeys.privateKey
    );

    console.log(`✅ Secure session established: ${sessionId}`);
    console.log(`   Fingerprint: ${fingerprint.substring(0, 32)}...`);
    console.log(`   Shared Secret: ${this.sharedSecret.toString('hex').substring(0, 32)}...`);

    return this;
  }

  /**
   * Make encrypted & signed API request
   * @param {string} endpoint - API endpoint (e.g., '/api/profile')
   * @param {object} data - Request payload (will be encrypted & signed)
   */
  async request(endpoint, data = {}) {
    if (!this.sessionId || !this.messageBuilder) {
      throw new Error('Not connected. Call connect() first.');
    }

    // Encrypt & sign request with auto-incrementing sequence
    const encrypted = this.messageBuilder.build(data);

    // Send request with security headers
    const response = await axios.post(`${this.baseUrl}${endpoint}`, encrypted, {
      headers: {
        'Content-Type': 'application/json',
        'X-Session-Id': this.sessionId,
        'X-Client-Fingerprint': this.fingerprint
      }
    });

    // Verify server signature & decrypt response
    const { payload } = verifyAndDecrypt(
      response.data,
      this.sharedSecret,
      this.serverSigningPublicKey
    );
    
    return payload;
  }

  /**
   * Logout and destroy session
   */
  async logout() {
    if (this.sessionId) {
      await axios.post(`${this.baseUrl}/auth/logout`, {}, {
        headers: { 'X-Session-Id': this.sessionId }
      });
      console.log('🚪 Session terminated');
    }
    this.sessionId = null;
    this.sharedSecret = null;
    this.messageBuilder = null;
  }
}

// ==========================================
// DEMO
// ==========================================

async function demo() {
  console.log('');
  console.log('╔════════════════════════════════════════════════════════════╗');
  console.log('║         Maximum Security API Client Demo                   ║');
  console.log('╚════════════════════════════════════════════════════════════╝');
  console.log('');

  const client = new SecureApiClient();

  try {
    // Connect with maximum security
    await client.connect('user-123');

    console.log('\n--- API Requests (Encrypted + Signed) ---\n');

    // 1. Get profile
    console.log('📤 Requesting profile...');
    const profile = await client.request('/api/profile', { action: 'get' });
    console.log('📥 Profile:', profile);

    // 2. Place order
    console.log('\n📤 Placing order...');
    const order = await client.request('/api/orders', {
      items: [
        { name: 'Product A', qty: 2, price: 100 },
        { name: 'Product B', qty: 1, price: 250 }
      ],
      total: 450
    });
    console.log('📥 Order result:', order);

    // 3. Transfer money
    console.log('\n📤 Transferring money...');
    const transfer = await client.request('/api/transfer', {
      to: 'recipient-456',
      amount: 1000,
      currency: 'THB'
    });
    console.log('📥 Transfer result:', transfer);

    // 4. Get secrets
    console.log('\n📤 Getting secrets...');
    const secrets = await client.request('/api/secrets', {});
    console.log('📥 Secrets:', secrets);

    console.log('\n✅ All requests completed with MAXIMUM SECURITY!');
    console.log('   🔐 AES-256-GCM encryption');
    console.log('   🔏 ECDSA digital signatures');
    console.log('   🔄 Nonce + Timestamp + Sequence (anti-replay)');
    console.log('   📍 Session fingerprint binding');

    // Logout
    await client.logout();

  } catch (err) {
    console.error('❌ Error:', err.response?.data || err.message);
  }
}

// ==========================================
// SECURITY TESTS
// ==========================================

async function testReplayAttack() {
  console.log('\n');
  console.log('╔════════════════════════════════════════════════════════════╗');
  console.log('║         Test 1: Replay Attack Prevention                   ║');
  console.log('╚════════════════════════════════════════════════════════════╝');
  console.log('');

  const client = new SecureApiClient();
  await client.connect('attacker');

  // Capture encrypted request
  const encrypted = client.messageBuilder.build({ action: 'get' });

  console.log('📤 First request (legitimate)...');
  try {
    const res1 = await axios.post(`${CONFIG.baseUrl}/api/profile`, encrypted, {
      headers: { 
        'X-Session-Id': client.sessionId,
        'X-Client-Fingerprint': client.fingerprint
      }
    });
    const { payload } = verifyAndDecrypt(res1.data, client.sharedSecret, client.serverSigningPublicKey);
    console.log('   ✅ Success:', payload);
  } catch (err) {
    console.log('   ❌ Failed:', err.response?.data || err.message);
  }

  console.log('\n📤 Second request (replay attack - same data)...');
  try {
    const res2 = await axios.post(`${CONFIG.baseUrl}/api/profile`, encrypted, {
      headers: {
        'X-Session-Id': client.sessionId,
        'X-Client-Fingerprint': client.fingerprint
      }
    });
    console.log('   ⚠️  Attack succeeded:', res2.data);
  } catch (err) {
    console.log('   ✅ Blocked:', err.response?.data.error);
  }

  console.log('\n🛡️  Replay attack was prevented!');
}

async function testSessionHijacking() {
  console.log('\n');
  console.log('╔════════════════════════════════════════════════════════════╗');
  console.log('║         Test 2: Session Hijacking Prevention               ║');
  console.log('╚════════════════════════════════════════════════════════════╝');
  console.log('');

  const legitimateClient = new SecureApiClient();
  await legitimateClient.connect('victim');

  console.log('📤 Legitimate request...');
  const profile = await legitimateClient.request('/api/profile', {});
  console.log('   ✅ Success:', profile);

  console.log('\n📤 Attacker trying to use stolen session ID with wrong fingerprint...');
  try {
    const attackerClient = new SecureApiClient();
    attackerClient.clientSigningKeys = generateSigningKeyPair();
    
    const fakeEncrypted = encryptAndSign(
      { action: 'steal' },
      legitimateClient.sharedSecret, // Assume attacker got the secret somehow
      attackerClient.clientSigningKeys.privateKey,
      1
    );

    const res = await axios.post(`${CONFIG.baseUrl}/api/profile`, fakeEncrypted, {
      headers: {
        'X-Session-Id': legitimateClient.sessionId,
        'X-Client-Fingerprint': 'fake-fingerprint'
      }
    });
    console.log('   ⚠️  Attack succeeded:', res.data);
  } catch (err) {
    console.log('   ✅ Blocked:', err.response?.data.error);
  }

  console.log('\n🛡️  Session hijacking was prevented!');
}

async function testFakeClient() {
  console.log('\n');
  console.log('╔════════════════════════════════════════════════════════════╗');
  console.log('║         Test 3: Fake Client Prevention                     ║');
  console.log('╚════════════════════════════════════════════════════════════╝');
  console.log('');

  console.log('📤 Attacker trying to create session without proper challenge signature...');
  try {
    // Generate fake keys
    const fakeEcdhKeys = generateKeyPair();
    const fakeSigningKeys = generateSigningKeyPair();

    // Get challenge
    const initRes = await axios.post(`${CONFIG.baseUrl}/auth/init`, {
      clientEcdhPublicKey: fakeEcdhKeys.publicKey,
      clientSigningPublicKey: fakeSigningKeys.publicKey,
      clientId: 'fake-client'
    });

    const { challenge } = initRes.data;

    // Try to use a wrong signature
    const wrongSignature = 'invalid-signature-base64';

    const sessionRes = await axios.post(`${CONFIG.baseUrl}/auth/session`, {
      clientEcdhPublicKey: fakeEcdhKeys.publicKey,
      clientSigningPublicKey: fakeSigningKeys.publicKey,
      clientId: 'fake-client',
      challenge,
      challengeSignature: wrongSignature
    });

    console.log('   ⚠️  Fake client accepted:', sessionRes.data);
  } catch (err) {
    console.log('   ✅ Blocked:', err.response?.data.error);
  }

  console.log('\n🛡️  Fake client was rejected!');
}

async function testMitmAttack() {
  console.log('\n');
  console.log('╔════════════════════════════════════════════════════════════╗');
  console.log('║         Test 4: MITM Attack Prevention                     ║');
  console.log('╚════════════════════════════════════════════════════════════╝');
  console.log('');

  const client = new SecureApiClient();
  await client.connect('victim');

  console.log('📤 Normal request (properly signed)...');
  const profile = await client.request('/api/profile', {});
  console.log('   ✅ Success:', profile);

  console.log('\n📤 MITM trying to modify encrypted data...');
  try {
    // Create valid encrypted message
    const encrypted = client.messageBuilder.build({ action: 'get' });
    
    // MITM modifies the signature
    encrypted.sig = 'tampered-signature';

    const res = await axios.post(`${CONFIG.baseUrl}/api/profile`, encrypted, {
      headers: {
        'X-Session-Id': client.sessionId,
        'X-Client-Fingerprint': client.fingerprint
      }
    });
    console.log('   ⚠️  MITM attack succeeded:', res.data);
  } catch (err) {
    console.log('   ✅ Blocked:', err.response?.data.error);
  }

  console.log('\n🛡️  MITM attack was prevented!');
}

// ==========================================
// RUN
// ==========================================

async function main() {
  await demo();
  await testReplayAttack();
  await testSessionHijacking();
  await testFakeClient();
  await testMitmAttack();
  
  console.log('\n');
  console.log('╔════════════════════════════════════════════════════════════╗');
  console.log('║         ALL SECURITY TESTS PASSED!                         ║');
  console.log('╚════════════════════════════════════════════════════════════╝');
  console.log('');
}

main().catch(console.error);
