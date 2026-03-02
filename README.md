# Secure API

HTTP API ที่ใช้ **ECDH key exchange** + **AES-256-GCM encryption** + **Replay Attack Prevention**

## Features

- 🔐 **ECDH Key Exchange** - ไม่ต้อง hardcode shared key
- 🔒 **AES-256-GCM** - Authenticated encryption
- 🛡️ **Anti-Replay** - Unique nonce + timestamp validation
- 🚀 **Express Middleware** - ใช้ง่าย plug-and-play

## Quick Start

```bash
# Install dependencies
npm install

# Start server
npm run server

# Run client demo (in another terminal)
npm run client
```

## How It Works

```
┌─────────────────────────────────────────────────────────────────┐
│                         FLOW                                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  Client                                    Server               │
│  ──────                                    ──────               │
│                                                                 │
│  1. Generate ECDH key pair                 Generate ECDH key    │
│                                            pair on startup      │
│                                                                 │
│  2. POST /auth/session         ──────────►                      │
│     { clientPublicKey }                    Derive shared secret │
│                                            Create session       │
│                          ◄──────────────   { sessionId,         │
│                                              serverPublicKey }  │
│                                                                 │
│  3. Derive shared secret                                        │
│     (same as server!)                                           │
│                                                                 │
│  4. POST /api/xxx              ──────────►                      │
│     Header: X-Session-Id                   Decrypt → Validate   │
│     Body: encrypted payload                Process → Encrypt    │
│                          ◄──────────────   Encrypted response   │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## API Endpoints

### Public (No encryption)

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/auth/pubkey` | Get server's public key |
| POST | `/auth/session` | Create session (key exchange) |

### Secure (Encrypted)

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/profile` | Get user profile |
| POST | `/api/orders` | Submit order |
| POST | `/api/transfer` | Transfer money |
| POST | `/api/secrets` | Get sensitive data |

## Usage in Your Project

### Server Side

```javascript
import { secureEndpoint } from './your-middleware.js';

// Protect any endpoint with encryption
app.post('/api/sensitive', secureEndpoint, (req, res) => {
  // req.secureBody = decrypted request
  const { userId, data } = req.secureBody;
  
  // res.json() auto-encrypts response
  res.json({ result: 'success', secret: 'data' });
});
```

### Client Side

```javascript
import { SecureApiClient } from './client.js';

const client = new SecureApiClient('https://api.example.com');
await client.connect('my-user-id');

// All requests are encrypted automatically
const result = await client.request('/api/sensitive', { 
  userId: 123,
  data: 'secret' 
});
```

## Security

| Feature | Implementation |
|---------|---------------|
| Key Exchange | ECDH (prime256v1 / P-256) |
| Encryption | AES-256-GCM |
| Anti-Replay | Unique nonce (UUID v4) + timestamp (±30s window) |
| Integrity | GCM authentication tag + AAD |

## Encrypted Message Format

```json
{
  "iv": "base64...",      // 12-byte random IV
  "data": "base64...",    // Encrypted payload
  "tag": "base64...",     // 16-byte auth tag
  "nonce": "uuid-v4",     // Unique request ID
  "ts": 1709366400000     // Timestamp (ms)
}
```
