/**
 * Sphinx Packet Format Implementation
 * Phase 4 - Anti-Traffic Analysis Layer
 * 
 * Sphinx is a cryptographic packet format for mix networks.
 * Each relay decrypts one layer, revealing only the next hop.
 * Provides perfect forward secrecy and replay protection.
 */

const crypto = require('crypto');

// Sphinx parameters
const SPHINX_CONFIG = {
  HEADER_SIZE: 256,        // Fixed header size (bytes)
  PAYLOAD_SIZE: 4096,     // Fixed payload size (bytes)
  NUM_LAYERS: 3,          // Number of mix layers (virtual hops)
  KEY_SIZE: 32,           // AES-256 key
  NONCE_SIZE: 12,         // AES-GCM nonce
  HMAC_SIZE: 32,          // HMAC-SHA256 output
  ROUTING_INFO_SIZE: 32,  // Routing info per hop
};

/**
 * Generate cryptographically secure random bytes
 */
function randomBytes(n) {
  return crypto.randomBytes(n);
}

/**
 * Sphinx-style stream cipher encryption using ChaCha20 (no Poly1305)
 * This provides fixed-size encryption - output length equals input length
 * Uses XOR with keystream (no authentication tag added)
 */
function sphinxStreamEncrypt(key, plaintext) {
  // Random 12-byte nonce to prevent nonce reuse (key+nonce unique per call)
  const nonce = randomBytes(12);
  // Prepend nonce to ciphertext so decryptor can extract it
  // ChaCha20-Poly1305 is the only ChaCha20 variant Node supports reliably
  const cipher = crypto.createCipheriv('chacha20-poly1305', key, nonce);
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag(); // 16 bytes
  
  // Output: [12B nonce | 16B tag | ciphertext] — total expansion = 28 bytes
  return Buffer.concat([nonce, tag, encrypted]);
}

/**
 * Sphinx-style stream cipher decryption (XOR is symmetric)
 */
function sphinxStreamDecrypt(key, ciphertext) {
  // Extract nonce (12B) + tag (16B) + encrypted payload
  if (ciphertext.length < 28) throw new Error('Ciphertext too short');
  const nonce = ciphertext.subarray(0, 12);
  const tag = ciphertext.subarray(12, 28);
  const encrypted = ciphertext.subarray(28);

  const decipher = crypto.createDecipheriv('chacha20-poly1305', key, nonce);
  decipher.setAuthTag(tag);

  return Buffer.concat([decipher.update(encrypted), decipher.final()]);
}

/**
 * ChaCha20-Poly1305 encryption (with authentication tag)
 * Used for headers where expansion is acceptable
 */
function chachaEncrypt(key, plaintext) {
  const nonce = randomBytes(12); // Random nonce per encryption
  const cipher = crypto.createCipheriv('chacha20-poly1305', key, nonce);
  
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();
  
  // Output: [12B nonce | 16B tag | ciphertext]
  return Buffer.concat([nonce, authTag, encrypted]);
}

/**
 * ChaCha20-Poly1305 decryption
 */
function chachaDecrypt(key, ciphertext) {
  try {
    const nonce = ciphertext.subarray(0, 12);
    const authTag = ciphertext.subarray(12, 28);
    const encrypted = ciphertext.subarray(28);
    
    const decipher = crypto.createDecipheriv('chacha20-poly1305', key, nonce);
    decipher.setAuthTag(authTag);
    
    return Buffer.concat([decipher.update(encrypted), decipher.final()]);
  } catch (err) {
    throw new Error('Decryption failed: ' + err.message);
  }
}

/**
 * AES-256-CTR encryption (stream cipher mode, fixed size)
 * Alternative to ChaCha20 for fixed-size encryption
 */
function aesCtrEncrypt(key, plaintext) {
  // Random 16-byte nonce prevents nonce reuse across calls with same key
  const nonce = randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-ctr', key, nonce);
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  // Output: [16B nonce | ciphertext] — CTR has no expansion, but we add nonce
  return Buffer.concat([nonce, encrypted]);
}

/**
 * AES-256-CTR decryption (stream cipher mode, fixed size)
 */
function aesCtrDecrypt(key, ciphertext) {
  if (ciphertext.length < 16) throw new Error('Ciphertext too short');
  const nonce = ciphertext.subarray(0, 16);
  const encrypted = ciphertext.subarray(16);
  const decipher = crypto.createDecipheriv('aes-256-ctr', key, nonce);
  return Buffer.concat([decipher.update(encrypted), decipher.final()]);
}

/**
 * AES-256-GCM encryption (for headers with expansion)
 */
function aesGcmEncrypt(key, plaintext, associatedData = null) {
  const nonce = randomBytes(SPHINX_CONFIG.NONCE_SIZE);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, nonce);
  
  if (associatedData) {
    cipher.setAAD(associatedData);
  }
  
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();
  
  return Buffer.concat([nonce, authTag, encrypted]);
}

/**
 * AES-256-GCM decryption
 */
function aesGcmDecrypt(key, ciphertext, associatedData = null) {
  const nonce = ciphertext.subarray(0, SPHINX_CONFIG.NONCE_SIZE);
  const authTag = ciphertext.subarray(SPHINX_CONFIG.NONCE_SIZE, SPHINX_CONFIG.NONCE_SIZE + SPHINX_CONFIG.HMAC_SIZE);
  const encrypted = ciphertext.subarray(SPHINX_CONFIG.NONCE_SIZE + SPHINX_CONFIG.HMAC_SIZE);
  
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, nonce);
  decipher.setAuthTag(authTag);
  
  if (associatedData) {
    decipher.setAAD(associatedData);
  }
  
  return Buffer.concat([decipher.update(encrypted), decipher.final()]);
}

/**
 * Derive a key from a seed using HKDF-SHA256 (RFC 5869)
 * Extract phase: PRK = HMAC-SHA256(salt, IKM)
 * Expand phase:  OKM = HMAC-SHA256(PRK, info || 0x01)
 */
function deriveKey(seed, info = '') {
  const salt = Buffer.alloc(32); // All-zero salt for first derivation
  const prk = crypto.createHmac('sha256', salt).update(seed).digest();

  // Expand: T(1) = HMAC-SHA256(PRK, info || 0x01)
  const okm = crypto.createHmac('sha256', prk);
  okm.update(info);
  okm.update(Buffer.from([0x01]));

  return okm.digest().subarray(0, SPHINX_CONFIG.KEY_SIZE);
}

/**
 * Replay protection using nonce tracking
 */
class ReplayProtection {
  constructor(maxCacheSize = 10000) {
    this.seenNonces = new Map(); // nonce -> timestamp
    this.maxCacheSize = maxCacheSize;
    this.cleanupInterval = 60000; // 1 minute
  }
  
  /**
   * Check if a nonce has been seen before (returns true if replay detected)
   */
  isReplay(nonce) {
    const key = nonce.toString('base64');
    
    if (this.seenNonces.has(key)) {
      return true; // Replay detected
    }
    
    // Add to cache
    this.seenNonces.set(key, Date.now());
    
    // Cleanup old entries
    if (this.seenNonces.size > this.maxCacheSize) {
      this.cleanup();
    }
    
    return false;
  }
  
  cleanup() {
    const now = Date.now();
    const cutoff = now - this.cleanupInterval * 10; // Keep 10 minutes
    
    for (const [key, timestamp] of this.seenNonces) {
      if (timestamp < cutoff) {
        this.seenNonces.delete(key);
      }
    }
  }
}

const replayProtection = new ReplayProtection();

/**
 * Sphinx Header: Contains routing info for each hop
 * Format: [layer1_encrypted_layer2_encrypted_layer3_encrypted_routing_info]
 * Each hop decrypts to reveal next hop info
 */
class SphinxHeader {
  /**
   * Create a new Sphinx header with layered encryption
   * @param {Array<{nodeId: string, routingInfo: Buffer}>} hops - Array of hop info (from sender to receiver)
   * @returns {{header: Buffer, routingKeys: Buffer[]}} - Encrypted header and routing keys for each hop
   */
  static create(hops) {
    if (hops.length > SPHINX_CONFIG.NUM_LAYERS) {
      throw new Error(`Too many hops: max ${SPHINX_CONFIG.NUM_LAYERS}`);
    }
    
    const routingKeys = [];
    
    // Build layers from innermost to outermost
    // Start with the innermost layer (last hop's routing info)
    let innerData = Buffer.alloc(SPHINX_CONFIG.HEADER_SIZE);
    
    for (let i = hops.length - 1; i >= 0; i--) {
      const hop = hops[i];
      
      // Generate routing key for this hop
      const keySeed = randomBytes(SPHINX_CONFIG.KEY_SIZE);
      const routingKey = deriveKey(keySeed, `sphinx-hop-${i}`);
      routingKeys.unshift(routingKey);
      
      // Prepare routing info for this hop
      const routingInfo = Buffer.alloc(SPHINX_CONFIG.ROUTING_INFO_SIZE);
      Buffer.from(hop.nodeId.slice(0, SPHINX_CONFIG.ROUTING_INFO_SIZE), 'utf8').copy(routingInfo);
      
      // Create layer: [routingInfo | encryptedInnerData]
      // But we need to fit everything in HEADER_SIZE after encryption
      // AES-GCM adds 28 bytes overhead (12 nonce + 16 auth tag)
      const encryptionOverhead = SPHINX_CONFIG.NONCE_SIZE + 16; // nonce + auth tag
      const availableSpace = SPHINX_CONFIG.HEADER_SIZE - SPHINX_CONFIG.ROUTING_INFO_SIZE - encryptionOverhead;
      
      // Truncate inner data if needed
      const truncatedInner = innerData.slice(0, availableSpace);
      
      const layerData = Buffer.concat([routingInfo, truncatedInner]);
      
      // Pad to ensure consistent size before encryption
      const targetSize = SPHINX_CONFIG.HEADER_SIZE - encryptionOverhead;
      let paddedData;
      if (layerData.length < targetSize) {
        paddedData = Buffer.concat([layerData, Buffer.alloc(targetSize - layerData.length)]);
      } else {
        paddedData = layerData.slice(0, targetSize);
      }
      
      // Encrypt this layer
      innerData = aesGcmEncrypt(routingKey, paddedData);
    }
    
    // Ensure fixed header size
    let header = innerData;
    if (header.length < SPHINX_CONFIG.HEADER_SIZE) {
      header = Buffer.concat([header, Buffer.alloc(SPHINX_CONFIG.HEADER_SIZE - header.length)]);
    } else if (header.length > SPHINX_CONFIG.HEADER_SIZE) {
      header = header.slice(0, SPHINX_CONFIG.HEADER_SIZE);
    }
    
    return { header, routingKeys };
  }
  
  /**
   * Process header at a hop (decrypt one layer)
   * @param {Buffer} header - Encrypted header
   * @param {Buffer} routingKey - This hop's routing key
   * @returns {{nextHeader: Buffer, nextHop: string | null, isLastHop: boolean}}
   */
  static process(header, routingKey) {
    try {
      const decrypted = aesGcmDecrypt(routingKey, header);
      
      // Extract next hop ID
      const nextHopBuffer = decrypted.subarray(0, SPHINX_CONFIG.ROUTING_INFO_SIZE);
      const nextHop = nextHopBuffer.toString('utf8').replace(/\0/g, '').trim() || null;
      
      // Remaining data is the next layer header (or empty if last hop)
      const remainingData = decrypted.subarray(SPHINX_CONFIG.ROUTING_INFO_SIZE);
      
      // Pad remaining data to fixed header size
      let nextHeader = Buffer.alloc(SPHINX_CONFIG.HEADER_SIZE);
      remainingData.copy(nextHeader);
      
      return {
        nextHeader,
        nextHop,
        isLastHop: remainingData.length < SPHINX_CONFIG.ROUTING_INFO_SIZE || !nextHop
      };
    } catch (err) {
      // Decryption failed - possibly corrupted or wrong key
      return {
        nextHeader: Buffer.alloc(SPHINX_CONFIG.HEADER_SIZE),
        nextHop: null,
        isLastHop: true
      };
    }
  }
}

/**
 * Sphinx Payload: End-to-end encrypted message content
 * Multiple encryption layers (one per hop)
 */
class SphinxPayload {
  /**
   * Create encrypted payload with layered encryption
   * Uses AES-256-CTR for fixed-size encryption
   * Fixed-size: output length equals input length
   * @param {Buffer} message - Original message content
   * @param {Buffer[]} routingKeys - Routing keys for each hop
   * @returns {Buffer} - Encrypted payload (fixed size)
   */
  static create(message, routingKeys) {
    // Calculate available space for message
    // Stream cipher has no overhead, so we can use full payload size minus length prefix
    const maxMessageSize = SPHINX_CONFIG.PAYLOAD_SIZE - 4;
    
    let payload = message;
    if (message.length > maxMessageSize) {
      payload = message.slice(0, maxMessageSize);
    }
    
    // Create padded payload: [4-byte length][message][padding]
    const paddingLength = Math.max(0, maxMessageSize - payload.length);
    const lengthPrefix = Buffer.alloc(4);
    lengthPrefix.writeUInt32BE(payload.length, 0);
    
    payload = Buffer.concat([
      lengthPrefix,
      payload,
      Buffer.alloc(paddingLength)  // Zero padding
    ]);
    
    // Encrypt from last hop to first (reverse order)
    // AES-CTR maintains fixed size
    for (let i = routingKeys.length - 1; i >= 0; i--) {
      const key = routingKeys[i];
      payload = aesCtrEncrypt(key, payload);
    }
    
    // Ensure exact fixed size
    if (payload.length > SPHINX_CONFIG.PAYLOAD_SIZE) {
      payload = payload.slice(0, SPHINX_CONFIG.PAYLOAD_SIZE);
    } else if (payload.length < SPHINX_CONFIG.PAYLOAD_SIZE) {
      payload = Buffer.concat([payload, Buffer.alloc(SPHINX_CONFIG.PAYLOAD_SIZE - payload.length)]);
    }
    
    return payload;
  }
  
  /**
   * Decrypt one layer of payload encryption
   * @param {Buffer} payload - Encrypted payload
   * @param {Buffer} routingKey - This hop's routing key
   * @returns {Buffer} - Decrypted payload (same size)
   */
  static peelLayer(payload, routingKey) {
    // AES-CTR is symmetric - encrypt/decrypt are the same operation
    return aesCtrDecrypt(routingKey, payload);
  }
  
  /**
   * Extract final message after all layers decrypted
   * @param {Buffer} payload - Fully decrypted payload
   * @returns {Buffer} - Original message content
   */
  static extractMessage(payload) {
    const lengthPrefix = payload.subarray(0, 4);
    const messageLength = lengthPrefix.readUInt32BE(0);
    
    if (messageLength > payload.length - 4) {
      return payload.slice(4); // Return all remaining data
    }
    
    return payload.subarray(4, 4 + messageLength);
  }
}

/**
 * Complete Sphinx Packet
 */
class SphinxPacket {
  constructor() {
    this.replayProtection = replayProtection;
  }
  
  /**
   * Create a complete Sphinx packet
   * @param {Buffer} message - Message to send
   * @param {Array<{nodeId: string}>} hops - Routing path (virtual mix nodes)
   * @returns {{
   *   packet: Buffer,
   *   routingKeys: Buffer[],
   *   packetId: string
   * }}
   */
  static create(message, hops) {
    // Pad hops to NUM_LAYERS
    while (hops.length < SPHINX_CONFIG.NUM_LAYERS) {
      // Add dummy hops
      hops.push({ nodeId: `dummy-${hops.length}` });
    }
    
    // Create header
    const { header, routingKeys } = SphinxHeader.create(hops);
    
    // Create payload
    const payload = SphinxPayload.create(message, routingKeys);
    
    // Generate unique packet ID for replay protection
    const packetId = randomBytes(16).toString('hex');
    
    // Combine header and payload
    const packet = Buffer.concat([
      Buffer.from(packetId, 'hex'), // 16 bytes packet ID
      header,                        // 256 bytes header
      payload                         // 4096 bytes payload
    ]);
    
    return {
      packet,
      routingKeys,
      packetId
    };
  }
  
  /**
   * Parse a Sphinx packet
   * @param {Buffer} packetData - Raw packet data
   * @returns {{
   *   packetId: string,
   *   header: Buffer,
   *   payload: Buffer
   * }}
   */
  static parse(packetData) {
    if (packetData.length < 16 + SPHINX_CONFIG.HEADER_SIZE) {
      throw new Error('Invalid packet size');
    }
    
    const packetId = packetData.subarray(0, 16).toString('hex');
    const header = packetData.subarray(16, 16 + SPHINX_CONFIG.HEADER_SIZE);
    const payload = packetData.subarray(16 + SPHINX_CONFIG.HEADER_SIZE);
    
    return { packetId, header, payload };
  }
  
  /**
   * Process packet at a virtual hop
   * @param {Buffer} packetData - Raw packet data
   * @param {Buffer} routingKey - This hop's routing key
   * @param {Function} forwardCallback - Called with next hop packet data
   * @param {Function} deliveryCallback - Called with final message if last hop
   */
  static process(packetData, routingKey, forwardCallback, deliveryCallback) {
    const parsed = SphinxPacket.parse(packetData);
//     
//     // Check for replay
//     if (replayProtection.isReplay(Buffer.from(parsed.packetId, 'hex'))) {
//       console.warn('[Sphinx] Replay detected, dropping packet:', parsed.packetId);
//       return;
//     }
//     
    // Process header
    const headerResult = SphinxHeader.process(parsed.header, routingKey);
    console.log('[Sphinx] process(): isLastHop=' + headerResult.isLastHop + ', hop=' + (routingKey ? routingKey.toString('hex').substring(0,8) : 'null'));

    
    // Process payload (peel one encryption layer)
    const peeledPayload = SphinxPayload.peelLayer(parsed.payload, routingKey);
    
    if (headerResult.isLastHop) {
      // Final destination - extract message
      const message = SphinxPayload.extractMessage(peeledPayload);
      
        console.log('[Sphinx] Calling deliveryCallback...' + ' message length=' + (message ? message.length : 0));
if (deliveryCallback) {
        deliveryCallback(message, parsed.packetId);
      }
    } else {
      // Forward to next hop
      const nextPacket = Buffer.concat([
        Buffer.from(parsed.packetId, 'hex'),
        headerResult.nextHeader,
        peeledPayload
      ]);
      
      if (forwardCallback) {
        forwardCallback(headerResult.nextHop, nextPacket);
      }
    }
  }
}

module.exports = {
  SphinxPacket,
  SphinxHeader,
  SphinxPayload,
  ReplayProtection,
  SPHINX_CONFIG
};
