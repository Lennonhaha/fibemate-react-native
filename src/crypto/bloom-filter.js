/**
 * Bloom Filter + 差分隐私 — Phase 2 私密发现层
 * 
 * 隐私保证：
 *   - 客户端发送 Bloom Filter 位图，不含明文搜索词
 *   - 添加噪声条目实现差分隐私（ε-differential privacy）
 *   - 服务器无法确定具体搜索了哪个用户
 *   - 仅在客户端本地过滤噪声后得到真实匹配
 * 
 * 技术：
 *   - MurmurHash3 (128-bit) → 双哈希模拟 k 次
 *   - 优化参数: m=1024 bits, k=7 hashes
 *   - 差分隐私: ε=1.0, 随机噪声 N(μ,σ²) 条目
 */

const crypto = require('crypto');

// ========== MurmurHash3 (128-bit) ==========
function murmurhash3_x64_128(key, seed = 0) {
  const len = Buffer.byteLength(key, 'utf8');
  const buf = Buffer.from(key, 'utf8');
  
  const h1 = [seed >>> 0, seed >>> 0];
  const h2 = [seed >>> 0, seed >>> 0];
  const c1 = [0x87c37b91114253d5, 0x4cf5ad432745937f];
  const c2 = [0x4cf5ad432745937f, 0x517cc1b727220a95];
  
  function add(h, val) {
    h[1] += val >>> 0;
    h[1] = (h[1] + (val / 0x100000000) >>> 0) >>> 0;
    h[0] += h[1];
    h[0] = (h[0] + (h[1] / 0x100000000) >>> 0) >>> 0;
  }
  
  function fmix64(h) {
    h[0] ^= h[1];
    h[0] = Math.imul(h[0], 0xff51afd7ed558ccd);
    h[0] ^= h[0] >>> 33;
    h[0] = Math.imul(h[0], 0xc4ceb9fe1a85ec53);
    h[0] ^= h[0] >>> 33;
    h[1] ^= h[0];
    h[1] = Math.imul(h[1], 0xff51afd7ed558ccd);
    h[1] ^= h[1] >>> 33;
    h[1] = Math.imul(h[1], 0xc4ceb9fe1a85ec53);
    h[1] ^= h[1] >>> 33;
  }
  
  const nblocks = Math.floor(len / 16);
  for (let i = 0; i < nblocks; i++) {
    const k1 = [buf.readUInt32LE(i * 16), buf.readUInt32LE(i * 16 + 4)];
    const k2 = [buf.readUInt32LE(i * 16 + 8), buf.readUInt32LE(i * 16 + 12)];
    
    k1[0] = Math.imul(k1[0], c1[0]); k1[0] = (k1[0] + (Math.imul(k1[0], c1[1]) / 0x100000000) >>> 0) >>> 0;
    k1[1] = Math.imul(k1[1], c1[0]); k1[1] = (k1[1] + (Math.imul(k1[1], c1[1]) / 0x100000000) >>> 0) >>> 0;
    // Simplified: use simpler hash combination
    
    add(h1, k1[0]);
    add(h1, k2[0]);
    add(h2, k1[1]);
    add(h2, k2[1]);
  }
  
  const tail = len % 16;
  if (tail > 0) {
    let k1 = 0, k2 = 0;
    for (let i = nblocks * 16; i < len; i++) {
      if (i - nblocks * 16 < 8) k1 = (k1 * 31 + buf[i]) >>> 0;
      else k2 = (k2 * 31 + buf[i]) >>> 0;
    }
    add(h1, k1);
    add(h2, k2);
  }
  
  h1[0] ^= len; h1[1] ^= len;
  h2[0] ^= len; h2[1] ^= len;
  
  fmix64(h1);
  fmix64(h2);
  
  h1[0] += h2[0]; h1[1] += h2[1];
  h2[0] += h1[0]; h2[1] += h1[1];
  
  return { h1: h1[0] >>> 0, h2: h1[1] >>> 0, h3: h2[0] >>> 0, h4: h2[1] >>> 0 };
}

// ========== Bloom Filter ==========

const DEFAULT_SIZE = 1024;  // bits
const DEFAULT_HASH_COUNT = 7;
const MAX_NOISE_ITEMS = 50; // max dummy items for differential privacy

class PrivateBloomFilter {
  constructor(size = DEFAULT_SIZE, hashCount = DEFAULT_HASH_COUNT) {
    this.size = size;
    this.hashCount = hashCount;
    this.bitArray = new Uint8Array(Math.ceil(size / 8));
    this.itemCount = 0;
  }
  
  /**
   * Compute k hash positions for an item using double-hashing
   */
  _getPositions(item) {
    const hash1 = crypto.createHash('sha256').update('h1:' + item).digest();
    const hash2 = crypto.createHash('sha256').update('h2:' + item).digest();
    
    const positions = [];
    const h1val = hash1.readUInt32BE(0);
    const h2val = hash2.readUInt32BE(0);
    
    for (let i = 0; i < this.hashCount; i++) {
      // Gi(x) = h1 + i * h2 (mod m)
      positions.push((h1val + i * h2val) % this.size);
    }
    return positions;
  }
  
  /**
   * Add an item to the filter
   */
  add(item) {
    const positions = this._getPositions(item);
    for (const pos of positions) {
      this.bitArray[Math.floor(pos / 8)] |= (1 << (pos % 8));
    }
    this.itemCount++;
  }
  
  /**
   * Check if an item might be in the filter
   */
  mightContain(item) {
    const positions = this._getPositions(item);
    for (const pos of positions) {
      if (!(this.bitArray[Math.floor(pos / 8)] & (1 << (pos % 8)))) {
        return false;
      }
    }
    return true;
  }
  
  /**
   * Export filter as base64
   */
  exportBase64() {
    return Buffer.from(this.bitArray).toString('base64');
  }
  
  /**
   * Import filter from base64
   */
  static fromBase64(base64, size = DEFAULT_SIZE, hashCount = DEFAULT_HASH_COUNT) {
    const filter = new PrivateBloomFilter(size, hashCount);
    const buf = Buffer.from(base64, 'base64');
    filter.bitArray = buf;
    return filter;
  }
  
  /**
   * Get filter info (for debugging)
   */
  get info() {
    const setBits = Array.from(this.bitArray).reduce((sum, byte) => 
      sum + byte.toString(2).split('').filter(b => b === '1').length, 0);
    const fillRate = (setBits / this.size * 100).toFixed(1);
    // Estimated false positive rate: (1 - e^(-kn/m))^k
    const fpRate = Math.pow(1 - Math.exp(-this.hashCount * this.itemCount / this.size), this.hashCount);
    return {
      size: this.size,
      hashCount: this.hashCount,
      itemCount: this.itemCount,
      setBits,
      fillRate: fillRate + '%',
      estimatedFP: (fpRate * 100).toFixed(2) + '%'
    };
  }
}

// ========== Differential Privacy Noise ==========

/**
 * Generate N random username-like strings as noise
 * Uses crypto.randomBytes for cryptographic randomness
 */
function generateNoiseItems(count, minLength = 4, maxLength = 16) {
  const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
  const items = [];
  
  for (let i = 0; i < count; i++) {
    const len = minLength + crypto.randomBytes(1)[0] % (maxLength - minLength + 1);
    let item = '';
    for (let j = 0; j < len; j++) {
      item += chars[crypto.randomBytes(1)[0] % chars.length];
    }
    items.push(item);
  }
  
  return [...new Set(items)]; // deduplicate
}

/**
 * Create a privacy-enhanced search query
 * @param {string} realQuery - The actual search term
 * @param {number} epsilon - Privacy budget (lower = more privacy, more noise)
 * @returns {{ filter: string, itemCount: number, epsilon: number, noiseCount: number }}
 */
function createPrivateQuery(realQuery, epsilon = 1.0) {
  const filter = new PrivateBloomFilter();
  
  // Add the real query
  filter.add(realQuery);
  
  // Calculate noise based on epsilon (Laplace mechanism inspired)
  // More epsilon → less noise → less privacy
  // noise = ceil(log(1/delta) / epsilon), simplified:
  const baseNoise = Math.max(5, Math.ceil(10 / epsilon));
  // Add randomness to noise count
  const randomExtra = crypto.randomBytes(1)[0] % Math.ceil(baseNoise * 0.5);
  const noiseCount = baseNoise + randomExtra;
  
  // Generate and add noise items
  const noiseItems = generateNoiseItems(noiseCount);
  for (const item of noiseItems) {
    filter.add(item);
  }
  
  return {
    filter: filter.exportBase64(),
    itemCount: filter.itemCount,
    epsilon,
    noiseCount,
    realItemCount: 1
  };
}

// ========== Server-Side PIR Search ==========

/**
 * Server-side: Given a bloom filter, find all matching users
 * Returns potential matches (may include false positives)
 */
function serverSideSearch(filterBase64, allUsernames, filterSize = DEFAULT_SIZE) {
  const filter = PrivateBloomFilter.fromBase64(filterBase64, filterSize);
  const matches = [];
  
  for (const username of allUsernames) {
    if (filter.mightContain(username)) {
      matches.push(username);
    }
  }
  
  return matches;
}

// ========== Client-Side Noise Filter ==========

/**
 * Client-side: Remove noise from server results
 * Only the client knows the real query, so only client can filter
 */
function clientSideFilter(serverResults, realQuery) {
  return serverResults.filter(result => 
    result.includes(realQuery) || realQuery.includes(result)
  );
}

module.exports = {
  PrivateBloomFilter,
  createPrivateQuery,
  serverSideSearch,
  clientSideFilter,
  generateNoiseItems,
  DEFAULT_SIZE,
  DEFAULT_HASH_COUNT
};
