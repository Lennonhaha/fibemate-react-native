/**
 * Traffic Shaping for Anti-Traffic Analysis
 * Phase 4 - Rate limiting + Poisson cover traffic + Flow correlation resistance
 * 
 * Goals:
 * 1. Poisson process cover traffic - unpredictable message timing
 * 2. Rate shaping - prevent burst patterns
 * 3. Flow correlation resistance - random drop/delay
 */

const crypto = require('crypto');

// Traffic shaping parameters
const TRAFFIC_CONFIG = {
  // Poisson cover traffic
  POISSON_LAMBDA: 0.1,        // Average messages per second (λ)
  COVER_MIN_INTERVAL: 5000,   // Minimum 5s between cover messages
  COVER_MAX_INTERVAL: 60000,  // Maximum 60s between cover messages
  
  // Rate limiting
  MAX_MESSAGES_PER_MINUTE: 30,  // Rate limit
  BURST_ALLOWANCE: 5,           // Allow short bursts
  
  // Flow correlation resistance
  DROP_PROBABILITY: 0.02,       // 2% random drop
  EXTRA_DELAY_MIN: 100,         // Additional random delay (ms)
  EXTRA_DELAY_MAX: 2000,
  
  // Traffic padding
  MIN_MESSAGE_SIZE: 512,        // Minimum message size
  MAX_MESSAGE_SIZE: 4096,       // Maximum message size
};

/**
 * Poisson process generator for cover traffic
 * Generates random intervals between messages
 */
class PoissonCoverTraffic {
  constructor(config = {}) {
    this.lambda = config.lambda || TRAFFIC_CONFIG.POISSON_LAMBDA;
    this.minInterval = config.minInterval || TRAFFIC_CONFIG.COVER_MIN_INTERVAL;
    this.maxInterval = config.maxInterval || TRAFFIC_CONFIG.COVER_MAX_INTERVAL;
    this.nextMessageTime = Date.now();
    this.callbacks = [];
    this.running = false;
    this.timerId = null;
  }
  
  /**
   * Generate next interval using Poisson distribution
   * P(k events in interval) = (λ^k * e^-λ) / k!
   * For inter-arrival times: exponential distribution with rate λ
   */
  generateInterval() {
    // Exponential distribution: -ln(U) / λ where U is uniform(0,1)
    const u = crypto.randomBytes(4).readUInt32BE(0) / 0xFFFFFFFF;
    const exponential = -Math.log(u) / this.lambda;
    
    // Convert to milliseconds and clamp to bounds
    const interval = Math.floor(exponential * 1000);
    return Math.max(this.minInterval, Math.min(this.maxInterval, interval));
  }
  
  /**
   * Start generating cover traffic
   * @param {Function} callback - Called when a cover message should be sent
   */
  start(callback) {
    if (this.running) return;
    
    this.running = true;
    this.callbacks.push(callback);
    this.scheduleNext();
  }
  
  /**
   * Stop generating cover traffic
   */
  stop() {
    this.running = false;
    if (this.timerId) {
      clearTimeout(this.timerId);
      this.timerId = null;
    }
    this.callbacks = [];
  }
  
  /**
   * Schedule next cover message
   */
  scheduleNext() {
    if (!this.running) return;
    
    const interval = this.generateInterval();
    this.nextMessageTime = Date.now() + interval;
    
    this.timerId = setTimeout(() => {
      if (this.running) {
        // Generate cover message
        const coverMsg = this.generateCoverMessage();
        
        // Notify all callbacks
        this.callbacks.forEach(cb => {
          try {
            cb(coverMsg);
          } catch (err) {
            console.error('[PoissonCoverTraffic] Callback error:', err.message);
          }
        });
        
        // Schedule next
        this.scheduleNext();
      }
    }, interval);
  }
  
  /**
   * Generate a cover message (fake message)
   */
  generateCoverMessage() {
    const size = TRAFFIC_CONFIG.MIN_MESSAGE_SIZE + 
      Math.floor(Math.random() * (TRAFFIC_CONFIG.MAX_MESSAGE_SIZE - TRAFFIC_CONFIG.MIN_MESSAGE_SIZE));
    
    return {
      type: 'cover',
      data: crypto.randomBytes(size),
      timestamp: Date.now(),
      isCover: true
    };
  }
  
  /**
   * Get statistics
   */
  getStats() {
    return {
      running: this.running,
      lambda: this.lambda,
      nextMessageIn: Math.max(0, this.nextMessageTime - Date.now()),
      callbacksCount: this.callbacks.length
    };
  }
}

/**
 * Rate limiter with token bucket algorithm
 */
class RateLimiter {
  constructor(config = {}) {
    this.maxTokens = config.maxTokens || TRAFFIC_CONFIG.MAX_MESSAGES_PER_MINUTE;
    this.burstAllowance = config.burstAllowance || TRAFFIC_CONFIG.BURST_ALLOWANCE;
    this.refillRate = this.maxTokens / 60000; // Tokens per ms
    this.tokens = this.maxTokens;
    this.lastRefill = Date.now();
    this.userBuckets = new Map(); // Per-user rate limiting
  }
  
  /**
   * Check if user can send a message (token bucket)
   * @param {string} userId - User identifier
   * @returns {{allowed: boolean, waitTime: number, tokensRemaining: number}}
   */
  canSend(userId) {
    this.refillTokens(userId);
    
    const bucket = this.userBuckets.get(userId);
    
    if (bucket.tokens >= 1) {
      bucket.tokens--;
      return { allowed: true, waitTime: 0, tokensRemaining: bucket.tokens };
    }
    
    // Calculate wait time until next token
    const waitTime = Math.ceil((1 - bucket.tokens) / this.refillRate);
    return { allowed: false, waitTime, tokensRemaining: bucket.tokens };
  }
  
  /**
   * Refill tokens based on time elapsed
   */
  refillTokens(userId) {
    const now = Date.now();
    
    if (!this.userBuckets.has(userId)) {
      this.userBuckets.set(userId, {
        tokens: this.maxTokens,
        lastRefill: now
      });
      return;
    }
    
    const bucket = this.userBuckets.get(userId);
    const elapsed = now - bucket.lastRefill;
    const refill = elapsed * this.refillRate;
    
    bucket.tokens = Math.min(this.maxTokens + this.burstAllowance, bucket.tokens + refill);
    bucket.lastRefill = now;
  }
  
  /**
   * Reset rate limiter for a user
   */
  reset(userId) {
    this.userBuckets.delete(userId);
  }
  
  /**
   * Get current state for a user
   */
  getState(userId) {
    this.refillTokens(userId);
    const bucket = this.userBuckets.get(userId);
    return {
      tokens: bucket ? bucket.tokens : this.maxTokens,
      maxTokens: this.maxTokens,
      burstAllowance: this.burstAllowance
    };
  }
}

/**
 * Flow correlation resistance
 * Adds random delays and drops to break timing patterns
 */
class FlowCorrelationResistance {
  constructor(config = {}) {
    this.dropProbability = config.dropProbability || TRAFFIC_CONFIG.DROP_PROBABILITY;
    this.extraDelayMin = config.extraDelayMin || TRAFFIC_CONFIG.EXTRA_DELAY_MIN;
    this.extraDelayMax = config.extraDelayMax || TRAFFIC_CONFIG.EXTRA_DELAY_MAX;
    this.pendingMessages = new Map();
  }
  
  /**
   * Process a message with random delay/drop
   * @param {*} message - Message to process
   * @param {Function} deliverCallback - Called when message should be delivered
   * @returns {{accepted: boolean, delay: number, willDrop: boolean}}
   */
  process(message, deliverCallback) {
    // Random drop decision
    const willDrop = Math.random() < this.dropProbability;
    
    if (willDrop) {
      return { accepted: false, delay: 0, willDrop: true };
    }
    
    // Calculate random delay
    const delay = this.extraDelayMin + 
      Math.floor(Math.random() * (this.extraDelayMax - this.extraDelayMin));
    
    // Schedule delivery
    const msgId = crypto.randomBytes(8).toString('hex');
    const timerId = setTimeout(() => {
      this.pendingMessages.delete(msgId);
      if (deliverCallback) {
        deliverCallback(message);
      }
    }, delay);
    
    this.pendingMessages.set(msgId, {
      message,
      timerId,
      scheduledAt: Date.now(),
      delay
    });
    
    return { accepted: true, delay, willDrop: false, msgId };
  }
  
  /**
   * Cancel a pending message
   */
  cancel(msgId) {
    const pending = this.pendingMessages.get(msgId);
    if (pending) {
      clearTimeout(pending.timerId);
      this.pendingMessages.delete(msgId);
      return true;
    }
    return false;
  }
  
  /**
   * Get statistics
   */
  getStats() {
    return {
      dropProbability: this.dropProbability,
      pendingCount: this.pendingMessages.size,
      delayRange: `${this.extraDelayMin}-${this.extraDelayMax}ms`
    };
  }
}

/**
 * Traffic shaper - combines all components
 */
class TrafficShaper {
  constructor(config = {}) {
    this.config = { ...TRAFFIC_CONFIG, ...config };
    this.rateLimiter = new RateLimiter(this.config);
    this.flowResistance = new FlowCorrelationResistance(this.config);
    this.coverTraffic = null;
    this.enabled = false;
  }
  
  /**
   * Enable traffic shaping
   * @param {Function} coverCallback - Called when cover message should be sent
   */
  enable(coverCallback) {
    if (this.enabled) return;
    
    this.enabled = true;
    
    // Start Poisson cover traffic
    this.coverTraffic = new PoissonCoverTraffic(this.config);
    if (coverCallback) {
      this.coverTraffic.start(coverCallback);
    }
    
    console.log('[TrafficShaper] Enabled - Poisson λ=' + this.config.POISSON_LAMBDA + 
      ', rate limit=' + this.config.MAX_MESSAGES_PER_MINUTE + '/min');
  }
  
  /**
   * Disable traffic shaping
   */
  disable() {
    this.enabled = false;
    if (this.coverTraffic) {
      this.coverTraffic.stop();
      this.coverTraffic = null;
    }
    console.log('[TrafficShaper] Disabled');
  }
  
  /**
   * Process outgoing message
   * @param {string} userId - Sender ID
   * @param {*} message - Message to send
   * @param {Function} deliverCallback - Called when message should be delivered
   * @returns {{allowed: boolean, reason?: string, delay?: number}}
   */
  processOutgoing(userId, message, deliverCallback) {
    if (!this.enabled) {
      if (deliverCallback) deliverCallback(message);
      return { allowed: true };
    }
    
    // Rate limit check
    const rateCheck = this.rateLimiter.canSend(userId);
    if (!rateCheck.allowed) {
      return { 
        allowed: false, 
        reason: 'rate_limit',
        waitTime: rateCheck.waitTime,
        tokensRemaining: rateCheck.tokensRemaining
      };
    }
    
    // Flow correlation resistance
    const flowResult = this.flowResistance.process(message, deliverCallback);
    
    if (!flowResult.accepted) {
      return { allowed: false, reason: 'random_drop' };
    }
    
    return { 
      allowed: true, 
      delay: flowResult.delay,
      msgId: flowResult.msgId
    };
  }
  
  /**
   * Cancel a pending message
   */
  cancelPending(msgId) {
    return this.flowResistance.cancel(msgId);
  }
  
  /**
   * Get comprehensive statistics
   */
  getStats() {
    return {
      enabled: this.enabled,
      rateLimiter: {
        // Global stats, not per-user
      },
      flowResistance: this.flowResistance.getStats(),
      coverTraffic: this.coverTraffic ? this.coverTraffic.getStats() : null
    };
  }
}

module.exports = {
  TrafficShaper,
  PoissonCoverTraffic,
  RateLimiter,
  FlowCorrelationResistance,
  TRAFFIC_CONFIG
};
