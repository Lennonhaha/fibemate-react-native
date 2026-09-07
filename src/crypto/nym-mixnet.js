/**
 * Nym Mixnet - Virtual Mix Node Routing with Sphinx Packets
 * Phase 4 - Anti-Traffic Analysis Layer
 * 
 * Implements virtual mix nodes on a single server.
 * Routes Sphinx packets through multiple layers of virtual nodes.
 * Provides reply blocks for anonymous responses.
 */

const { SphinxPacket, SPHINX_CONFIG } = require('./sphinx-packet');
const { TrafficShaper } = require('./traffic-shaping');
const crypto = require('crypto');

// Nym mixnet configuration
const NYM_CONFIG = {
  NUM_VIRTUAL_NODES: 5,       // Number of virtual mix nodes
  ROUTING_DELAY_MIN: 50,      // Minimum delay at each hop (ms)
  ROUTING_DELAY_MAX: 500,     // Maximum delay at each hop (ms)
  REPLY_BLOCK_TTL: 3600000,   // Reply block lifetime (1 hour)
  PATH_SELECTION: 'random',   // random | balanced | load-aware
};

/**
 * Virtual Mix Node
 * Simulates a mix node in the network
 */
class VirtualMixNode {
  constructor(nodeId, config = {}) {
    this.nodeId = nodeId;
    this.config = config;
    this.routingKey = crypto.randomBytes(SPHINX_CONFIG.KEY_SIZE);
    this.messageQueue = [];
    this.stats = {
      processed: 0,
      forwarded: 0,
      delivered: 0,
      dropped: 0
    };
  }
  
  /**
   * Get node's routing key (for Sphinx packet processing)
   */
  getRoutingKey() {
    return this.routingKey;
  }
  
  /**
   * Process a packet at this virtual node
   * @param {Buffer} packetData - Sphinx packet
   * @param {Function} forwardCallback - Called with (nextHop, packet) to forward
   * @param {Function} deliverCallback - Called with (message, packetId) for final delivery
   */
  process(packetData, forwardCallback, deliverCallback) {
    // Add to queue for timing obfuscation
    const delay = NYM_CONFIG.ROUTING_DELAY_MIN + 
      Math.floor(Math.random() * (NYM_CONFIG.ROUTING_DELAY_MAX - NYM_CONFIG.ROUTING_DELAY_MIN));
    
    setTimeout(() => {
      try {
        SphinxPacket.process(
          packetData,
          this.routingKey,
          (nextHop, packet) => {
            this.stats.forwarded++;
            if (forwardCallback) {
              forwardCallback(nextHop, packet);
            }
          },
          (message, packetId) => {
            this.stats.delivered++;
            if (deliverCallback) {
              deliverCallback(message, packetId);
            }
          }
        );
        this.stats.processed++;
      } catch (err) {
        this.stats.dropped++;
        console.error(`[VirtualMixNode ${this.nodeId}] Error:`, err.message);
      }
    }, delay);
  }
  
  /**
   * Get node statistics
   */
  getStats() {
    return {
      nodeId: this.nodeId,
      ...this.stats
    };
  }
}

/**
 * Reply Block - Anonymous return address
 * Allows recipients to reply without revealing their identity
 */
class ReplyBlock {
  constructor(recipientId, path, routingKeys) {
    this.recipientId = recipientId;
    this.path = path;
    this.routingKeys = routingKeys;
    this.createdAt = Date.now();
    this.expiresAt = this.createdAt + NYM_CONFIG.REPLY_BLOCK_TTL;
    this.used = false;
    this.blockId = crypto.randomBytes(16).toString('hex');
  }
  
  /**
   * Check if reply block is valid
   */
  isValid() {
    return !this.used && Date.now() < this.expiresAt;
  }
  
  /**
   * Create a message using this reply block
   * @param {Buffer} message - Message to send
   * @returns {Buffer} - Sphinx packet ready to send
   */
  createReply(message) {
    if (!this.isValid()) {
      throw new Error('Reply block expired or already used');
    }
    
    // Reverse the path for reply
    const replyPath = [...this.path].reverse();
    
    // Create Sphinx packet with reversed path
    const { packet } = SphinxPacket.create(message, replyPath);
    
    this.used = true;
    return packet;
  }
  
  /**
   * Serialize reply block for sharing
   */
  serialize() {
    return {
      blockId: this.blockId,
      recipientId: this.recipientId,
      path: this.path.map(p => p.nodeId),
      createdAt: this.createdAt,
      expiresAt: this.expiresAt
    };
  }
}

/**
 * Nym Mixnet - Main class
 * Coordinates virtual mix nodes and routes Sphinx packets
 */
class NymMixnet {
  constructor(db, onlineUsers, sendToUserCallback, config = {}) {
    this.db = db;
    this.onlineUsers = onlineUsers;
    this.sendToUser = sendToUserCallback;
    this.config = { ...NYM_CONFIG, ...config };
    
    // Create virtual mix nodes
    this.nodes = new Map();
    this.nodeList = [];
    for (let i = 0; i < this.config.NUM_VIRTUAL_NODES; i++) {
      const nodeId = `vnode-${i}`;
      const node = new VirtualMixNode(nodeId, this.config);
      this.nodes.set(nodeId, node);
      this.nodeList.push(node);
    }
    
    // Reply block registry
    this.replyBlocks = new Map();
    
    // Traffic shaper
    this.trafficShaper = new TrafficShaper(this.config);
    
    console.log(`[NymMixnet] Initialized with ${this.nodes.size} virtual mix nodes`);
  }
  
  /**
   * Start the mixnet
   */
  start() {
    // Enable traffic shaper with cover traffic callback
    this.trafficShaper.enable((coverMsg) => {
      this.processCoverMessage(coverMsg);
    });
    
    console.log('[NymMixnet] Started with Poisson cover traffic');
  }
  
  /**
   * Stop the mixnet
   */
  stop() {
    this.trafficShaper.disable();
    console.log('[NymMixnet] Stopped');
  }
  
  /**
   * Select a random path through the mixnet
   * @param {string} destinationId - Final destination user ID
   * @returns {Array<{nodeId: string}>} - Path from sender to receiver
   */
  selectPath(destinationId) {
    // Shuffle virtual nodes
    const shuffledNodes = [...this.nodeList].sort(() => Math.random() - 0.5);
    
    // Select first SPHINX_CONFIG.NUM_LAYERS nodes
    const path = shuffledNodes.slice(0, SPHINX_CONFIG.NUM_LAYERS - 1);
    
    // Add destination as final hop
    path.push({ nodeId: `user:${destinationId}` });
    
    return path;
  }
  
  /**
   * Send a message through the mixnet
   * @param {string} fromUserId - Sender ID
   * @param {string} toUserId - Recipient ID
   * @param {Buffer} message - Message content (already encrypted)
   * @param {boolean} useReplyBlock - Use reply block if available
   * @returns {{success: boolean, path?: Array, packetId?: string}}
   */
  sendMessage(fromUserId, toUserId, message, useReplyBlock = false) {
    // Rate limiting
    const rateCheck = this.trafficShaper.rateLimiter.canSend(fromUserId);
    if (!rateCheck.allowed) {
      console.warn(`[NymMixnet] Rate limit hit for user ${fromUserId}`);
      return { success: false, reason: 'rate_limit' };
    }
    
    // Select path
    const path = this.selectPath(toUserId);
    
    // Create Sphinx packet
    const { packet, routingKeys, packetId } = SphinxPacket.create(message, path);
    
    // Start routing through virtual nodes
    this.routePacket(packet, path, routingKeys, 0, toUserId);
    
    return { success: true, path: path.map(p => p.nodeId), packetId };
  }
  
  /**
   * Route a packet through virtual nodes
   */
  routePacket(packet, path, routingKeys, currentIndex, finalRecipientId) {
    if (currentIndex >= path.length - 1) {
      // Final hop - deliver to user
      this.deliverToUser(finalRecipientId, packet, routingKeys[currentIndex]);
      return;
    }
    
    const currentNodeId = path[currentIndex].nodeId;
    const node = this.nodes.get(currentNodeId);
    
    if (!node) {
      console.error(`[NymMixnet] Node not found: ${currentNodeId}`);
      return;
    }
    
    // Process at virtual node
    node.process(
      packet,
      (nextHop, nextPacket) => {
        // Forward to next virtual node
        const nextIndex = currentIndex + 1;
        if (nextIndex < path.length) {
          this.routePacket(nextPacket, path, routingKeys, nextIndex, finalRecipientId);
        }
      },
      (message, packetId) => {
        // Should not reach here before final hop
        console.log(`[NymMixnet] Early delivery at node ${currentNodeId}`);
      }
    );
  }
  
  /**
   * Deliver packet to final recipient
   */
  deliverToUser(userId, packet, finalRoutingKey) {
    try {
      SphinxPacket.process(
        packet,
        finalRoutingKey,
        null, // No forwarding at final hop
        (message, packetId) => {
          // Deliver to user via WebSocket
          this.sendToUser(userId, {
            type: 'nym_message',
            payload: message.toString('base64'),
            packetId,
            timestamp: Date.now()
          });
          
          console.log(`[NymMixnet] Delivered message ${packetId} to user ${userId}`);
        }
      );
    } catch (err) {
      console.error(`[NymMixnet] Delivery error:`, err.message);
    }
  }
  
  /**
   * Create a reply block for anonymous replies
   * @param {string} userId - User who wants to receive replies
   * @returns {ReplyBlock}
   */
  createReplyBlock(userId) {
    // Select path for incoming replies
    const path = this.selectPath(userId);
    
    // Get routing keys (simplified - in production would derive from path)
    const routingKeys = path.map((_, i) => 
      crypto.randomBytes(SPHINX_CONFIG.KEY_SIZE)
    );
    
    const replyBlock = new ReplyBlock(userId, path, routingKeys);
    this.replyBlocks.set(replyBlock.blockId, replyBlock);
    
    console.log(`[NymMixnet] Created reply block ${replyBlock.blockId} for user ${userId}`);
    return replyBlock;
  }
  
  /**
   * Get a reply block by ID
   */
  getReplyBlock(blockId) {
    const block = this.replyBlocks.get(blockId);
    if (block && block.isValid()) {
      return block;
    }
    return null;
  }
  
  /**
   * Process cover traffic message
   */
  processCoverMessage(coverMsg) {
    // Select random path through virtual nodes
    const dummyRecipient = `dummy-${crypto.randomBytes(8).toString('hex')}`;
    const path = this.selectPath(dummyRecipient);
    
    // Create Sphinx packet with dummy payload
    const { packet } = SphinxPacket.create(coverMsg.data, path);
    
    // Route through virtual nodes (will eventually be dropped)
    this.routePacket(packet, path, [], 0, dummyRecipient);
    
    console.log(`[NymMixnet] Generated cover traffic`);
  }
  
  /**
   * Get comprehensive statistics
   */
  getStats() {
    const nodeStats = Array.from(this.nodes.values()).map(n => n.getStats());
    
    return {
      nodes: {
        total: this.nodes.size,
        stats: nodeStats
      },
      replyBlocks: {
        total: this.replyBlocks.size,
        active: Array.from(this.replyBlocks.values()).filter(rb => rb.isValid()).length
      },
      trafficShaper: this.trafficShaper.getStats()
    };
  }
}

module.exports = {
  NymMixnet,
  VirtualMixNode,
  ReplyBlock,
  NYM_CONFIG
};
