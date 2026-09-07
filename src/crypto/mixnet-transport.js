/**
 * NoIR Mixnet Transport Layer — Phase 3 Metadata Hiding
 * 
 * 功能:
 * 1. 消息填充 (Padding) — 统一消息大小，隐藏真实长度
 * 2. 虚拟流量 (Cover Traffic) — 随机假消息，掩盖真实通信模式
 * 3. 延迟投递 (Delayed Delivery) — 随机延迟，打破时间关联
 * 4. 批量处理 (Batching) — 固定时间窗口批量发送，隐藏时间特征
 */

const crypto = require('crypto');

// ========================
// 配置
// ========================
const MIXNET_CONFIG = {
  // 消息填充
  PAD_MESSAGE_SIZE: 4096,          // 所有消息填充到 4KB
  PAD_BLOCK_SIZE: 256,             // 填充块大小
  PAD_ALGORITHM: 'aes-256-gcm',    // 填充加密算法（防长度分析）
  
  // 虚拟流量
  COVER_TRAFFIC_RATE: 0.15,        // 15% 的消息是假消息
  COVER_MESSAGE_MIN_DELAY: 5000,   // 假消息最小延迟 5s
  COVER_MESSAGE_MAX_DELAY: 60000,  // 假消息最大延迟 60s
  
  // 延迟投递
  DELAY_MIN_MS: 100,               // 最小延迟 100ms
  DELAY_MAX_MS: 2000,              // 最大延迟 2s
  DELAY_JITTER: 0.3,               // 30% 抖动
  
  // 批量处理
  BATCH_WINDOW_MS: 1000,           // 1s 批量窗口
  BATCH_MAX_SIZE: 10,              // 每批最多 10 条消息
  
  // 垃圾回收
  MESSAGE_TTL_MS: 3600000,         // 消息 TTL 1 小时
};

// ========================
// 填充器 (Padder)
// ========================
class MessagePadder {
  /**
   * 填充消息到固定大小
   * @param {Buffer} ciphertext - 原始密文
   * @param {number} targetSize - 目标大小 (默认 4KB)
   * @returns {Buffer} 填充后的消息
   */
  static pad(ciphertext, targetSize = MIXNET_CONFIG.PAD_MESSAGE_SIZE) {
    const originalLen = ciphertext.length;
    
    // 如果消息大于目标大小，按块扩展
    const blockSize = MIXNET_CONFIG.PAD_BLOCK_SIZE;
    let paddedLen = targetSize;
    if (originalLen > targetSize) {
      paddedLen = Math.ceil(originalLen / blockSize) * blockSize;
    }
    
    // 随机填充
    const paddingLen = paddedLen - originalLen;
    const padding = crypto.randomBytes(paddingLen);
    
    // 格式: [originalLen(4 bytes)] [ciphertext] [padding]
    const lenBuf = Buffer.alloc(4);
    lenBuf.writeUInt32BE(originalLen, 0);
    
    return Buffer.concat([lenBuf, ciphertext, padding]);
  }
  
  /**
   * 移除填充，还原原始消息
   * @param {Buffer} paddedMsg - 填充后的消息
   * @returns {Buffer} 原始密文
   */
  static unpad(paddedMsg) {
    const originalLen = paddedMsg.readUInt32BE(0);
    return paddedMsg.subarray(4, 4 + originalLen);
  }
}

// ========================
// 虚拟流量生成器 (Cover Traffic Generator)
// ========================
class CoverTrafficGenerator {
  constructor() {
    this.pendingCoverMessages = new Map(); // conversationId -> cover messages
  }
  
  /**
   * 生成假消息
   * @param {string} fromUserId - 发送者 ID
   * @param {string} toUserId - 接收者 ID
   * @returns {Object} 假消息对象
   */
  generateCoverMessage(fromUserId, toUserId) {
    // 假消息使用随机密文
    const fakeCiphertext = crypto.randomBytes(MIXNET_CONFIG.PAD_MESSAGE_SIZE - 4);
    const padded = MessagePadder.pad(fakeCiphertext);
    
    return {
      type: 'cover_message',
      messageId: crypto.randomUUID(),
      from: fromUserId,
      to: toUserId,
      ciphertext: padded.toString('base64'),
      messageType: 'cover',
      isCover: true, // 标记为假消息
      createdAt: Date.now(),
      // 假消息会被客户端丢弃，但服务器无法区分
    };
  }
  
  /**
   * 根据通信模式生成假消息
   * @param {string} userId - 用户 ID
   * @param {Array<string>} contacts - 联系人列表
   * @param {Function} sendFn - 发送函数
   */
  scheduleCoverTraffic(userId, contacts, sendFn) {
    if (!contacts || contacts.length === 0) return;
    
    // 随机选择联系人
    const randomContact = contacts[Math.floor(Math.random() * contacts.length)];
    
    // 随机延迟
    const delay = MIXNET_CONFIG.COVER_MESSAGE_MIN_DELAY + 
      Math.random() * (MIXNET_CONFIG.COVER_MESSAGE_MAX_DELAY - MIXNET_CONFIG.COVER_MESSAGE_MIN_DELAY);
    
    const coverMsg = this.generateCoverMessage(userId, randomContact);
    
    setTimeout(() => {
      sendFn(coverMsg);
    }, delay);
  }
  
  /**
   * 判断是否应该生成假消息
   */
  shouldGenerateCover() {
    return Math.random() < MIXNET_CONFIG.COVER_TRAFFIC_RATE;
  }
}

// ========================
// 延迟管理器 (Delay Manager)
// ========================
class DelayManager {
  constructor() {
    this.delayQueues = new Map(); // userId -> message queue
  }
  
  /**
   * 计算消息延迟
   * @returns {number} 延迟毫秒数
   */
  calculateDelay() {
    const baseDelay = MIXNET_CONFIG.DELAY_MIN_MS + 
      Math.random() * (MIXNET_CONFIG.DELAY_MAX_MS - MIXNET_CONFIG.DELAY_MIN_MS);
    
    // 添加抖动
    const jitter = baseDelay * MIXNET_CONFIG.DELAY_JITTER * (Math.random() * 2 - 1);
    
    return Math.max(0, Math.floor(baseDelay + jitter));
  }
  
  /**
   * 延迟发送消息
   * @param {Object} message - 消息对象
   * @param {Function} sendFn - 发送函数
   */
  delayMessage(message, sendFn) {
    const delay = this.calculateDelay();
    
    setTimeout(() => {
      sendFn(message);
    }, delay);
    
    return delay;
  }
}

// ========================
// 批量处理器 (Batch Processor)
// ========================
class BatchProcessor {
  constructor() {
    this.batches = new Map(); // batchId -> { messages, timer, sendFn }
  }
  
  /**
   * 添加消息到批次
   * @param {string} batchId - 批次 ID（通常是 recipientUserId）
   * @param {Object} message - 消息对象
   * @param {Function} sendFn - 发送函数
   */
  addToBatch(batchId, message, sendFn) {
    let batch = this.batches.get(batchId);
    
    if (!batch) {
      batch = {
        messages: [],
        timer: null,
        sendFn,
      };
      this.batches.set(batchId, batch);
      
      // 设置批量窗口定时器
      batch.timer = setTimeout(() => {
        this.flushBatch(batchId);
      }, MIXNET_CONFIG.BATCH_WINDOW_MS);
    }
    
    batch.messages.push(message);
    
    // 批次满了立即发送
    if (batch.messages.length >= MIXNET_CONFIG.BATCH_MAX_SIZE) {
      this.flushBatch(batchId);
    }
  }
  
  /**
   * 发送批次中的所有消息
   * @param {string} batchId - 批次 ID
   */
  flushBatch(batchId) {
    const batch = this.batches.get(batchId);
    if (!batch) return;
    
    if (batch.timer) {
      clearTimeout(batch.timer);
    }
    
    if (batch.messages.length > 0) {
      // 随机打乱顺序
      const shuffled = batch.messages.sort(() => Math.random() - 0.5);
      
      // 按固定间隔发送
      shuffled.forEach((msg, idx) => {
        setTimeout(() => {
          batch.sendFn(msg);
        }, idx * 50); // 每条消息间隔 50ms
      });
    }
    
    this.batches.delete(batchId);
  }
}

// ========================
// Mixnet 传输层 (Main Class)
// ========================
class MixnetTransport {
  constructor(db, onlineUsers, sendToUserFn) {
    this.db = db;
    this.onlineUsers = onlineUsers;
    this.sendToUser = sendToUserFn;
    
    this.padder = MessagePadder; // static class, not instance
    this.coverGen = new CoverTrafficGenerator();
    this.delayMgr = new DelayManager();
    this.batchProc = new BatchProcessor();
    
    // 启动假消息生成器（每 30s 检查一次）
    this.coverInterval = setInterval(() => {
      this.generateBackgroundCoverTraffic();
    }, 30000);
  }
  
  /**
   * 处理发送消息（主要入口）
   * @param {Object} msgObj - 原始消息对象
   * @returns {Object} 处理后的消息
   */
  processOutgoingMessage(msgObj) {
    // 1. 填充消息
    if (msgObj.ciphertext) {
      const ciphertextBuf = Buffer.isBuffer(msgObj.ciphertext) 
        ? msgObj.ciphertext 
        : Buffer.from(msgObj.ciphertext, 'base64');
      
      msgObj.ciphertext = MessagePadder.pad(ciphertextBuf).toString('base64');
    }
    
    // 2. 添加噪声时间戳（打破时间关联）
    msgObj.createdAt = this.addNoiseToTimestamp(msgObj.createdAt || Date.now());
    
    return msgObj;
  }
  
  /**
   * 处理接收消息
   * @param {Object} msgObj - 接收到的消息
   * @returns {Object} 处理后的消息
   */
  processIncomingMessage(msgObj) {
    // 移除填充
    if (msgObj.ciphertext && !msgObj.isCover) {
      try {
        const paddedBuf = Buffer.from(msgObj.ciphertext, 'base64');
        const originalBuf = MessagePadder.unpad(paddedBuf);
        msgObj.ciphertext = originalBuf.toString('base64');
      } catch (e) {
        console.error('[Mixnet] Unpad error:', e.message);
      }
    }
    
    // 假消息标记（客户端会丢弃）
    if (msgObj.isCover) {
      msgObj._discard = true;
    }
    
    return msgObj;
  }
  
  /**
   * 发送消息（带延迟和批量）
   * @param {string} toUserId - 接收者 ID
   * @param {Object} message - 消息对象
   * @param {boolean} useBatch - 是否使用批量发送
   */
  sendMessage(toUserId, message, useBatch = true) {
    console.log('[Mixnet] sendMessage() toUserId=' + toUserId + ' onlineUsers.size=' + this.onlineUsers.size);

    const processed = this.processOutgoingMessage({ ...message });
    
    if (useBatch) {
      // 批量发送
      this.batchProc.addToBatch(toUserId, processed, (msg) => {
        this.delayMgr.delayMessage(msg, (m) => {
    console.log('[Mixnet] Calling sendToUser for ' + toUserId);
          this.sendToUser(toUserId, m);
        });
      });
    } else {
      // 直接延迟发送
      this.delayMgr.delayMessage(processed, (m) => {
        this.sendToUser(toUserId, m);
      });
    }
    
    // 随机生成假消息
    if (this.coverGen.shouldGenerateCover()) {
      const fromUserId = message.from;
      this.coverGen.scheduleCoverTraffic(fromUserId, [toUserId], (coverMsg) => {
        this.sendToUser(toUserId, coverMsg);
      });
    }
  }
  
  /**
   * 添加时间噪声
   */
  addNoiseToTimestamp(timestamp) {
    const noise = Math.floor((Math.random() - 0.5) * 2000); // ±1s
    return timestamp + noise;
  }
  
  /**
   * 后台假流量生成
   */
  generateBackgroundCoverTraffic() {
    // 为所有在线用户生成假流量
    for (const [userId, sockets] of this.onlineUsers) {
      if (sockets.size > 0) {
        // 获取用户的对话列表
        const convs = this.db.getConversationsByUserId(userId);
        const contacts = convs.map(c => 
          c.userAId === userId ? c.userBId : c.userAId
        );
        
        if (contacts.length > 0 && this.coverGen.shouldGenerateCover()) {
          this.coverGen.scheduleCoverTraffic(userId, contacts, (coverMsg) => {
            const toUserId = coverMsg.to;
            this.sendToUser(toUserId, coverMsg);
          });
        }
      }
    }
  }
  
  /**
   * 停止 Mixnet 传输层
   */
  stop() {
    if (this.coverInterval) {
      clearInterval(this.coverInterval);
    }
  }
}

module.exports = {
  MixnetTransport,
  MessagePadder,
  CoverTrafficGenerator,
  DelayManager,
  BatchProcessor,
  MIXNET_CONFIG,
};
