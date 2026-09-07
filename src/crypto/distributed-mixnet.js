/**
 * 分布式 Mixnet 部署配置
 * 
 * 将单服务器虚拟节点扩展为多服务器分布式架构
 * 支持地理分散部署，增强抗审查能力
 */

const crypto = require('crypto');

/**
 * 分布式节点配置
 * 生产环境应部署在不同云服务商/地理位置
 */
const DISTRIBUTED_NODES = [
  {
    id: 'entry-sg',
    role: 'entry',
    region: 'Singapore',
    host: 'entry.noir-app.sg',
    port: 3001,
    publicKey: null, // 运行时从节点获取
    latencyTarget: '< 50ms'
  },
  {
    id: 'mix-1-jp',
    role: 'mix',
    region: 'Tokyo',
    host: 'mix1.noir-app.jp',
    port: 3001,
    publicKey: null,
    latencyTarget: '< 80ms'
  },
  {
    id: 'mix-2-de',
    role: 'mix',
    region: 'Frankfurt',
    host: 'mix2.noir-app.de',
    port: 3001,
    publicKey: null,
    latencyTarget: '< 100ms'
  },
  {
    id: 'mix-3-us',
    role: 'mix',
    region: 'Virginia',
    host: 'mix3.noir-app.us',
    port: 3001,
    publicKey: null,
    latencyTarget: '< 120ms'
  },
  {
    id: 'exit-nl',
    role: 'exit',
    region: 'Amsterdam',
    host: 'exit.noir-app.nl',
    port: 3001,
    publicKey: null,
    latencyTarget: '< 150ms'
  }
];

/**
 * 分布式 Mixnet 客户端
 * 连接到远程节点，而非本地虚拟节点
 */
class DistributedMixnetClient {
  constructor(config = {}) {
    this.nodes = new Map();
    this.nodeList = [];
    this.config = {
      timeout: 5000,
      retries: 3,
      ...config
    };
    
    // 初始化节点列表
    for (const nodeConfig of DISTRIBUTED_NODES) {
      this.nodes.set(nodeConfig.id, {
        ...nodeConfig,
        status: 'offline',
        lastPing: null,
        latency: null
      });
      this.nodeList.push(nodeConfig.id);
    }
  }
  
  /**
   * 连接到所有节点
   */
  async connectAll() {
    console.log('[DistributedMixnet] Connecting to all nodes...');
    
    const results = await Promise.allSettled(
      this.nodeList.map(nodeId => this.connectNode(nodeId))
    );
    
    const connected = results.filter(r => r.status === 'fulfilled' && r.value.ok).length;
    console.log(`[DistributedMixnet] Connected ${connected}/${this.nodeList.length} nodes`);
    
    return connected;
  }
  
  /**
   * 连接到单个节点
   */
  async connectNode(nodeId) {
    const node = this.nodes.get(nodeId);
    if (!node) {
      throw new Error(`Node not found: ${nodeId}`);
    }
    
    try {
      const startTime = Date.now();
      
      // 健康检查
      const response = await fetch(`http://${node.host}:${node.port}/health`, {
        method: 'GET',
        signal: AbortSignal.timeout(this.config.timeout)
      });
      
      const latency = Date.now() - startTime;
      
      if (response.ok) {
        const data = await response.json();
        node.status = 'online';
        node.latency = latency;
        node.lastPing = Date.now();
        node.publicKey = data.publicKey;
        
        console.log(`[DistributedMixnet] Node ${nodeId} online (${latency}ms)`);
        return { ok: true, nodeId, latency };
      } else {
        node.status = 'error';
        console.error(`[DistributedMixnet] Node ${nodeId} error: ${response.status}`);
        return { ok: false, nodeId, error: response.status };
      }
    } catch (err) {
      node.status = 'offline';
      console.error(`[DistributedMixnet] Node ${nodeId} offline: ${err.message}`);
      return { ok: false, nodeId, error: err.message };
    }
  }
  
  /**
   * 选择最优路径
   * 基于延迟和节点状态选择最佳路由
   */
  selectOptimalPath(destinationId) {
    const onlineNodes = Array.from(this.nodes.values())
      .filter(n => n.status === 'online')
      .sort((a, b) => (a.latency || 999) - (b.latency || 999));
    
    if (onlineNodes.length < 3) {
      console.warn('[DistributedMixnet] Not enough online nodes for full path');
      // 降级到可用节点
      return onlineNodes.map(n => n.id);
    }
    
    // 选择路径: entry -> mix1 -> mix2 -> exit -> destination
    const entry = onlineNodes.find(n => n.role === 'entry') || onlineNodes[0];
    const mixes = onlineNodes.filter(n => n.role === 'mix');
    const exit = onlineNodes.find(n => n.role === 'exit') || onlineNodes[onlineNodes.length - 1];
    
    const path = [entry.id];
    
    // 选择 2-3 个 mix 节点
    const selectedMixes = mixes.slice(0, Math.min(3, mixes.length));
    path.push(...selectedMixes.map(m => m.id));
    
    path.push(exit.id);
    path.push(`user:${destinationId}`);
    
    return path;
  }
  
  /**
   * 通过分布式网络发送消息
   */
  async sendMessage(fromUserId, toUserId, message) {
    const path = this.selectOptimalPath(toUserId);
    
    if (path.length < 3) {
      throw new Error('Insufficient nodes for secure routing');
    }
    
    console.log(`[DistributedMixnet] Routing through: ${path.join(' -> ')}`);
    
    // 创建 Sphinx 包
    const { SphinxPacket } = require('./sphinx-packet');
    const { packet, packetId } = SphinxPacket.create(message, path.map(id => ({ nodeId: id })));
    
    // 发送到入口节点
    const entryNode = this.nodes.get(path[0]);
    
    try {
      const response = await fetch(`http://${entryNode.host}:${entryNode.port}/api/mixnet/route`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          packet: packet.toString('base64'),
          path: path.slice(1), // 剩余路径
          packetId
        })
      });
      
      if (response.ok) {
        return { success: true, packetId, path };
      } else {
        throw new Error(`Routing failed: ${response.status}`);
      }
    } catch (err) {
      console.error('[DistributedMixnet] Send failed:', err.message);
      return { success: false, error: err.message };
    }
  }
  
  /**
   * 获取网络状态
   */
  getNetworkStatus() {
    const nodes = Array.from(this.nodes.values()).map(n => ({
      id: n.id,
      role: n.role,
      region: n.region,
      status: n.status,
      latency: n.latency
    }));
    
    const online = nodes.filter(n => n.status === 'online').length;
    
    return {
      totalNodes: nodes.length,
      onlineNodes: online,
      health: online >= 3 ? 'healthy' : online >= 1 ? 'degraded' : 'offline',
      nodes
    };
  }
}

/**
 * Mixnet 节点服务器端
 * 处理来自其他节点的路由请求
 */
class MixnetNodeServer {
  constructor(nodeId, config = {}) {
    this.nodeId = nodeId;
    this.config = config;
    this.routingKey = crypto.randomBytes(32);
    this.relayQueue = [];
  }
  
  /**
   * 处理路由请求
   */
  async handleRouteRequest(request, forwardCallback) {
    const { packet, path, packetId } = request;
    
    // 解码包
    const packetBuffer = Buffer.from(packet, 'base64');
    
    if (path.length === 0) {
      // 最终目的地，交付消息
      return { delivered: true, packetId };
    }
    
    // 还有下一跳，转发
    const nextHop = path[0];
    const remainingPath = path.slice(1);
    
    // 添加随机延迟（混淆时序）
    const delay = 50 + Math.random() * 450;
    
    await new Promise(resolve => setTimeout(resolve, delay));
    
    // 转发到下一节点
    if (forwardCallback) {
      await forwardCallback(nextHop, packetBuffer, remainingPath, packetId);
    }
    
    return { forwarded: true, nextHop, packetId };
  }
  
  /**
   * 获取节点公钥（用于 Sphinx 加密）
   */
  getPublicKey() {
    return this.routingKey.toString('hex');
  }
}

module.exports = {
  DISTRIBUTED_NODES,
  DistributedMixnetClient,
  MixnetNodeServer
};
