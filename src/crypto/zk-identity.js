/**
 * 零知识身份认证模块 - P-256 曲线版 v5
 * 
 * 从 secp256k1 切换到 P-256，与前端 Web Crypto API 对齐
 * Node.js 内置 crypto 模块原生支持 P-256，无需第三方库
 */

const crypto = require('crypto');
const { safeCompareHex } = require('../lib/constant-time');
const pedersen = require('./pedersen');

// 使用 P-256 曲线（与前端 Web Crypto 一致）
const CURVE = 'prime256v1'; // P-256 的 OpenSSL 名称

/**
 * 生成身份密钥对（ECDSA P-256）
 * @returns {{ privateKey: string, publicKey: string, privateKeyPem: string, publicKeyPem: string }}
 */
function generateIdentityKeyPair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', {
    namedCurve: CURVE,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
  });
  
  // 提取原始公钥字节（未压缩格式 04 + x + y = 65 bytes = 130 hex chars）
  const pubKeyObj = crypto.createPublicKey(publicKey);
  const pubKeyRaw = pubKeyObj.export({ type: 'spki', format: 'der' });
  // DER SPKI 格式最后 66 字节是 04 + 32字节x + 32字节y（P-256）
  const rawBytes = pubKeyRaw.slice(-65);
  const publicKeyHex = rawBytes.toString('hex');
  
  return {
    privateKey: privateKey,
    publicKey: '0x' + publicKeyHex,
    privateKeyPem: privateKey,
    publicKeyPem: publicKey
  };
}

/**
 * 使用私钥签名消息（ECDSA P-256 + SHA-256）
 * @param {string} message - 要签名的消息
 * @param {string} privateKeyPem - 私钥 PEM
 * @returns {string} - 签名（hex，DER 编码）
 */
function sign(message, privateKeyPem) {
  const sign = crypto.createSign('SHA256');
  sign.update(message, 'utf8');
  sign.end();
  
  const signature = sign.sign(privateKeyPem);
  return '0x' + signature.toString('hex');
}

/**
 * 验证签名（ECDSA P-256 + SHA-256）
 * 
 * @param {string} message - 原始消息
 * @param {string} signature - 签名（hex，DER 编码）
 * @param {string} publicKey - 公钥（hex，04 + x + y 格式）或 PEM
 * @returns {boolean}
 */
function verifySignature(message, signature, publicKey) {
  try {
    let verifyKey;
    
    // 支持 hex 公钥和 PEM 公钥两种格式
    if (publicKey.startsWith('-----BEGIN')) {
      verifyKey = publicKey;
    } else {
      // hex 格式：0x04 + x + y → 转 PEM
      const pubKeyHex = publicKey.startsWith('0x') ? publicKey.slice(2) : publicKey;
      
      if (pubKeyHex.length !== 130) {
        console.error('[ZK-Identity] P-256 公钥长度错误: 期望130, 实际' + pubKeyHex.length);
        return false;
      }
      
      // 构造 DER 编码的 SPKI 公钥
      // P-256 OID: 1.2.840.10045.2.1 + 1.2.840.10045.3.1.7
      const derPrefix = Buffer.from('3059301306072a8648ce3d020106082a8648ce3d030107034200', 'hex');
      const rawPubKey = Buffer.from(pubKeyHex, 'hex');
      const spkiDer = Buffer.concat([derPrefix, rawPubKey]);
      verifyKey = crypto.createPublicKey({ key: spkiDer, format: 'der', type: 'spki' });
    }
    
    const sigHex = signature.startsWith('0x') ? signature.slice(2) : signature;
    const sigBuffer = Buffer.from(sigHex, 'hex');
    
    if (sigBuffer.length === 0) {
      console.error('[ZK-Identity] 签名为空');
      return false;
    }
    
    // 验证签名
    const verifier = crypto.createVerify('SHA256');
    verifier.update(message, 'utf8');
    verifier.end();
    
    return verifier.verify(verifyKey, sigBuffer);
  } catch (e) {
    console.error('[ZK-Identity] 签名验证异常:', e.message);
    return false;
  }
}

/**
 * 创建注册请求（客户端调用）
 */
function createRegistrationRequest(username, password) {
  const { commitment, r, g, h } = pedersen.commit(username);
  const keyPair = generateIdentityKeyPair();
  
  const passwordHash = crypto.createHash('sha256')
    .update(password, 'utf8')
    .digest('hex');
  
  const proofOfKnowledge = pedersen.generateProof(commitment, username, r);
  const signature = sign(commitment, keyPair.privateKeyPem);
  
  return {
    commitment,
    identityPublicKey: keyPair.publicKey,
    passwordHash,
    proofOfKnowledge,
    signature,
    _clientSecrets: { username, r, privateKeyPem: keyPair.privateKeyPem, g, h }
  };
}

/**
 * 验证注册请求（服务器调用）
 */
function verifyRegistrationRequest(request) {
  const { commitment, identityPublicKey, passwordHash, proofOfKnowledge, signature } = request;
  
  if (!commitment || !identityPublicKey || !passwordHash || !proofOfKnowledge || !signature) {
    return { valid: false, error: '缺少必填字段' };
  }
  
  if (!commitment.startsWith('0x') || commitment.length !== 66) {
    return { valid: false, error: 'commitment 格式无效' };
  }
  
  const pubKeyHex = identityPublicKey.startsWith('0x') ? identityPublicKey.slice(2) : identityPublicKey;
  if (pubKeyHex.length !== 130) {
    return { valid: false, error: 'P-256 公钥格式无效（期望130 hex字符，实际' + pubKeyHex.length + '）' };
  }
  
  if (!pedersen.verifyProof(commitment, proofOfKnowledge)) {
    return { valid: false, error: 'ZK 证明验证失败' };
  }
  
  // ECDSA P-256 签名验证
  if (!verifySignature(commitment, signature, identityPublicKey)) {
    return { valid: false, error: '签名验证失败' };
  }
  
  return { valid: true };
}

/**
 * 创建登录请求
 */
function createLoginRequest(username, r, privateKeyPem, commitment) {
  const zkProof = pedersen.generateProof(commitment, username, r);
  const signature = sign(zkProof.challenge, privateKeyPem);
  
  return {
    commitment,
    zkProof,
    signature,
    timestamp: Date.now()
  };
}

/**
 * 验证登录请求
 */
function verifyLoginRequest(request, user) {
  const { commitment, zkProof, signature, timestamp } = request;
  
  const now = Date.now();
  if (!timestamp || Math.abs(now - timestamp) > 5 * 60 * 1000) {
    return { valid: false, error: '请求已过期' };
  }
  
  if (!safeCompareHex(commitment, user.commitment)) {
    return { valid: false, error: '用户不存在' };
  }
  
  if (!pedersen.verifyProof(commitment, zkProof)) {
    return { valid: false, error: 'ZK 证明验证失败' };
  }
  
  if (!verifySignature(zkProof.challenge, signature, user.identityPublicKey)) {
    return { valid: false, error: '签名验证失败' };
  }
  
  return { valid: true };
}

/**
 * 生成匿名显示名称
 */
function generateAnonymousDisplayName(commitment) {
  const hash = crypto.createHash('sha256')
    .update(commitment, 'utf8')
    .digest('hex');
  
  return `匿名用户#${hash.slice(0, 4).toUpperCase()}`;
}

module.exports = {
  generateIdentityKeyPair,
  sign,
  verifySignature,
  createRegistrationRequest,
  verifyRegistrationRequest,
  createLoginRequest,
  verifyLoginRequest,
  generateAnonymousDisplayName
};
