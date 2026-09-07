const sm2 = require('sm-crypto').sm2;
const sm3 = require('sm-crypto').sm3;

/**
 * FIBEMATE SM2 国密密码学模块
 * 基于 sm-crypto，符合 GM/T 0003.2-2012 规范
 *
 * 密钥长度：256-bit（同 P-256，不同参数）
 * 签名算法：SM2 with SM3 hash
 * 加密算法：SM2 公钥加密（SM3 + AES-128 封装）
 */

// ============ Key Management ============

/**
 * 生成 SM2 密钥对（Hex 字符串）
 * @returns {{ privateKey: string, publicKey: string }}
 */
function generateKeyPairHex() {
    return sm2.generateKeyPairHex();
}

/**
 * 从私钥导出公钥
 * @param {string} privateKeyHex - 64 hex chars (32 bytes)
 * @returns {string} publicKeyHex - 130 hex chars (04 + X + Y)
 */
function getPublicKeyFromPrivateKey(privateKeyHex) {
    return sm2.getPublicKeyFromPrivateKey(privateKeyHex);
}

/**
 * 压缩公钥
 */
function compressPublicKeyHex(publicKeyHex) {
    return sm2.compressPublicKeyHex(publicKeyHex);
}

// ============ Sign/Verify ============

/**
 * SM2 签名（带 SM3 预处理，符合国密规范 Za）
 * @param {string} msg              - 原始消息（字符串或 Hex）
 * @param {string} privateKeyHex   - 私钥 Hex
 * @param {object} opts            - 选项 { hash: true, userId: '1234567812345678' }
 * @returns {string} sigHex        - 128 hex chars (r||s, 各 32 字节)
 */
function sign(msg, privateKeyHex, opts = { hash: true, userId: '1234567812345678' }) {
    return sm2.doSignature(msg, privateKeyHex, opts);
}

/**
 * SM2 验签
 * @param {string} msg            - 原始消息
 * @param {string} sigHex        - 签名 Hex (r||s)
 * @param {string} publicKeyHex  - 公钥 Hex
 * @param {object} opts          - 选项（须与签名一致）
 * @returns {boolean}
 */
function verify(msg, sigHex, publicKeyHex, opts = { hash: true, userId: '1234567812345678' }) {
    return sm2.doVerifySignature(msg, sigHex, publicKeyHex, opts);
}

// ============ Encrypt/Decrypt ============

/**
 * SM2 公钥加密（SM3 + 随机数封装）
 * @param {string} msg            - 明文（字符串或 Hex）
 * @param {string} publicKeyHex  - 接收方公钥
 * @returns {string} ciphertext  - Hex 密文
 */
function encrypt(msg, publicKeyHex) {
    return sm2.doEncrypt(msg, publicKeyHex);
}

/**
 * SM2 私钥解密
 * @param {string} ciphertextHex - 密文 Hex
 * @param {string} privateKeyHex - 接收方私钥
 * @returns {string} plaintext   - 明文字符串
 */
function decrypt(ciphertextHex, privateKeyHex) {
    return sm2.doDecrypt(ciphertextHex, privateKeyHex);
}

// ============ SM3 Hash ============

/**
 * SM3 哈希（国密替代 SHA-256）
 * @param {string|Buffer} msg
 * @returns {string} hashHex - 64 hex chars (32 bytes)
 */
function hash(msg) {
    return sm3(msg);
}

// ============ Key Validation ============

/**
 * 验证 SM2 公钥格式
 * @param {string} publicKeyHex
 * @returns {boolean}
 */
function verifyPublicKey(publicKeyHex) {
    try {
        return sm2.verifyPublicKey(publicKeyHex);
    } catch {
        return false;
    }
}

// ============ Utility: DER Encoding ============

/**
 * SM2 签名 r||s → DER 编码（国密标准）
 * @param {string} rsHex - 128 hex chars (r 64 + s 64)
 * @returns {string} derHex
 */
function signatureToDER(rsHex) {
    if (rsHex.length !== 128) throw new Error('Invalid SM2 signature length');
    const r = BigInt('0x' + rsHex.slice(0, 64));
    const s = BigInt('0x' + rsHex.slice(64));
    const rBytes = toSignedDERInt(r);
    const sBytes = toSignedDERInt(s);
    const inner = '02' + toLengthHex(rBytes) + rBytes + '02' + toLengthHex(sBytes) + sBytes;
    return '30' + toLengthHex(inner) + inner;
}

function toSignedDERInt(n) {
    // Convert BigInt to minimal bytes, ensure positive by prepending 0x00 if high bit set
    let hex = n.toString(16);
    if (hex.length % 2 !== 0) hex = '0' + hex;  // pad to even
    // Check high bit
    if (parseInt(hex.slice(0, 2), 16) >= 0x80) hex = '00' + hex;
    // Strip leading zeros (but keep at least one zero if value is 0)
    while (hex.length > 2 && hex.startsWith('00')) hex = hex.slice(2);
    if (hex === '') hex = '00';
    return hex;
}

function toLengthHex(contentHex) {
    const len = contentHex.length / 2;
    if (len < 0x80) return len.toString(16).padStart(2, '0');
    const lenHex = len.toString(16);
    const lenLen = (lenHex.length / 2).toString(16).padStart(2, '0');
    return (0x80 + lenLen).toString(16).padStart(2, '0') + lenHex;
}

function DERToSignature(derHex) {
    // Simplified DER parse: 30 LL 02 LL1 r 02 LL2 s
    if (!derHex.startsWith('30')) throw new Error('Invalid DER');
    const inner = derHex.slice(4); // skip 30 LL
    const rStart = inner.indexOf('02') + 2;
    const rLen = parseInt(inner.slice(rStart, rStart + 2), 16) * 2;
    const r = inner.slice(rStart + 2, rStart + 2 + rLen).padStart(64, '0');
    const sStart = inner.indexOf('02', rStart) + 2;
    const sLen = parseInt(inner.slice(sStart, sStart + 2), 16) * 2;
    const s = inner.slice(sStart + 2, sStart + 2 + sLen).padStart(64, '0');
    return r + s;
}

// ============ Self-Test ============

function selfTest() {
    const kp = generateKeyPairHex();
    const msg = 'FIBEMATE SM2 self-test 2026';
    const sig = sign(msg, kp.privateKey);
    const ok = verify(msg, sig, kp.publicKey);
    const enc = encrypt(msg, kp.publicKey);
    const dec = decrypt(enc, kp.privateKey);
    return {
        keygen: !!kp.publicKey && !!kp.privateKey,
        signVerify: ok,
        encryptDecrypt: dec === msg,
        hash: hash('test').length === 64,
    };
}

module.exports = {
    generateKeyPairHex,
    getPublicKeyFromPrivateKey,
    compressPublicKeyHex,
    sign,
    verify,
    encrypt,
    decrypt,
    hash,
    verifyPublicKey,
    signatureToDER,
    DERToSignature,
    selfTest,
};