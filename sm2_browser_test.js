require('./src/crypto/sm2-ec-browser');
const s = globalThis.SM2EC;

// 1. Keygen
const kp = s.generateKeyPair();
const pubHex = s.publicKeyToHex(kp.publicKey);
console.log('[1] Keygen: pubHex=' + pubHex.slice(0, 10) + '...');

// 2. Encrypt / Decrypt
const ct = s.encrypt(pubHex, 'hello fibemate');
const pt = s.decrypt(kp.privateKey, ct.c1, ct.c2);
console.log('[2] Enc/Dec:', pt, pt === 'hello fibemate' ? '✅' : '❌');

// 3. Sign / Verify
const msgHex = '0a0b0c';
const sig = s.sign(kp.privateKey, msgHex);
const vfy = s.verify(pubHex, msgHex, sig.r, sig.s);
console.log('[3] Sign/Verify:', vfy ? '✅' : '❌');

// 4. ECDH shared secret
const kp2 = s.generateKeyPair();
const ss1 = s.computeSharedSecret(kp.privateKey, kp2.publicKey);
const ss2 = s.computeSharedSecret(kp2.privateKey, kp.publicKey);
console.log('[4] ECDH:', Buffer.from(ss1).equals(Buffer.from(ss2)) ? '✅' : '❌');

console.log('\n=== SM2-Browser ALL PASS ===');
