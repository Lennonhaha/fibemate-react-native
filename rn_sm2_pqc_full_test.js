/**
 * FIBEMATE Mobile — Full SM2 + PQC Integration Test
 * Runs in Node.js with react-native-get-random-values polyfilled.
 * Consumes the same src/crypto/*.js modules that will be bundled into RN.
 */
const path = require('path');
const RN_ROOT = path.resolve('D:/FIBEMATE/Mobile/FibemateMobile');

// Polyfill: crypto.getRandomValues
global.crypto = global.crypto || {};
if (!global.crypto.getRandomValues) {
  global.crypto.getRandomValues = require('crypto').randomFillSync;
}
global.window = global;

console.log('╔══════════════════════════════════════════╗');
console.log('║  FIBEMATE Mobile — SM2 + PQC Full Test    ║');
console.log('╠══════════════════════════════════════════╣');

let pass = 0, fail = 0;

function check(label, ok, detail) {
  if (ok) { pass++; console.log(`  [PASS] ${label}: ${detail}`); }
  else { fail++; console.error(`  [FAIL] ${label}: ${detail}`); }
}

// ========== TEST 1: SM2-EC-Browser ==========
console.log('║');
console.log('║  T1: SM2-EC-Browser (Pure JS BigInt)     ║');
try {
  require(path.join(RN_ROOT, 'src/crypto/sm2-ec-browser'));
  const SM2 = globalThis.SM2EC;
  check('SM2 loaded', !!SM2, 'globalThis.SM2EC exists');

  const kp = SM2.generateKeyPair();
  const pubHex = SM2.publicKeyToHex(kp.publicKey);
  check('Keygen', pubHex.startsWith('04') && pubHex.length === 130, `pubHex ${pubHex.slice(0,8)}...`);

  const ct = SM2.encrypt(pubHex, 'FIBEMATE PQC Test 2026');
  check('Encrypt', !!ct.c1 && !!ct.c2, `c1=${ct.c1.slice(0,10)}...`);

  const pt = SM2.decrypt(kp.privateKey, ct.c1, ct.c2);
  check('Decrypt', pt === 'FIBEMATE PQC Test 2026', pt);

  const sig = SM2.sign(kp.privateKey, '0a0b0c');
  check('Sign', sig.r.length === 64, `r=${sig.r.slice(0,8)}...`);

  const vfy = SM2.verify(pubHex, '0a0b0c', sig.r, sig.s);
  check('Verify', vfy, 'valid');

  const kp2 = SM2.generateKeyPair();
  const ss1 = SM2.computeSharedSecret(kp.privateKey, kp2.publicKey);
  const ss2 = SM2.computeSharedSecret(kp2.privateKey, kp.publicKey);
  check('ECDH', Buffer.from(ss1).equals(Buffer.from(ss2)), 'shared secret match');
} catch(e) {
  fail++; console.error(`  [FAIL] SM2-EC-Browser: ${e.message}`);
}

// ========== TEST 2: ML-KEM-768 Keygen/Encaps/Decaps ==========
console.log('║');
console.log('║  T2: ML-KEM-768 (Pure JS, zero deps)     ║');
try {
  const { generateKeypair, encapsulate, decapsulate } = require(path.join(RN_ROOT, 'src/crypto/ml-kem-768'));
  const kp1 = generateKeypair();
  check('Keygen A', !!kp1.publicKey && !!kp1.secretKey,
    `pk=${kp1.publicKey.length}B, sk=${kp1.secretKey.length}B`);

  const { sharedSecret: ssEnc, ciphertext: ctEnc } = encapsulate(kp1.publicKey);
  check('Encapsulate', ssEnc.length === 32 && ctEnc.length === 1088,
    `ss=${ssEnc.length}B, ct=${ctEnc.length}B`);

  const ssDec = decapsulate(kp1.secretKey, ctEnc);
  const match = Buffer.compare(Buffer.from(ssEnc), Buffer.from(ssDec)) === 0;
  check('Decapsulate', match, match ? 'ss match' : 'ss MISMATCH');

  // Negative test: wrong secret key
  const kp2 = generateKeypair();
  const ssWrong = decapsulate(kp2.secretKey, ctEnc);
  const wrongMatch = Buffer.compare(Buffer.from(ssEnc), Buffer.from(ssWrong)) === 0;
  check('Wrong SK', !wrongMatch, 'different ss (expected)');
} catch(e) {
  fail++; console.error(`  [FAIL] ML-KEM-768: ${e.message}`);
}

// ========== TEST 3: PQC Hybrid Handshake ==========
console.log('║');
console.log('║  T3: Hybrid Handshake (ML-KEM + ECDH)    ║');
(async () => {
  try {
    const { HybridKeyExchange } = require(path.join(RN_ROOT, 'src/crypto/hybrid'));
    const alice = new HybridKeyExchange();
    const bob = new HybridKeyExchange();

    const aKeys = await alice.initialize();
    const bKeys = await bob.initialize();
    check('Init A', !!aKeys.kemPublicKey, 'Alice keypair ready');
    check('Init B', !!bKeys.kemPublicKey, 'Bob keypair ready');

    const { ciphertext, sharedSecret: ssAlice } = await alice.encapsulateToPeer(bKeys.kemPublicKey, bKeys.ecdhPublicKey);
    check('Encaps A→B', ssAlice.length > 0, `ss=${ssAlice.length}B`);

    const ssBob = await bob.decapsulateFromPeer(ciphertext, aKeys.ecdhPublicKey);
    const matchH = Buffer.compare(Buffer.from(ssAlice), Buffer.from(ssBob)) === 0;
    check('Decaps B', matchH, matchH ? 'shared secret MATCH ✅' : 'shared secret MISMATCH ❌');

    // Cross-direction: B→A
    const { ciphertext: ct2, sharedSecret: ssB2 } = await bob.encapsulateToPeer(aKeys.kemPublicKey, aKeys.ecdhPublicKey);
    const ssA2 = await alice.decapsulateFromPeer(ct2, bKeys.ecdhPublicKey);
    const matchH2 = Buffer.compare(Buffer.from(ssB2), Buffer.from(ssA2)) === 0;
    check('Cross B→A', matchH2, matchH2 ? 'bidirectional OK ✅' : 'bidirectional FAIL ❌');

  } catch(e) {
    fail++; console.error(`  [FAIL] Hybrid: ${e.message}`);
  }

  // ========== SUMMARY ==========
  const total = pass + fail;
  console.log('╠══════════════════════════════════════════╣');
  console.log(`║  RESULT: ${pass}/${total} passed`);
  if (fail > 0) {
    console.log(`║  ${fail} FAILURES — see above for details`);
  } else {
    console.log('║  🎉 ALL TESTS PASSED');
    console.log('║  SM2 ✅  ML-KEM-768 ✅  Hybrid ✅');
  }
  console.log('╚══════════════════════════════════════════╝');
})();
