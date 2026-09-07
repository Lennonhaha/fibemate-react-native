const { HybridKeyExchange } = require('./src/crypto/hybrid');

(async () => {
  const a = new HybridKeyExchange();
  const b = new HybridKeyExchange();
  console.log('[1/3] Init A...');
  const aKeys = await a.initialize();
  console.log('[2/3] Init B...');
  const bKeys = await b.initialize();
  console.log('[3/3] Handshake A->B...');
  const { ciphertext, sharedSecret: sA } = await a.encapsulateToPeer(bKeys.kemPublicKey, bKeys.ecdhPublicKey);
  const sB = await b.decapsulateFromPeer(ciphertext, aKeys.ecdhPublicKey);
  const match = Buffer.compare(Buffer.from(sA), Buffer.from(sB)) === 0;
  console.log('Shared secret match:', match ? 'YES' : 'NO');
  console.log('Hybrid handshake ' + (match ? 'OK' : 'FAIL'));
})().catch(e => console.error('FAIL:', e.message));
