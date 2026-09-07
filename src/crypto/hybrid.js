/**
 * HybridKeyExchange — ML-KEM-768 + ECDH-P-256 hybrid key exchange.
 *
 * REQUIRES: crypto.subtle (available in browsers and Node.js >= 15 with WebCrypto)
 * This module depends on the core ml-kem-768.js for generateKeypair/encapsulate/decapsulate.
 */

const { generateKeypair, encapsulate, decapsulate, sha3_256 } = require('./ml-kem-768');

class HybridKeyExchange {
    constructor() { this.kemKeypair = null; this.ecdhKeypair = null; }

    async initialize() {
        this.kemKeypair = generateKeypair();
        this.ecdhKeypair = await crypto.subtle.generateKey(
            { name: 'ECDH', namedCurve: 'P-256' },
            true,
            ['deriveBits']
        );
        return {
            kemPublicKey: this.kemKeypair.publicKey,
            ecdhPublicKey: await crypto.subtle.exportKey('raw', this.ecdhKeypair.publicKey)
        };
    }

    async encapsulateToPeer(pk, ecdhPk) {
        const k = encapsulate(pk);
        const e = await crypto.subtle.importKey(
            'raw', ecdhPk,
            { name: 'ECDH', namedCurve: 'P-256' },
            false, []
        );
        const d = await crypto.subtle.deriveBits(
            { name: 'ECDH', public: e },
            this.ecdhKeypair.privateKey,
            256
        );
        const c = new Uint8Array(64);
        c.set(k.sharedSecret, 0);
        c.set(new Uint8Array(d), 32);
        return { ciphertext: k.ciphertext, sharedSecret: sha3_256(c) };
    }

    async decapsulateFromPeer(ct, ecdhPk) {
        const ks = decapsulate(this.kemKeypair.secretKey, ct);
        const e = await crypto.subtle.importKey(
            'raw', ecdhPk,
            { name: 'ECDH', namedCurve: 'P-256' },
            false, []
        );
        const d = await crypto.subtle.deriveBits(
            { name: 'ECDH', public: e },
            this.ecdhKeypair.privateKey,
            256
        );
        const c = new Uint8Array(64);
        c.set(ks, 0);
        c.set(new Uint8Array(d), 32);
        return sha3_256(c);
    }
}

module.exports = { HybridKeyExchange };