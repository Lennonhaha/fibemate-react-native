module.exports = {
  root: true,
  extends: '@react-native',
  // The crypto/self-test modules use browser + Node globals (crypto.subtle,
  // Buffer, BigInt, globalThis, TextEncoder/Decoder, AbortSignal). Declare the
  // environments so `no-undef` recognizes them instead of failing the lint gate.
  env: {
    browser: true,
    node: true,
    es2021: true,
  },
};
