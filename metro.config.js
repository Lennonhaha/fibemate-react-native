const { getDefaultConfig, mergeConfig } = require('@react-native/metro-config');

/**
 * Metro configuration for FIBEMATE Mobile
 * - Supports .cjs extension for crypto polyfills (react-native-quick-crypto)
 */
const config = {
  resolver: {
    sourceExts: ['js', 'jsx', 'ts', 'tsx', 'cjs', 'mjs', 'json'],
  },
};

module.exports = mergeConfig(getDefaultConfig(__dirname), config);
