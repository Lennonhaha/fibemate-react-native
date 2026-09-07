// FIBEMATE Mobile — Entry Point
// Polyfills for React Native crypto
import 'react-native-get-random-values';
import { install } from 'react-native-quick-crypto';
install();

// Core imports
import { AppRegistry } from 'react-native';
import App from './App';
import { name as appName } from './app.json';

// Quick SM2 self-test on load
const crypto = require('./src/crypto/sm2-crypto');
try {
  const result = crypto.selfTest();
  console.log('[FIBEMATE] SM2 self-test:', JSON.stringify(result));
} catch (e) {
  console.error('[FIBEMATE] SM2 self-test failed:', e.message);
}

AppRegistry.registerComponent(appName, () => App);
