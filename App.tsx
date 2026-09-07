import React, { useState } from 'react';
import {
  SafeAreaView,
  ScrollView,
  StatusBar,
  StyleSheet,
  Text,
  TouchableOpacity,
  View,
  ActivityIndicator,
  useColorScheme,
} from 'react-native';

// ============ Crypto imports ============
// SM2 (Browser Edition — pure JS, zero Node deps)
import './src/crypto/sm2-ec-browser';
// ML-KEM-768 + Hybrid ECDH
import { HybridKeyExchange } from './src/crypto/hybrid';

// ============ Colors ============
const Colors = {
  dark: { bg: '#0D1117', card: '#161B22', text: '#E6EDF3', subtext: '#8B949E', accent: '#58A6FF', green: '#3FB950', red: '#F85149', border: '#30363D' },
  light: { bg: '#FFFFFF', card: '#F6F8FA', text: '#24292F', subtext: '#57606A', accent: '#0969DA', green: '#1A7F37', red: '#CF222E', border: '#D0D7DE' },
};

// ============ Status Badge ============
const Badge: React.FC<{ ok: boolean; label: string }> = ({ ok, label }) => (
  <View style={styles.badge}>
    <View style={[styles.badgeDot, { backgroundColor: ok ? '#3FB950' : '#F85149' }]} />
    <Text style={styles.badgeText}>{label}</Text>
  </View>
);

// ============ Step Row ============
const Step: React.FC<{ step: number; title: string; result?: string; running?: boolean; done?: boolean }> = ({ step, title, result, running, done }) => (
  <View style={styles.step}>
    <View style={[styles.stepCircle, done ? styles.stepDone : running ? styles.stepRunning : undefined]}>
      {running ? <ActivityIndicator size="small" color="#FFF" /> : <Text style={styles.stepNum}>{done ? '✓' : step}</Text>}
    </View>
    <View style={styles.stepContent}>
      <Text style={styles.stepTitle}>{title}</Text>
      {result && <Text style={[styles.stepResult, { color: result.startsWith('✅') ? '#3FB950' : '#F85149' }]}>{result}</Text>}
    </View>
  </View>
);

// ============ Main App ============
export default function App() {
  const isDark = useColorScheme() === 'dark';
  const c = isDark ? Colors.dark : Colors.light;

  const [results, setResults] = useState<Array<{ title: string; ok: boolean; detail: string }>>([]);
  const [currentStep, setCurrentStep] = useState('');
  const [running, setRunning] = useState(false);

  const runAllTests = async () => {
    setRunning(true);
    setResults([]);
    const add = (title: string, ok: boolean, detail: string) => {
      setResults(prev => [...prev, { title, ok, detail }]);
    };

    try {
      // ==================== STEP 1: SM2 Keygen ====================
      setCurrentStep('SM2 Keygen');
      add('SM2 Keygen', true, 'Generating...');

      const SM2 = (globalThis as any).SM2EC;
      const kp = SM2.generateKeyPair();
      const pubHex = SM2.publicKeyToHex(kp.publicKey);
      add('SM2 Keygen', true, `✅ ${pubHex.slice(0, 12)}...`);

      // ==================== STEP 2: SM2 Encrypt/Decrypt ====================
      setCurrentStep('SM2 Enc/Dec');
      const ct = SM2.encrypt(pubHex, 'FIBEMATE Mobile PQC Test');
      const pt = SM2.decrypt(kp.privateKey, ct.c1, ct.c2);
      add('SM2 Enc/Dec', pt === 'FIBEMATE Mobile PQC Test', pt === 'FIBEMATE Mobile PQC Test' ? `✅ ${ct.c1.slice(0, 10)}...` : '❌ Decrypt mismatch');

      // ==================== STEP 3: SM2 Sign/Verify ====================
      setCurrentStep('SM2 Sign/Verify');
      const sig = SM2.sign(kp.privateKey, '0a0b0c');
      const vfy = SM2.verify(pubHex, '0a0b0c', sig.r, sig.s);
      add('SM2 Sign/Verify', vfy, vfy ? `✅ sig ${sig.r.slice(0, 8)}...` : '❌');

      // ==================== STEP 4: ML-KEM-768 Keygen ====================
      setCurrentStep('ML-KEM-768 Keygen');
      const a = new HybridKeyExchange();
      await a.initialize();
      add('ML-KEM-768 Keygen', true, '✅ Keypair generated');

      // ==================== STEP 5: Hybrid Handshake ====================
      setCurrentStep('PQC Hybrid Handshake');
      const b = new HybridKeyExchange();
      const bKeys = await b.initialize();
      const { ciphertext, sharedSecret: sA } = await a.encapsulateToPeer(bKeys.kemPublicKey, bKeys.ecdhPublicKey);
      const sB = await b.decapsulateFromPeer(ciphertext, (a as any).ecdhPublicKey);
      const match = Buffer.compare(Buffer.from(sA), Buffer.from(sB)) === 0;
      add('Hybrid Handshake', match, match ? '✅ Shared secret match' : '❌ Key mismatch');

      setCurrentStep('');
    } catch (e: any) {
      add(currentStep || 'Error', false, `❌ ${e.message}`);
      setCurrentStep('');
    } finally {
      setRunning(false);
    }
  };

  const allPassed = results.length > 0 && results.every(r => r.ok);
  const anyDone = results.length > 0;

  return (
    <SafeAreaView style={[styles.container, { backgroundColor: c.bg }]}>
      <StatusBar barStyle={isDark ? 'light-content' : 'dark-content'} />

      <ScrollView contentContainerStyle={styles.scrollContent}>
        {/* ============ Header ============ */}
        <View style={styles.header}>
          <Text style={[styles.title, { color: c.text }]}>FIBEMATE Mobile</Text>
          <Text style={[styles.subtitle, { color: c.subtext }]}>SM2 • ML-KEM-768 • PQC Hybrid</Text>
          {anyDone && (
            <Badge ok={allPassed} label={allPassed ? 'ALL PASS' : 'FAILURES'} />
          )}
        </View>

        {/* ============ Steps ============ */}
        {results.map((r, i) => (
          <Step
            key={i}
            step={i + 1}
            title={r.title}
            result={r.detail}
            running={running && i === results.length - 1}
            done={!running || i < results.length - 1}
          />
        ))}

        {/* ============ Run Button ============ */}
        <TouchableOpacity
          style={[styles.runButton, { backgroundColor: running ? c.border : c.accent }]}
          onPress={runAllTests}
          disabled={running}
          activeOpacity={0.7}>
          {running ? (
            <View style={styles.runButtonContent}>
              <ActivityIndicator size="small" color="#FFF" />
              <Text style={styles.runButtonText}>{currentStep}</Text>
            </View>
          ) : (
            <Text style={styles.runButtonText}>
              {anyDone ? '↻ Re-run Tests' : '▶ Run SM2 + PQC Tests'}
            </Text>
          )}
        </TouchableOpacity>

        {/* ============ Summary ============ */}
        {anyDone && (
          <View style={[styles.summaryCard, { backgroundColor: c.card, borderColor: c.border }]}>
            <Text style={[styles.summaryTitle, { color: c.text }]}>
              {allPassed ? '🎉 All Tests Passed' : '⚠️ Some Tests Failed'}
            </Text>
            <Text style={[styles.summaryText, { color: c.subtext }]}>
              {results.filter(r => r.ok).length} / {results.length} successful
            </Text>
          </View>
        )}
      </ScrollView>
    </SafeAreaView>
  );
}

// ============ Styles ============
const styles = StyleSheet.create({
  container: { flex: 1 },
  scrollContent: { padding: 20, paddingBottom: 40 },
  header: { alignItems: 'center', marginBottom: 24, marginTop: 12 },
  title: { fontSize: 26, fontWeight: '700', marginBottom: 4 },
  subtitle: { fontSize: 14, marginBottom: 12 },
  badge: { flexDirection: 'row', alignItems: 'center', backgroundColor: '#161B2266', paddingHorizontal: 12, paddingVertical: 6, borderRadius: 20 },
  badgeDot: { width: 8, height: 8, borderRadius: 4, marginRight: 6 },
  badgeText: { color: '#E6EDF3', fontSize: 13, fontWeight: '600' },

  step: { flexDirection: 'row', alignItems: 'flex-start', marginBottom: 12 },
  stepCircle: { width: 28, height: 28, borderRadius: 14, backgroundColor: '#30363D', justifyContent: 'center', alignItems: 'center', marginRight: 12, marginTop: 2 },
  stepDone: { backgroundColor: '#1A7F37' },
  stepRunning: { backgroundColor: '#0969DA' },
  stepNum: { color: '#E6EDF3', fontSize: 13, fontWeight: '600' },
  stepContent: { flex: 1 },
  stepTitle: { color: '#E6EDF3', fontSize: 14, fontWeight: '600', marginBottom: 2 },
  stepResult: { fontSize: 12, fontFamily: 'monospace' },

  runButton: { paddingVertical: 14, paddingHorizontal: 24, borderRadius: 10, marginTop: 8, marginBottom: 20, alignItems: 'center' },
  runButtonContent: { flexDirection: 'row', alignItems: 'center', gap: 8 },
  runButtonText: { color: '#FFF', fontSize: 16, fontWeight: '600' },

  summaryCard: { padding: 16, borderRadius: 10, borderWidth: 1 },
  summaryTitle: { fontSize: 16, fontWeight: '700', marginBottom: 4, textAlign: 'center' },
  summaryText: { fontSize: 13, textAlign: 'center' },
});
