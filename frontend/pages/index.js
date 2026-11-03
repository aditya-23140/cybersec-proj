import { useState } from 'react';
import Head from 'next/head';
import Layout from '../components/Layout';
import ScanResult from '../components/ScanResult';
import { checkUrl } from '../lib/api';
import styles from './index.module.css';

export default function Home() {
  const [url, setUrl] = useState('');
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const validateUrl = (u) => {
    try {
      const parsed = new URL(u.trim());
      return ['http:', 'https:'].includes(parsed.protocol);
    } catch { return false; }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(null); setResult(null);

    const trimmed = url.trim();
    if (!trimmed) { setError('Please enter a URL.'); return; }
    if (!validateUrl(trimmed)) {
      setError('URL must start with http:// or https://');
      return;
    }

    setLoading(true);
    try {
      const resp = await checkUrl(trimmed);
      setResult(resp.data);
    } catch (err) {
      if (err.response?.status === 503) {
        setError('Backend model is unavailable. Please ensure the server is running with a trained model.');
      } else if (err.response?.status === 422) {
        setError(err.response.data?.detail || 'Invalid URL format.');
      } else if (err.code === 'ECONNABORTED' || err.code === 'ERR_NETWORK') {
        setError('Could not reach the backend server. Is it running at http://127.0.0.1:8000?');
      } else {
        setError('Unexpected error. Please try again.');
      }
    } finally {
      setLoading(false);
    }
  };

  return (
    <Layout>
      <Head><title>PhishGuard — URL Phishing Detection</title></Head>
      <div className={styles.hero}>
        <h1>🛡️ PhishGuard</h1>
        <p className={styles.tagline}>Hybrid XGBoost URL and page-signal phishing detection. Paste a URL to check its risk level.</p>
        <div className={styles.disclaimer}>
          ⚠ Predictions are probabilistic. The browser extension can additionally provide sanitized page-structure signals.
          This tool may be incorrect. Do not rely on it as your only security measure.
        </div>
      </div>

      <div className={`card ${styles.checker}`}>
        <form onSubmit={handleSubmit}>
          <label htmlFor="url-input">Enter URL to analyse</label>
          <div className={styles.inputRow}>
            <input
              id="url-input"
              type="text"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="https://example.com/path"
              disabled={loading}
              autoComplete="off"
              spellCheck={false}
            />
            <button type="submit" className="btn btn-primary" disabled={loading}>
              {loading ? <span className="spinner" /> : 'Check'}
            </button>
          </div>
        </form>

        {error && <div className="error-box" style={{ marginTop: '1rem' }}>{error}</div>}
        {result && <ScanResult result={result} />}
      </div>
    </Layout>
  );
}
