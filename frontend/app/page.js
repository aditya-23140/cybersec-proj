'use client';

import Link from 'next/link';
import { useState } from 'react';
import { checkUrl } from '../lib/api';
import { FihhMascot, UrlInput, VerdictCard } from './components/Ui';

export default function Home() {
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);

  const scan = async (url) => {
    setLoading(true);
    try {
      const response = await checkUrl(url);
      setResult(response.data);
      const existing = JSON.parse(localStorage.getItem('fihh-history') || '[]');
      localStorage.setItem('fihh-history', JSON.stringify([{ ...response.data, scanned_at: new Date().toISOString() }, ...existing].slice(0, 50)));
    } catch (error) {
      setResult({
        risk_level: 'unknown',
        phishing_probability: 0,
        explanation: error.response?.data?.detail || 'the backend could not read this link right now.',
        model_mode: 'unknown',
      });
    } finally { setLoading(false); }
  };

  return (
    <>
      <section className="hero">
        <div>
          <span className="eyebrow">your slightly chaotic link buddy</span>
          <h1>don&apos;t get <em>hooked.</em></h1>
          <p className="hero-copy">fihhguard checks suspicious links before they get a chance to steal your login, your wallet, or your whole afternoon.</p>
          <UrlInput onScan={scan} />
          {loading && <VerdictCard loading />}
          {!loading && result && <><VerdictCard result={result} /><div className="scanner-actions"><button className="btn btn-outline" onClick={() => setResult(null)}>scan another</button></div></>}
        </div>
        <div className="hero-fish"><FihhMascot mood="chill" size={220} /></div>
      </section>
      <section className="steps" aria-label="How it works">
        {[['01', 'paste the link', 'No account. No weird hoops. Just drop the URL.'], ['02', 'fihh sniffs', 'URL patterns and available page structure get checked.'], ['03', 'you stay sharp', 'You get a plain-English verdict, not a mystery score.']].map(([number, title, copy]) => (
          <article className="step" key={number}><b>{number}</b><h3>{title}</h3><p>{copy}</p></article>
        ))}
      </section>
      <section className="install-banner">
        <div><h2>keep fihh in your browser</h2><p>the extension checks links before you click them.</p></div>
        <Link className="btn btn-outline" href="/education">see how it works →</Link>
      </section>
    </>
  );
}
