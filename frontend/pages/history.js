import { useState, useEffect } from 'react';
import Head from 'next/head';
import { useRouter } from 'next/router';
import Layout from '../components/Layout';
import RiskBadge from '../components/RiskBadge';
import { getHistory } from '../lib/api';

export default function History() {
  const [items, setItems] = useState([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const router = useRouter();

  useEffect(() => {
    const token = typeof window !== 'undefined' ? localStorage.getItem('token') : null;
    if (!token) { router.push('/login'); return; }

    setLoading(true);
    getHistory(page)
      .then(res => { setItems(res.data.items); setTotal(res.data.total); })
      .catch(err => {
        if (err.response?.status === 401) router.push('/login');
        else setError('Could not load history.');
      })
      .finally(() => setLoading(false));
  }, [page]);

  return (
    <Layout>
      <Head><title>Scan History — PhishGuard</title></Head>
      <h2 style={{ marginBottom: '1rem' }}>🕑 Scan History</h2>
      <p style={{ color: 'var(--color-muted)', marginBottom: '1.5rem', fontSize: '0.88rem' }}>
        Your personal scan history. Only your scans are shown.
      </p>

      {loading && <div style={{ textAlign: 'center', padding: '2rem' }}><span className="spinner" style={{ margin: '0 auto' }} /></div>}
      {error && <div className="error-box">{error}</div>}

      {!loading && !error && items.length === 0 && (
        <div className="empty-state card">
          <h3>No scans yet</h3>
          <p>Check a URL on the home page to see your history here.</p>
        </div>
      )}

      {!loading && !error && items.length > 0 && (
        <>
          <div className="card" style={{ overflowX: 'auto', padding: 0 }}>
            <table>
              <thead>
                <tr>
                  <th>URL</th>
                  <th>Risk</th>
                  <th>Probability</th>
                  <th>Source</th>
                  <th>Date</th>
                </tr>
              </thead>
              <tbody>
                {items.map(item => (
                  <tr key={item.id}>
                    <td style={{ maxWidth: 320, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={item.url}>
                      {item.url}
                    </td>
                    <td><RiskBadge risk={item.risk_level} /></td>
                    <td>{(item.phishing_probability * 100).toFixed(1)}%</td>
                    <td><span style={{ fontSize: '0.78rem', color: 'var(--color-muted)' }}>{item.source}</span></td>
                    <td style={{ fontSize: '0.82rem', color: 'var(--color-muted)', whiteSpace: 'nowrap' }}>
                      {new Date(item.created_at).toLocaleString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div style={{ display: 'flex', gap: '0.5rem', justifyContent: 'center', marginTop: '1rem' }}>
            <button className="btn btn-outline" disabled={page === 1} onClick={() => setPage(p => p - 1)}>← Prev</button>
            <span style={{ padding: '0.6rem 1rem', fontSize: '0.88rem', color: 'var(--color-muted)' }}>
              Page {page} · {total} total
            </span>
            <button className="btn btn-outline" disabled={items.length < 20} onClick={() => setPage(p => p + 1)}>Next →</button>
          </div>
        </>
      )}
    </Layout>
  );
}
