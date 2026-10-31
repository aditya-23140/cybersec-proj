import { useState, useEffect } from 'react';
import Head from 'next/head';
import Layout from '../components/Layout';
import RiskBadge from '../components/RiskBadge';
import { getStats, getModelInfo } from '../lib/api';
import { PieChart, Pie, Cell, Tooltip, Legend, ResponsiveContainer } from 'recharts';

const COLORS = { safe: '#22c55e', suspicious: '#f97316', dangerous: '#ef4444' };

export default function Dashboard() {
  const [stats, setStats] = useState(null);
  const [modelInfo, setModelInfo] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    Promise.all([getStats(), getModelInfo()])
      .then(([sRes, mRes]) => { setStats(sRes.data); setModelInfo(mRes.data); })
      .catch(() => setError('Could not load dashboard data. Is the backend running?'))
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <Layout><div style={{ textAlign: 'center', padding: '4rem' }}><span className="spinner" style={{ margin: '0 auto' }} /></div></Layout>;
  if (error) return <Layout><Head><title>Dashboard</title></Head><div className="error-box">{error}</div></Layout>;

  const pieData = [
    { name: 'Safe', value: stats.safe_count },
    { name: 'Suspicious', value: stats.suspicious_count },
    { name: 'Dangerous', value: stats.dangerous_count },
  ].filter(d => d.value > 0);

  return (
    <Layout>
      <Head><title>Dashboard — PhishGuard</title></Head>
      <h2 style={{ marginBottom: '1.5rem' }}>📊 Statistics Dashboard</h2>
      <p style={{ color: 'var(--color-muted)', marginBottom: '1.5rem', fontSize: '0.9rem' }}>
        All statistics are from actual scan records in the database. No seeded or fabricated data.
      </p>

      {stats.total_scans === 0 ? (
        <div className="empty-state card">
          <h3>No scans yet</h3>
          <p>Use the URL checker on the home page to run your first scan.</p>
        </div>
      ) : (
        <>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: '1rem', marginBottom: '1.5rem' }}>
            {[
              { label: 'Total Scans', value: stats.total_scans, color: 'var(--color-navy)' },
              { label: 'Safe', value: stats.safe_count, color: '#166534' },
              { label: 'Suspicious', value: stats.suspicious_count, color: '#9a3412' },
              { label: 'Dangerous', value: stats.dangerous_count, color: '#991b1b' },
              { label: 'Last 24h', value: stats.recent_scans_24h, color: 'var(--color-navy)' },
            ].map(({ label, value, color }) => (
              <div key={label} className="card" style={{ textAlign: 'center' }}>
                <div style={{ fontSize: '2rem', fontWeight: 900, color }}>{value}</div>
                <div style={{ fontSize: '0.82rem', color: 'var(--color-muted)', marginTop: '0.25rem' }}>{label}</div>
              </div>
            ))}
          </div>

          {pieData.length > 0 && (
            <div className="card" style={{ marginBottom: '1.5rem' }}>
              <h3 style={{ marginBottom: '1rem' }}>Risk Level Distribution</h3>
              <ResponsiveContainer width="100%" height={280}>
                <PieChart>
                  <Pie data={pieData} cx="50%" cy="50%" outerRadius={100} dataKey="value" label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}>
                    {pieData.map((entry) => (
                      <Cell key={entry.name} fill={COLORS[entry.name.toLowerCase()] || '#9ca3af'} />
                    ))}
                  </Pie>
                  <Tooltip />
                  <Legend />
                </PieChart>
              </ResponsiveContainer>
            </div>
          )}
        </>
      )}

      <div className="card">
        <h3 style={{ marginBottom: '0.75rem' }}>Model Status</h3>
        <p><strong>Version:</strong> {modelInfo?.model_version || 'N/A'}</p>
        <p><strong>Model loaded:</strong> {modelInfo?.model_loaded ? '✅ Yes' : '❌ No — train the model first'}</p>
        {modelInfo?.threshold_config && (
          <>
            <p><strong>Suspicious threshold:</strong> {(modelInfo.threshold_config.suspicious_threshold * 100).toFixed(0)}%</p>
            <p><strong>Dangerous threshold:</strong> {(modelInfo.threshold_config.dangerous_threshold * 100).toFixed(0)}%</p>
          </>
        )}
        {stats.last_scan_at && <p><strong>Last scan:</strong> {new Date(stats.last_scan_at).toLocaleString()}</p>}
      </div>
    </Layout>
  );
}
