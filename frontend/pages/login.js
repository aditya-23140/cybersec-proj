import { useState } from 'react';
import Head from 'next/head';
import { useRouter } from 'next/router';
import Link from 'next/link';
import Layout from '../components/Layout';
import { login } from '../lib/api';

export default function Login() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const router = useRouter();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(null); setLoading(true);
    try {
      const res = await login(username.trim(), password);
      localStorage.setItem('token', res.data.access_token);
      localStorage.setItem('username', username.trim());
      router.push('/');
    } catch (err) {
      setError(err.response?.data?.detail || 'Login failed. Check your credentials.');
    } finally { setLoading(false); }
  };

  return (
    <Layout>
      <Head><title>Login — PhishGuard</title></Head>
      <div style={{ maxWidth: 400, margin: '3rem auto' }}>
        <h2 style={{ marginBottom: '1.5rem', textAlign: 'center' }}>Log In</h2>
        {error && <div className="error-box" style={{ marginBottom: '1rem' }}>{error}</div>}
        <div className="card">
          <form onSubmit={handleSubmit}>
            <div style={{ marginBottom: '1rem' }}>
              <label htmlFor="username">Username</label>
              <input id="username" type="text" value={username} onChange={e => setUsername(e.target.value)} autoComplete="username" required />
            </div>
            <div style={{ marginBottom: '1.25rem' }}>
              <label htmlFor="password">Password</label>
              <input id="password" type="password" value={password} onChange={e => setPassword(e.target.value)} autoComplete="current-password" required />
            </div>
            <button type="submit" className="btn btn-primary" style={{ width: '100%' }} disabled={loading}>
              {loading ? 'Logging in...' : 'Log In'}
            </button>
          </form>
          <p style={{ textAlign: 'center', marginTop: '1rem', fontSize: '0.88rem', color: 'var(--color-muted)' }}>
            No account? <Link href="/register" style={{ color: 'var(--color-navy)', fontWeight: 600 }}>Register</Link>
          </p>
        </div>
      </div>
    </Layout>
  );
}
