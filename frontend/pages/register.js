import { useState } from 'react';
import Head from 'next/head';
import { useRouter } from 'next/router';
import Link from 'next/link';
import Layout from '../components/Layout';
import { register } from '../lib/api';

export default function Register() {
  const [form, setForm] = useState({ username: '', email: '', password: '', confirm: '' });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const router = useRouter();

  const set = (k) => (e) => setForm(f => ({ ...f, [k]: e.target.value }));

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(null);
    if (form.password !== form.confirm) { setError('Passwords do not match.'); return; }
    if (form.password.length < 8) { setError('Password must be at least 8 characters.'); return; }
    setLoading(true);
    try {
      await register(form.username.trim(), form.email.trim(), form.password);
      router.push('/login');
    } catch (err) {
      setError(err.response?.data?.detail || 'Registration failed.');
    } finally { setLoading(false); }
  };

  return (
    <Layout>
      <Head><title>Register — PhishGuard</title></Head>
      <div style={{ maxWidth: 420, margin: '3rem auto' }}>
        <h2 style={{ marginBottom: '1.5rem', textAlign: 'center' }}>Create Account</h2>
        {error && <div className="error-box" style={{ marginBottom: '1rem' }}>{error}</div>}
        <div className="card">
          <form onSubmit={handleSubmit}>
            {[
              { id: 'username', label: 'Username', type: 'text', key: 'username', autocomplete: 'username' },
              { id: 'email', label: 'Email', type: 'email', key: 'email', autocomplete: 'email' },
              { id: 'password', label: 'Password (min 8 chars)', type: 'password', key: 'password', autocomplete: 'new-password' },
              { id: 'confirm', label: 'Confirm Password', type: 'password', key: 'confirm', autocomplete: 'new-password' },
            ].map(({ id, label, type, key, autocomplete }) => (
              <div key={id} style={{ marginBottom: '1rem' }}>
                <label htmlFor={id}>{label}</label>
                <input id={id} type={type} value={form[key]} onChange={set(key)} autoComplete={autocomplete} required />
              </div>
            ))}
            <button type="submit" className="btn btn-primary" style={{ width: '100%' }} disabled={loading}>
              {loading ? 'Creating account...' : 'Register'}
            </button>
          </form>
          <p style={{ textAlign: 'center', marginTop: '1rem', fontSize: '0.88rem', color: 'var(--color-muted)' }}>
            Already have an account? <Link href="/login" style={{ color: 'var(--color-navy)', fontWeight: 600 }}>Log In</Link>
          </p>
        </div>
      </div>
    </Layout>
  );
}
