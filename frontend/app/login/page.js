'use client';

import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useState } from 'react';
import { login } from '../../lib/api';

export default function Login() {
  const router = useRouter();
  const [form, setForm] = useState({ username: '', password: '' });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const submit = async (event) => {
    event.preventDefault(); setLoading(true); setError('');
    try { const response = await login(form.username.trim(), form.password); localStorage.setItem('token', response.data.access_token); localStorage.setItem('username', form.username.trim()); router.push('/'); }
    catch (err) { setError(err.response?.data?.detail || 'could not log you in. check those details.'); }
    finally { setLoading(false); }
  };
  return <section className="auth-card"><span className="eyebrow">welcome back</span><h1>log in</h1>{error && <div className="error-box">{error}</div>}<form className="card form-stack" onSubmit={submit}><div><label htmlFor="username">username</label><input id="username" value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} required /></div><div><label htmlFor="password">password</label><input id="password" type="password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} required /></div><button className="btn btn-primary" disabled={loading}>{loading ? 'checking...' : 'log in'}</button><p className="muted">new here? <Link href="/register">make an account</Link></p></form></section>;
}
