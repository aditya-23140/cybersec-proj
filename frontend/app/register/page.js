'use client';

import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useState } from 'react';
import { register } from '../../lib/api';

export default function Register() {
  const router = useRouter();
  const [form, setForm] = useState({ username: '', email: '', password: '', confirm: '' });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const submit = async (event) => {
    event.preventDefault(); setError('');
    if (form.password !== form.confirm) return setError('those passwords do not match.');
    if (form.password.length < 8) return setError('passwords need at least 8 characters.');
    setLoading(true);
    try { await register(form.username.trim(), form.email.trim(), form.password); router.push('/login'); }
    catch (err) { setError(err.response?.data?.detail || 'could not create that account.'); }
    finally { setLoading(false); }
  };
  return <section className="auth-card"><span className="eyebrow">join the school of fish</span><h1>register</h1>{error && <div className="error-box">{error}</div>}<form className="card form-stack" onSubmit={submit}>{[['username', 'text'], ['email', 'email'], ['password', 'password'], ['confirm', 'password']].map(([key, type]) => <div key={key}><label htmlFor={key}>{key === 'confirm' ? 'confirm password' : key}</label><input id={key} type={type} value={form[key]} onChange={(e) => setForm({ ...form, [key]: e.target.value })} required /></div>)}<button className="btn btn-primary" disabled={loading}>{loading ? 'making waves...' : 'create account'}</button><p className="muted">already have one? <Link href="/login">log in</Link></p></form></section>;
}
