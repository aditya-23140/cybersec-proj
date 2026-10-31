import { useState, useEffect } from 'react';
import Head from 'next/head';
import { useRouter } from 'next/router';
import Layout from '../components/Layout';
import { getAllowlist, addAllowlist, deleteAllowlist, getBlocklist, addBlocklist, deleteBlocklist } from '../lib/api';

function ListSection({ title, items, onAdd, onDelete, placeholder, description }) {
  const [domain, setDomain] = useState('');
  const [notes, setNotes] = useState('');
  const [adding, setAdding] = useState(false);
  const [error, setError] = useState(null);

  const handleAdd = async (e) => {
    e.preventDefault();
    setError(null);
    const d = domain.trim().toLowerCase().replace(/^www\./, '').replace(/^https?:\/\//, '').split('/')[0];
    if (!d) { setError('Enter a valid domain.'); return; }
    setAdding(true);
    try {
      await onAdd(d, notes.trim() || null);
      setDomain(''); setNotes('');
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to add domain.');
    } finally { setAdding(false); }
  };

  return (
    <div className="card" style={{ marginBottom: '1.5rem' }}>
      <h3 style={{ marginBottom: '0.5rem' }}>{title}</h3>
      <p style={{ color: 'var(--color-muted)', fontSize: '0.88rem', marginBottom: '1rem' }}>{description}</p>
      <form onSubmit={handleAdd} style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', marginBottom: '1rem' }}>
        <input type="text" value={domain} onChange={e => setDomain(e.target.value)} placeholder={placeholder} style={{ flex: '1 1 200px' }} />
        <input type="text" value={notes} onChange={e => setNotes(e.target.value)} placeholder="Notes (optional)" style={{ flex: '1 1 150px' }} />
        <button type="submit" className="btn btn-primary" disabled={adding}>{adding ? '...' : 'Add'}</button>
      </form>
      {error && <div className="error-box" style={{ marginBottom: '0.75rem' }}>{error}</div>}
      {items.length === 0 ? (
        <div className="empty-state" style={{ padding: '1.5rem' }}><p>No entries yet.</p></div>
      ) : (
        <table>
          <thead><tr><th>Domain</th><th>Notes</th><th>Added</th><th></th></tr></thead>
          <tbody>
            {items.map(item => (
              <tr key={item.id}>
                <td><code style={{ fontSize: '0.9rem' }}>{item.domain}</code></td>
                <td style={{ color: 'var(--color-muted)', fontSize: '0.88rem' }}>{item.notes || '—'}</td>
                <td style={{ fontSize: '0.78rem', color: 'var(--color-muted)' }}>{new Date(item.created_at).toLocaleDateString()}</td>
                <td>
                  <button className="btn btn-danger" style={{ fontSize: '0.78rem', padding: '0.3rem 0.6rem' }} onClick={() => onDelete(item.id)}>
                    Remove
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

export default function Lists() {
  const [allowlist, setAllowlist] = useState([]);
  const [blocklist, setBlocklist] = useState([]);
  const [loading, setLoading] = useState(true);
  const router = useRouter();

  const loadAll = () => {
    const token = typeof window !== 'undefined' ? localStorage.getItem('token') : null;
    if (!token) { router.push('/login'); return; }
    Promise.all([getAllowlist(), getBlocklist()])
      .then(([a, b]) => { setAllowlist(a.data.items); setBlocklist(b.data.items); })
      .catch(err => { if (err.response?.status === 401) router.push('/login'); })
      .finally(() => setLoading(false));
  };

  useEffect(() => { loadAll(); }, []);

  const handleAddAllow = async (domain, notes) => {
    await addAllowlist(domain, notes);
    const res = await getAllowlist();
    setAllowlist(res.data.items);
  };
  const handleDelAllow = async (id) => {
    await deleteAllowlist(id);
    setAllowlist(prev => prev.filter(i => i.id !== id));
  };
  const handleAddBlock = async (domain, notes) => {
    await addBlocklist(domain, notes);
    const res = await getBlocklist();
    setBlocklist(res.data.items);
  };
  const handleDelBlock = async (id) => {
    await deleteBlocklist(id);
    setBlocklist(prev => prev.filter(i => i.id !== id));
  };

  if (loading) return <Layout><div style={{ textAlign: 'center', padding: '4rem' }}><span className="spinner" style={{ margin: '0 auto' }} /></div></Layout>;

  return (
    <Layout>
      <Head><title>Allow/Block Lists — PhishGuard</title></Head>
      <h2 style={{ marginBottom: '0.5rem' }}>📋 Allow / Block Lists</h2>
      <p style={{ color: 'var(--color-muted)', marginBottom: '1.5rem', fontSize: '0.88rem' }}>
        Personal lists that supplement (but never replace) the ML model's prediction.
        Enter domains without http:// — e.g. <code>example.com</code>.
      </p>

      <ListSection
        title="✅ Allowlist"
        items={allowlist}
        onAdd={handleAddAllow}
        onDelete={handleDelAllow}
        placeholder="trusted-site.com"
        description="Domains you trust. The model still runs, but a note is added that you marked this domain as trusted."
      />
      <ListSection
        title="⛔ Blocklist"
        items={blocklist}
        onAdd={handleAddBlock}
        onDelete={handleDelBlock}
        placeholder="evil-domain.xyz"
        description="Domains you always want flagged as dangerous, regardless of the model prediction."
      />
    </Layout>
  );
}
