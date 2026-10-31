import { useState, useEffect } from 'react';
import Head from 'next/head';
import { useRouter } from 'next/router';
import Layout from '../../components/Layout';
import { createForumPost } from '../../lib/api';

export default function CreatePost() {
  const [title, setTitle] = useState('');
  const [body, setBody] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState(null);
  const router = useRouter();

  useEffect(() => {
    const token = typeof window !== 'undefined' ? localStorage.getItem('token') : null;
    if (!token) router.push('/login');
  }, []);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!title.trim() || !body.trim()) { setError('Title and body are required.'); return; }
    setSubmitting(true); setError(null);
    try {
      const res = await createForumPost(title.trim(), body.trim());
      router.push(`/forum/${res.data.id}`);
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to create post.');
    } finally { setSubmitting(false); }
  };

  return (
    <Layout>
      <Head><title>Create Post — PhishGuard Forum</title></Head>
      <div style={{ maxWidth: 720, margin: '0 auto' }}>
        <h2 style={{ marginBottom: '1.5rem' }}>📝 Create Forum Post</h2>
        {error && <div className="error-box" style={{ marginBottom: '1rem' }}>{error}</div>}
        <div className="card">
          <form onSubmit={handleSubmit}>
            <div style={{ marginBottom: '1rem' }}>
              <label htmlFor="title">Title <span style={{ color: 'var(--color-muted)', fontWeight: 400 }}>(max 200 chars)</span></label>
              <input id="title" type="text" value={title} onChange={e => setTitle(e.target.value)} maxLength={200} placeholder="e.g. How to spot a phishing link" />
              <div style={{ fontSize: '0.75rem', color: 'var(--color-muted)', marginTop: '0.25rem' }}>{title.length}/200</div>
            </div>
            <div style={{ marginBottom: '1.25rem' }}>
              <label htmlFor="body">Body <span style={{ color: 'var(--color-muted)', fontWeight: 400 }}>(max 5000 chars)</span></label>
              <textarea id="body" value={body} onChange={e => setBody(e.target.value)} rows={10} maxLength={5000} placeholder="Share your experience or question..." style={{ resize: 'vertical' }} />
              <div style={{ fontSize: '0.75rem', color: 'var(--color-muted)', marginTop: '0.25rem' }}>{body.length}/5000</div>
            </div>
            <div style={{ display: 'flex', gap: '0.75rem' }}>
              <button type="submit" className="btn btn-primary" disabled={submitting}>{submitting ? 'Posting...' : 'Post'}</button>
              <button type="button" className="btn btn-outline" onClick={() => router.push('/forum')}>Cancel</button>
            </div>
          </form>
        </div>
      </div>
    </Layout>
  );
}
