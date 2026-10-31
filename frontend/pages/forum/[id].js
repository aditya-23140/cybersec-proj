import { useState, useEffect } from 'react';
import Head from 'next/head';
import { useRouter } from 'next/router';
import Link from 'next/link';
import Layout from '../../components/Layout';
import { getForumPost, getForumReplies, createReply } from '../../lib/api';

export default function ThreadPage() {
  const router = useRouter();
  const { id } = router.query;
  const [post, setPost] = useState(null);
  const [replies, setReplies] = useState([]);
  const [body, setBody] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState(null);
  const [isLoggedIn, setIsLoggedIn] = useState(false);

  useEffect(() => {
    setIsLoggedIn(!!(typeof window !== 'undefined' && localStorage.getItem('token')));
    if (!id) return;
    Promise.all([getForumPost(id), getForumReplies(id)])
      .then(([p, r]) => { setPost(p.data); setReplies(Array.isArray(r.data) ? r.data : []); })
      .catch(() => setError('Could not load this thread.'));
  }, [id]);

  const handleReply = async (e) => {
    e.preventDefault();
    if (!body.trim()) return;
    setSubmitting(true); setError(null);
    try {
      await createReply(id, body.trim());
      const res = await getForumReplies(id);
      setReplies(Array.isArray(res.data) ? res.data : []);
      setBody('');
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to post reply.');
    } finally { setSubmitting(false); }
  };

  return (
    <Layout>
      <Head><title>{post?.title || 'Thread'} — PhishGuard Forum</title></Head>
      <Link href="/forum" style={{ color: 'var(--color-muted)', fontSize: '0.88rem', display: 'inline-block', marginBottom: '1rem' }}>
        ← Back to Forum
      </Link>

      {error && <div className="error-box" style={{ marginBottom: '1rem' }}>{error}</div>}

      {post && (
        <div className="card" style={{ marginBottom: '1.5rem' }}>
          <h2 style={{ marginBottom: '0.25rem' }}>{post.title}</h2>
          <p style={{ fontSize: '0.82rem', color: 'var(--color-muted)', marginBottom: '1rem' }}>
            by <strong>{post.username}</strong> · {new Date(post.created_at).toLocaleString()}
          </p>
          <p style={{ lineHeight: 1.7, whiteSpace: 'pre-wrap' }}>{post.body}</p>
        </div>
      )}

      <h3 style={{ marginBottom: '1rem' }}>Replies ({replies.length})</h3>
      {replies.map(r => (
        <div key={r.id} className="card" style={{ marginBottom: '0.75rem', background: '#f8fafc' }}>
          <p style={{ fontSize: '0.82rem', color: 'var(--color-muted)', marginBottom: '0.4rem' }}>
            <strong>{r.username}</strong> · {new Date(r.created_at).toLocaleString()}
          </p>
          <p style={{ whiteSpace: 'pre-wrap', lineHeight: 1.6 }}>{r.body}</p>
        </div>
      ))}

      {isLoggedIn ? (
        <div className="card" style={{ marginTop: '1.5rem' }}>
          <h4 style={{ marginBottom: '0.75rem' }}>Add a Reply</h4>
          <form onSubmit={handleReply}>
            <textarea
              value={body} onChange={e => setBody(e.target.value)}
              rows={4} maxLength={5000}
              placeholder="Write your reply..."
              style={{ marginBottom: '0.75rem', resize: 'vertical' }}
            />
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: '0.78rem', color: 'var(--color-muted)' }}>{body.length}/5000</span>
              <button type="submit" className="btn btn-primary" disabled={submitting || !body.trim()}>
                {submitting ? '...' : 'Post Reply'}
              </button>
            </div>
          </form>
        </div>
      ) : (
        <div className="info-box" style={{ marginTop: '1.5rem' }}>
          <Link href="/login" style={{ color: '#1e40af', fontWeight: 600 }}>Log in</Link> to reply.
        </div>
      )}
    </Layout>
  );
}
