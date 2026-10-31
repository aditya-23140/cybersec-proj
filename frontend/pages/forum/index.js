import { useState, useEffect } from 'react';
import Head from 'next/head';
import Link from 'next/link';
import { useRouter } from 'next/router';
import Layout from '../../components/Layout';
import { getForumPosts } from '../../lib/api';

export default function Forum() {
  const [posts, setPosts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const router = useRouter();

  useEffect(() => {
    const token = typeof window !== 'undefined' ? localStorage.getItem('token') : null;
    setIsLoggedIn(!!token);

    if (!token) { setLoading(false); return; }
    getForumPosts()
      .then(res => setPosts(Array.isArray(res.data) ? res.data : []))
      .catch(err => {
        if (err.response?.status === 401) setIsLoggedIn(false);
        else setError('Could not load forum posts.');
      })
      .finally(() => setLoading(false));
  }, []);

  return (
    <Layout>
      <Head><title>Forum — PhishGuard</title></Head>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
        <h2>💬 Community Forum</h2>
        {isLoggedIn && (
          <Link href="/forum/create" className="btn btn-primary">+ New Post</Link>
        )}
      </div>

      {!isLoggedIn && (
        <div className="info-box" style={{ marginBottom: '1.5rem' }}>
          <Link href="/login" style={{ color: '#1e40af', fontWeight: 600 }}>Log in</Link> to participate in the forum.
        </div>
      )}

      {loading && <div style={{ textAlign: 'center', padding: '2rem' }}><span className="spinner" style={{ margin: '0 auto' }} /></div>}
      {error && <div className="error-box">{error}</div>}

      {!loading && isLoggedIn && posts.length === 0 && (
        <div className="empty-state card">
          <h3>No posts yet</h3>
          <p>Be the first to start a discussion!</p>
        </div>
      )}

      {posts.map(post => (
        <Link key={post.id} href={`/forum/${post.id}`} style={{ display: 'block', marginBottom: '0.75rem', textDecoration: 'none' }}>
          <div className="card" style={{ transition: 'box-shadow 0.15s', cursor: 'pointer' }}
            onMouseEnter={e => e.currentTarget.style.boxShadow = 'var(--shadow-lg)'}
            onMouseLeave={e => e.currentTarget.style.boxShadow = 'var(--shadow)'}
          >
            <h3 style={{ marginBottom: '0.25rem', color: 'var(--color-navy)' }}>{post.title}</h3>
            <p style={{ fontSize: '0.88rem', color: 'var(--color-muted)' }}>
              by <strong>{post.username}</strong> · {new Date(post.created_at).toLocaleDateString()}
            </p>
          </div>
        </Link>
      ))}
    </Layout>
  );
}
