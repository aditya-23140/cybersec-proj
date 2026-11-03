'use client';

import Link from 'next/link';
import { useEffect, useState } from 'react';
import { getForumPosts } from '../../lib/api';

export default function Forum() {
  const [posts, setPosts] = useState([]);
  const [logged, setLogged] = useState(false);
  useEffect(() => { setLogged(Boolean(localStorage.getItem('token'))); if (localStorage.getItem('token')) getForumPosts().then((r) => setPosts(Array.isArray(r.data) ? r.data : [])); }, []);
  return <section><div className="section-title"><div><span className="eyebrow">the school of fish</span><h1>community</h1></div>{logged && <Link className="btn btn-primary" href="/forum/create">new post</Link>}</div>{!logged && <p className="card">log in to join the conversation.</p>}<div className="stack">{posts.map((post) => <Link className="card" href={`/forum/${post.id}`} key={post.id}><h2>{post.title}</h2><p className="muted">by {post.username} · {new Date(post.created_at).toLocaleDateString()}</p></Link>)}</div></section>;
}
