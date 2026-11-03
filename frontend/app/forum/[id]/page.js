'use client';

import Link from 'next/link';
import { useParams } from 'next/navigation';
import { useEffect, useState } from 'react';
import { createReply, getForumPost, getForumReplies } from '../../../lib/api';

export default function Thread() {
  const { id } = useParams();
  const [post, setPost] = useState(null);
  const [replies, setReplies] = useState([]);
  const [body, setBody] = useState('');
  const [logged, setLogged] = useState(false);
  useEffect(() => { setLogged(Boolean(localStorage.getItem('token'))); if (!id) return; Promise.all([getForumPost(id), getForumReplies(id)]).then(([p, r]) => { setPost(p.data); setReplies(Array.isArray(r.data) ? r.data : []); }); }, [id]);
  const submit = async (event) => { event.preventDefault(); if (!body.trim()) return; await createReply(id, body.trim()); setReplies((await getForumReplies(id)).data); setBody(''); };
  return <section className="prose"><Link href="/forum" className="muted">← community</Link>{post && <div className="card" style={{ marginTop: '1rem' }}><h1>{post.title}</h1><p>{post.body}</p></div>}<h2>replies ({replies.length})</h2>{replies.map((reply) => <div className="card" key={reply.id}><strong>{reply.username}</strong><p>{reply.body}</p></div>)}{logged && <form className="card form-stack" onSubmit={submit}><textarea value={body} onChange={(e) => setBody(e.target.value)} rows={4} placeholder="say something useful..." /><button className="btn btn-primary">reply</button></form>}</section>;
}
