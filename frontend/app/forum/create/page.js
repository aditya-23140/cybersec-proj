'use client';

import { useRouter } from 'next/navigation';
import { useEffect, useState } from 'react';
import { createForumPost } from '../../../lib/api';

export default function CreatePost() {
  const router = useRouter();
  const [title, setTitle] = useState('');
  const [body, setBody] = useState('');
  const [error, setError] = useState('');
  useEffect(() => { if (!localStorage.getItem('token')) router.push('/login'); }, [router]);
  const submit = async (event) => { event.preventDefault(); try { const response = await createForumPost(title.trim(), body.trim()); router.push(`/forum/${response.data.id}`); } catch (err) { setError(err.response?.data?.detail || 'could not post that.'); } };
  return <section className="auth-card"><span className="eyebrow">make some noise</span><h1>new post</h1>{error && <div className="error-box">{error}</div>}<form className="card form-stack" onSubmit={submit}><div><label htmlFor="title">title</label><input id="title" value={title} onChange={(e) => setTitle(e.target.value)} maxLength={200} required /></div><div><label htmlFor="body">body</label><textarea id="body" value={body} onChange={(e) => setBody(e.target.value)} maxLength={5000} rows={8} required /></div><button className="btn btn-primary">post it</button></form></section>;
}
