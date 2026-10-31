import axios from 'axios';

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://127.0.0.1:8000';

const api = axios.create({
  baseURL: `${API_URL}/api/v1`,
  timeout: 10000,
});

// Attach JWT from localStorage if present (client-side only)
api.interceptors.request.use((config) => {
  const token = typeof window !== 'undefined' ? localStorage.getItem('token') : null;
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

// ── URL Prediction ────────────────────────────────────────────────────────────
export const checkUrl      = (url)                   => api.post('/predict', { url });
export const getHealth     = ()                       => api.get('/health');
export const getStats      = ()                       => api.get('/stats');
export const getModelInfo  = ()                       => api.get('/model-info');

// ── History ───────────────────────────────────────────────────────────────────
export const getHistory    = (page = 1)               => api.get(`/history?page=${page}`);

// ── Allow/Blocklists ──────────────────────────────────────────────────────────
export const getAllowlist   = ()                       => api.get('/allowlist');
export const addAllowlist   = (domain, notes)         => api.post('/allowlist', { domain, notes });
export const deleteAllowlist = (id)                   => api.delete(`/allowlist/${id}`);
export const getBlocklist   = ()                       => api.get('/blocklist');
export const addBlocklist   = (domain, notes)         => api.post('/blocklist', { domain, notes });
export const deleteBlocklist = (id)                   => api.delete(`/blocklist/${id}`);

// ── Forum ─────────────────────────────────────────────────────────────────────
export const getForumPosts   = (page = 1)             => api.get(`/forum/posts?page=${page}`);
export const createForumPost = (title, body)          => api.post('/forum/posts', { title, body });
export const getForumPost    = (id)                   => api.get(`/forum/posts/${id}`);
export const getForumReplies = (id)                   => api.get(`/forum/posts/${id}/replies`);
export const createReply     = (id, body)             => api.post(`/forum/posts/${id}/replies`, { body });

// ── Auth ──────────────────────────────────────────────────────────────────────
export const login    = (username, password)          => api.post('/auth/login', { username, password });
export const register = (username, email, password)   => api.post('/auth/register', { username, email, password });
export const logout   = ()                            => api.post('/auth/logout');
export const getMe    = ()                            => api.get('/auth/me');

export default api;
