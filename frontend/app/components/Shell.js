'use client';

import Link from 'next/link';
import { usePathname, useRouter } from 'next/navigation';
import { useEffect, useState } from 'react';

export default function Shell({ children }) {
  const pathname = usePathname();
  const router = useRouter();
  const [theme, setTheme] = useState('light');
  const [user, setUser] = useState(null);

  useEffect(() => {
    const saved = localStorage.getItem('fihh-theme');
    const preferred = saved || (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
    setTheme(preferred);
    document.documentElement.dataset.theme = preferred;
    const username = localStorage.getItem('username');
    if (localStorage.getItem('token') && username) setUser(username);
  }, []);

  const toggleTheme = () => {
    const next = theme === 'dark' ? 'light' : 'dark';
    setTheme(next);
    localStorage.setItem('fihh-theme', next);
    document.documentElement.dataset.theme = next;
  };

  const logout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('username');
    setUser(null);
    router.push('/');
  };

  const nav = [
    ['/', 'scan'],
    ['/dashboard', 'dashboard'],
    ['/history', 'history'],
    ['/education', 'how it works'],
    ['/forum', 'community'],
  ];

  return (
    <div className="app-shell">
      <header className="topbar">
        <Link href="/" className="brand" aria-label="FihhGuard home">
          <span className="brand-fish" aria-hidden="true"><FihhMark /></span> fihhguard
        </Link>
        <nav aria-label="Main navigation">
          {nav.map(([href, label]) => (
            <Link key={href} href={href} className={pathname === href ? 'active' : ''}>{label}</Link>
          ))}
        </nav>
        <div className="top-actions">
          <button className="icon-btn" onClick={toggleTheme} aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`}>
            {theme === 'dark' ? '☼' : '◐'}
          </button>
          {user ? (
            <button className="text-btn" onClick={logout}>log out</button>
          ) : (
            <Link href="/login" className="text-btn">log in</Link>
          )}
        </div>
      </header>
      <main className="site-main">{children}</main>
      <footer className="site-footer">
        <span>fihhguard / no detector is perfect, so stay sharp.</span>
        <Link href="/education">learn the tells →</Link>
      </footer>
    </div>
  );
}

function FihhMark() {
  return <svg width="28" height="28" viewBox="0 0 64 64" fill="none">
    <path d="M44 32 60 20q-2 12 0 24Z" fill="var(--accent)" stroke="currentColor" strokeWidth="2" strokeLinejoin="round" />
    <ellipse cx="28" cy="32" rx="19" ry="14" fill="var(--accent)" stroke="currentColor" strokeWidth="2" />
    <path d="M26 38q4 10 12 6-4-4-6-8Z" fill="var(--accent)" stroke="currentColor" strokeWidth="2" />
    <circle cx="17" cy="29" r="3" fill="currentColor" />
    <circle cx="16" cy="28" r="1" fill="var(--paper)" />
    <path d="M10 36q3 2 6 0" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
  </svg>;
}
