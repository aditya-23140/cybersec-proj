import { useState, useEffect } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/router';
import styles from './Layout.module.css';

export default function Layout({ children }) {
  const [user, setUser] = useState(null);
  const router = useRouter();

  useEffect(() => {
    const token = localStorage.getItem('token');
    const username = localStorage.getItem('username');
    if (token && username) setUser({ username });
  }, []);

  const handleLogout = () => {
    localStorage.removeItem('token');
    localStorage.removeItem('username');
    setUser(null);
    router.push('/');
  };

  const navLinks = [
    { href: '/', label: '🔍 Check URL' },
    { href: '/dashboard', label: '📊 Dashboard' },
    { href: '/forum', label: '💬 Forum' },
    { href: '/education', label: '📚 Learn' },
  ];

  return (
    <div className={styles.wrapper}>
      <nav className={styles.nav}>
        <div className={styles.navInner}>
          <Link href="/" className={styles.logo}>🛡️ PhishGuard</Link>
          <div className={styles.navLinks}>
            {navLinks.map(({ href, label }) => (
              <Link
                key={href}
                href={href}
                className={`${styles.navLink} ${router.pathname === href ? styles.active : ''}`}
              >
                {label}
              </Link>
            ))}
            {user && (
              <>
                <Link href="/history" className={`${styles.navLink} ${router.pathname === '/history' ? styles.active : ''}`}>
                  🕑 History
                </Link>
                <Link href="/lists" className={`${styles.navLink} ${router.pathname === '/lists' ? styles.active : ''}`}>
                  📋 Lists
                </Link>
              </>
            )}
          </div>
          <div className={styles.authArea}>
            {user ? (
              <>
                <span className={styles.username}>👤 {user.username}</span>
                <button className="btn btn-outline" onClick={handleLogout} style={{ fontSize: '0.82rem', padding: '0.4rem 0.9rem' }}>
                  Logout
                </button>
              </>
            ) : (
              <>
                <Link href="/login" className="btn btn-outline" style={{ fontSize: '0.82rem', padding: '0.4rem 0.9rem' }}>Login</Link>
                <Link href="/register" className="btn btn-primary" style={{ fontSize: '0.82rem', padding: '0.4rem 0.9rem' }}>Register</Link>
              </>
            )}
          </div>
        </div>
      </nav>
      <main className={styles.main}>{children}</main>
      <footer className={styles.footer}>
        <p>PhishGuard — URL Phishing Detection. Predictions are probabilistic estimates, not guarantees.</p>
      </footer>
    </div>
  );
}
