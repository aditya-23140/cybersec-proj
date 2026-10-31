import Head from 'next/head';
import Layout from '../components/Layout';

function Section({ emoji, title, children }) {
  return (
    <div className="card" style={{ marginBottom: '1.25rem' }}>
      <h3 style={{ marginBottom: '0.75rem' }}>{emoji} {title}</h3>
      {children}
    </div>
  );
}

function Example({ children }) {
  return (
    <code style={{
      display: 'inline-block', background: '#f1f5f9',
      border: '1px solid #e2e8f0', borderRadius: 4,
      padding: '0.15rem 0.5rem', fontSize: '0.88rem',
      wordBreak: 'break-all', margin: '0.2rem 0.2rem 0.2rem 0',
    }}>{children}</code>
  );
}

export default function Education() {
  return (
    <Layout>
      <Head><title>Security Education — PhishGuard</title></Head>
      <h2 style={{ marginBottom: '0.5rem' }}>📚 Phishing Prevention Guide</h2>
      <p style={{ color: 'var(--color-muted)', marginBottom: '1.5rem', fontSize: '0.9rem' }}>
        Learn to recognize and avoid phishing attacks. Understanding these patterns helps you stay safe online.
      </p>

      <Section emoji="🎣" title="What is URL Phishing?">
        <p style={{ lineHeight: 1.7 }}>Phishing is a social engineering attack where criminals impersonate trusted organizations using deceptive websites. They craft URLs that look legitimate at first glance to steal credentials, financial information, or personal data. The URL is often the most reliable indicator of a fake site — but it requires careful inspection.</p>
      </Section>

      <Section emoji="🔍" title="Common Phishing URL Patterns">
        <p style={{ marginBottom: '0.75rem' }}>Attackers use these techniques to disguise malicious URLs:</p>
        <ul style={{ lineHeight: 2, paddingLeft: '1.5rem' }}>
          <li><strong>Brand names in wrong domain:</strong> <Example>paypal-secure-login.xyz</Example> <Example>apple-id-verify.ru</Example></li>
          <li><strong>Brand as subdomain:</strong> <Example>paypal.attacker.com</Example> — the real domain is <em>attacker.com</em></li>
          <li><strong>Hyphen-separated fake domain:</strong> <Example>secure-amazon-account.tk</Example></li>
          <li><strong>Long paths to confuse:</strong> <Example>attacker.com/www.paypal.com/login</Example></li>
          <li><strong>Misleading TLDs:</strong> <Example>google.com.phishing.net</Example></li>
          <li><strong>Free or newly registered TLDs:</strong> .xyz, .ml, .tk, .ga, .cf are frequently abused</li>
        </ul>
      </Section>

      <Section emoji="🏠" title="Suspicious Subdomains">
        <p>The real domain is always the part just before the TLD. In <Example>login.paypal.account.verify.attacker.com</Example>, the real domain is <strong>attacker.com</strong>, not paypal. Count from the right: TLD, domain, then subdomains.</p>
        <p style={{ marginTop: '0.75rem' }}>Legitimate sites rarely have 3+ subdomain levels for login pages.</p>
      </Section>

      <Section emoji="🔤" title="Homoglyphs and Lookalike Characters">
        <p style={{ marginBottom: '0.5rem' }}>Attackers replace letters with visually similar characters:</p>
        <ul style={{ lineHeight: 2, paddingLeft: '1.5rem' }}>
          <li><Example>paypa1.com</Example> (digit 1 instead of l)</li>
          <li><Example>g00gle.com</Example> (zeros instead of o)</li>
          <li><Example>rn</Example> can look like <Example>m</Example> in some fonts (arnazon.com)</li>
          <li>Unicode lookalikes: Cyrillic а (U+0430) looks like Latin a</li>
        </ul>
        <p style={{ marginTop: '0.5rem' }}>Always copy the URL to a plain-text editor and inspect it carefully.</p>
      </Section>

      <Section emoji="🔗" title="URL Shorteners and Redirects">
        <p>URL shorteners (<Example>bit.ly/abc123</Example>, <Example>t.co/xyz</Example>) hide the real destination. Expand them using a service like <strong>checkshorturl.com</strong> before clicking. Redirects can also chain through legitimate-looking domains before landing on malicious ones.</p>
      </Section>

      <Section emoji="🔒" title="Why HTTPS ≠ Safe">
        <p>HTTPS means the connection is <em>encrypted</em> — it does <strong>not</strong> mean the site is legitimate. Phishing sites routinely use free HTTPS certificates. The padlock only tells you your data is encrypted in transit; it says nothing about where it is going.</p>
      </Section>

      <Section emoji="👁️" title="How to Inspect Links Safely">
        <ul style={{ lineHeight: 2, paddingLeft: '1.5rem' }}>
          <li>Hover over a link — check the status bar (bottom of browser) before clicking</li>
          <li>On mobile, long-press to preview the URL</li>
          <li>Never click links in unexpected emails, texts, or DMs — go directly to the official site</li>
          <li>Use this tool to check suspicious URLs before visiting them</li>
          <li>Enable browser warnings and keep your browser updated</li>
        </ul>
      </Section>

      <Section emoji="🤖" title="What 'Phishing Probability' Means">
        <p>PhishGuard uses an XGBoost machine learning model trained on labeled URL datasets. The probability score (0–100%) indicates how similar the URL is to known phishing patterns, based on features like URL length, subdomain count, and brand keyword presence.</p>
        <p style={{ marginTop: '0.5rem' }}><strong>It is NOT a definitive verdict.</strong> The model can be wrong. Legitimate sites can be flagged (false positives) and new phishing sites may not be detected (false negatives).</p>
      </Section>

      <Section emoji="⚖️" title="False Positives and False Negatives">
        <p><strong>False positive:</strong> A legitimate site is flagged as suspicious. This can happen with newly registered legitimate domains, sites using brand keywords in their own name, or unusual URL structures. If you trust the site, you can add it to your allowlist.</p>
        <p style={{ marginTop: '0.5rem' }}><strong>False negative:</strong> A phishing site is classified as safe. No detection system is perfect. Always apply additional judgment. If something feels off, do not proceed.</p>
      </Section>

      <Section emoji="🚨" title="What to Do If You Clicked a Suspicious Link">
        <ol style={{ lineHeight: 2, paddingLeft: '1.5rem' }}>
          <li>Do not enter any credentials or personal information</li>
          <li>Close the tab immediately</li>
          <li>Clear your browser cookies and cache</li>
          <li>If you entered credentials, change your password immediately on the real site</li>
          <li>If financial information was involved, contact your bank</li>
          <li>Report the phishing site to <strong>phishtank.org</strong> or your browser vendor</li>
          <li>Enable two-factor authentication on all important accounts</li>
        </ol>
      </Section>
    </Layout>
  );
}
