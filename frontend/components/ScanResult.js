import RiskBadge from './RiskBadge';
import styles from './ScanResult.module.css';

export default function ScanResult({ result }) {
  if (!result) return null;
  const pct = (result.phishing_probability * 100).toFixed(1);
  const network = result.network_signals;
  const dns = network?.dns;
  const whois = network?.whois;
  const tls = network?.tls;
  const reputation = network?.reputation;
  const http = network?.http;
  return (
    <div className={`card ${styles.result}`}>
      <div className={styles.header}>
        <RiskBadge risk={result.risk_level} />
        <span className={styles.prob}>Final assessment: <strong>{result.risk_level}</strong></span>
      </div>
      <p className={styles.url} title={result.url}>
        <span className={styles.urlLabel}>URL:</span> {result.url}
      </p>
      <p className={styles.explanation}>{result.explanation}</p>
      {result.verification_status && result.verification_status !== 'verified' && (
        <p className={styles.meta}>
          Verification: {result.verification_status === 'partial'
            ? 'domain and connection verified; page content unavailable'
            : result.verification_status}
        </p>
      )}
      {result.calibrated_url_model_score != null && (
        <p className={styles.meta}>
          URL pattern risk: {(result.calibrated_url_model_score * 100).toFixed(1)}%
          {' '} (supporting signal only)
        </p>
      )}
      {result.warnings && result.warnings.length > 0 && (
        <ul className={styles.warnings}>
          {result.warnings.map((w, i) => <li key={i}>{w}</li>)}
        </ul>
      )}
      {network?.enrichment_enabled && (
        <div className={styles.enrichment}>
          <strong>Live checks</strong>
          <ul>
            {dns && <li>DNS: {dns.dns_resolves ? 'resolved' : 'not resolved'}; {dns.nameserver_count ?? 'unknown'} nameservers; MX {dns.has_mx ? 'found' : 'not found'}</li>}
            {whois && <li>WHOIS: {whois.domain_age_days == null ? (whois.lookup_status === 'timeout' ? 'lookup timed out' : 'domain age unavailable') : `${whois.domain_age_days} days old`}</li>}
            {tls && <li>TLS: {tls.certificate_checked ? (tls.certificate_valid ? `valid${tls.certificate_days_remaining == null ? '' : `, ${tls.certificate_days_remaining} days remaining`}` : 'invalid or hostname mismatch') : (tls.lookup_status === 'timeout' ? 'check timed out' : 'check unavailable')}</li>}
            {reputation && <li>Reputation: {reputation.reputation_provider ? (reputation.reputation_hit ? `reported by ${reputation.reputation_provider}` : reputation.lookup_status === 'ok' ? `no match from ${reputation.reputation_provider}` : 'lookup unavailable') : 'external lookup disabled'}</li>}
            {http && <li>HTTP: {http.request_status === 'ok' ? `${http.http_status}; ${http.redirect_count} redirect(s); ${http.cross_domain_redirect ? 'cross-domain redirect' : 'no cross-domain redirect'}; ${http.has_password_field ? 'password field found' : 'no password field'}` : http.request_status === 'timeout' ? 'page fetch timed out' : 'page fetch unavailable'}</li>}
          </ul>
        </div>
      )}
      <p className={styles.meta}>Model version: {result.model_version}</p>
      {result.source && <p className={styles.meta}>Assessment source: {result.source}</p>}
      <p className={styles.disclaimer}>
        ⚠ This is a probabilistic estimate based on URL and available page-structure signals. It may be incorrect. Always verify links through official channels.
      </p>
    </div>
  );
}
