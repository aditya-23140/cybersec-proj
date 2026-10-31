import RiskBadge from './RiskBadge';
import styles from './ScanResult.module.css';

export default function ScanResult({ result }) {
  if (!result) return null;
  const pct = (result.phishing_probability * 100).toFixed(1);
  return (
    <div className={`card ${styles.result}`}>
      <div className={styles.header}>
        <RiskBadge risk={result.risk_level} />
        <span className={styles.prob}>Phishing probability: <strong>{pct}%</strong></span>
      </div>
      <p className={styles.url} title={result.url}>
        <span className={styles.urlLabel}>URL:</span> {result.url}
      </p>
      <p className={styles.explanation}>{result.explanation}</p>
      {result.warnings && result.warnings.length > 0 && (
        <ul className={styles.warnings}>
          {result.warnings.map((w, i) => <li key={i}>{w}</li>)}
        </ul>
      )}
      <p className={styles.meta}>Model version: {result.model_version}</p>
      <p className={styles.disclaimer}>
        ⚠ This is a probabilistic estimate based on URL structure only. It may be incorrect. Always verify links through official channels.
      </p>
    </div>
  );
}
