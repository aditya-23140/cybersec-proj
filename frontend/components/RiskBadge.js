export default function RiskBadge({ risk }) {
  const map = {
    safe: { label: '✓ Safe', cls: 'risk-safe' },
    suspicious: { label: '⚠ Suspicious', cls: 'risk-suspicious' },
    dangerous: { label: '✕ Dangerous', cls: 'risk-dangerous' },
    unknown: { label: '? Unknown', cls: 'risk-unknown' },
  };
  const { label, cls } = map[risk] || map.unknown;
  return <span className={`risk-badge ${cls}`}>{label}</span>;
}
