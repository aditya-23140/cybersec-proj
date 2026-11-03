"use client";

import { useEffect, useState } from "react";
import { getModelInfo, getStats } from "../../lib/api";

export default function Dashboard() {
  const [stats, setStats] = useState(null);
  const [model, setModel] = useState(null);
  const [error, setError] = useState("");
  useEffect(() => {
    Promise.all([getStats(), getModelInfo()])
      .then(([s, m]) => {
        setStats(s.data);
        setModel(m.data);
      })
      .catch(() => setError("could not load dashboard data."));
  }, []);
  if (error) return <div className="error-box">{error}</div>;
  if (!stats)
    return (
      <div className="loading-card card">
        <span className="spinner" /> loading the numbers...
      </div>
    );
  const cards = [
    ["all scans", stats.total_scans],
    ["safe", stats.safe_count],
    ["suspicious", stats.suspicious_count],
    ["dangerous", stats.dangerous_count],
  ];
  return (
    <section>
      <div className="section-title">
        <div>
          <span className="eyebrow">the receipts</span>
          <h1>dashboard</h1>
        </div>
        <span className="muted">real scans only. no fake demo stats.</span>
      </div>
      <div className="stats-grid">
        {cards.map(([label, value]) => (
          <div className="card stat-card" key={label}>
            <strong>{value}</strong>
            <span>{label}</span>
          </div>
        ))}
      </div>
      <div className="card" style={{ marginTop: "1.5rem" }}>
        <span className="eyebrow">under the hood</span>
        <h2>model status</h2>
        <p>
          version: <strong>{model?.model_version || "unknown"}</strong>
        </p>
        <p>
          mode: <strong>{model?.model_kind || "unknown"}</strong>
        </p>
        <p className="muted">
          the model is a signal, not a crystal ball. use your judgment too.
        </p>
      </div>
    </section>
  );
}
