"use client";

import { useEffect, useState } from "react";
import { RiskMeter, ScanModeBadge, FihhMascot } from "../components/Ui";

export default function History() {
  const [items, setItems] = useState([]);
  const [filter, setFilter] = useState("all");
  useEffect(
    () => setItems(JSON.parse(localStorage.getItem("fihh-history") || "[]")),
    [],
  );
  const clear = () => {
    localStorage.removeItem("fihh-history");
    setItems([]);
  };
  const filtered =
    filter === "all"
      ? items
      : items.filter((item) => item.risk_level === filter);
  return (
    <section>
      <div className="section-title">
        <div>
          <span className="eyebrow">your local receipts</span>
          <h1>history</h1>
        </div>
        <button className="btn btn-outline" onClick={clear}>
          clear all
        </button>
      </div>
      <div
        className="filter-row"
        style={{
          display: "flex",
          gap: ".5rem",
          marginBottom: "1rem",
          flexWrap: "wrap",
        }}
      >
        {["all", "safe", "suspicious", "dangerous"].map((option) => (
          <button
            key={option}
            className={`btn ${filter === option ? "btn-primary" : "btn-outline"}`}
            onClick={() => setFilter(option)}
          >
            {option}
          </button>
        ))}
      </div>
      {!filtered.length ? (
        <div className="card empty-state">
          <FihhMascot mood="sleepy" size={90} />
          <h2>no scans here yet</h2>
          <p>your local history stays in this browser.</p>
        </div>
      ) : (
        <div className="stack">
          {filtered.map((item, index) => (
            <article className="card" key={`${item.url}-${index}`}>
              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  gap: "1rem",
                  flexWrap: "wrap",
                }}
              >
                <strong style={{ wordBreak: "break-all" }}>{item.url}</strong>
                <ScanModeBadge mode={item.model_mode} />
              </div>
              <div
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "1rem",
                  marginTop: ".8rem",
                }}
              >
                <span>{item.risk_level}</span>
                <RiskMeter
                  probability={item.phishing_probability}
                  risk={item.risk_level}
                />
              </div>
            </article>
          ))}
        </div>
      )}
    </section>
  );
}
