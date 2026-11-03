"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import {
  addAllowlist,
  addBlocklist,
  deleteAllowlist,
  deleteBlocklist,
  getAllowlist,
  getBlocklist,
} from "../../lib/api";

function ListCard({ title, items, onAdd, onDelete, placeholder }) {
  const [domain, setDomain] = useState("");
  const [notes, setNotes] = useState("");
  const submit = async (event) => {
    event.preventDefault();
    if (!domain.trim()) return;
    await onAdd(domain.trim(), notes.trim() || null);
    setDomain("");
    setNotes("");
  };
  return (
    <div className="card">
      <h2>{title}</h2>
      <form className="url-row" onSubmit={submit}>
        <input
          value={domain}
          onChange={(e) => setDomain(e.target.value)}
          placeholder={placeholder}
        />
        <input
          value={notes}
          onChange={(e) => setNotes(e.target.value)}
          placeholder="note (optional)"
        />
        <button className="btn btn-primary">add</button>
      </form>
      <div className="stack" style={{ marginTop: "1rem" }}>
        {items.map((item) => (
          <div
            key={item.id}
            style={{
              display: "flex",
              justifyContent: "space-between",
              gap: "1rem",
              borderBottom: "2px solid var(--line)",
              padding: ".6rem 0",
            }}
          >
            <span>
              <strong>{item.domain}</strong>
              <br />
              <small className="muted">{item.notes || "no note"}</small>
            </span>
            <button
              className="btn btn-danger"
              onClick={() => onDelete(item.id)}
            >
              remove
            </button>
          </div>
        ))}
      </div>
    </div>
  );
}

export default function Lists() {
  const router = useRouter();
  const [allow, setAllow] = useState([]);
  const [block, setBlock] = useState([]);
  useEffect(() => {
    if (!localStorage.getItem("token")) router.push("/login");
    Promise.all([getAllowlist(), getBlocklist()]).then(([a, b]) => {
      setAllow(a.data.items);
      setBlock(b.data.items);
    });
  }, [router]);
  return (
    <section>
      <div className="section-title">
        <div>
          <span className="eyebrow">your rules</span>
          <h1>lists</h1>
        </div>
      </div>
      <div className="stack">
        <ListCard
          title="allow list"
          items={allow}
          placeholder="trusted-site.com"
          onAdd={async (d, n) => {
            await addAllowlist(d, n);
            setAllow((await getAllowlist()).data.items);
          }}
          onDelete={async (id) => {
            await deleteAllowlist(id);
            setAllow(allow.filter((i) => i.id !== id));
          }}
        />
        <ListCard
          title="block list"
          items={block}
          placeholder="definitely-not-a-scam.xyz"
          onAdd={async (d, n) => {
            await addBlocklist(d, n);
            setBlock((await getBlocklist()).data.items);
          }}
          onDelete={async (id) => {
            await deleteBlocklist(id);
            setBlock(block.filter((i) => i.id !== id));
          }}
        />
      </div>
    </section>
  );
}
