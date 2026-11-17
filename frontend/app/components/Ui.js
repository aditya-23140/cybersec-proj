"use client";

import { useState } from "react";

const moods = ["chill", "sidee", "alarmed", "sleepy", "unknown"];

export function FihhMascot({ mood = "chill", size = 64 }) {
  const expression = moods.includes(mood) ? mood : "unknown";
  return (
    <svg
      className="fihh"
      width={size}
      height={size}
      viewBox="0 0 64 64"
      fill="none"
      role="img"
      aria-label={`Fihh the fish, ${expression}`}
    >
      <path
        d="M44 32 60 20q-2 12 0 24Z"
        fill="var(--accent)"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinejoin="round"
      />
      <ellipse
        cx="28"
        cy="32"
        rx="19"
        ry="14"
        fill="var(--accent)"
        stroke="currentColor"
        strokeWidth="2"
      />
      <path
        d="M26 38q4 10 12 6-4-4-6-8Z"
        fill="var(--accent)"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinejoin="round"
      />
      {expression === "sleepy" ? (
        <path
          d="M14 29q3 3 6 0"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
        />
      ) : (
        <>
          <circle
            cx="17"
            cy="29"
            r={expression === "alarmed" ? 4 : 3}
            fill="currentColor"
          />
          <circle
            cx={expression === "sidee" ? 15.8 : 16}
            cy="28"
            r="1"
            fill="#FFFFFF"
          />
        </>
      )}
      {expression === "sidee" && (
        <path
          d="M12 24 21 25"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
        />
      )}
      {expression === "chill" && (
        <path
          d="M10 36q3 2 6 0"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
        />
      )}
      {expression === "sidee" && (
        <path
          d="M10 36h5"
          stroke="currentColor"
          strokeWidth="2"
          strokeLinecap="round"
        />
      )}
      {expression === "alarmed" && (
        <>
          <circle
            cx="12"
            cy="36"
            r="1.8"
            stroke="currentColor"
            strokeWidth="1.6"
          />
          <path
            d="m8 22-2-3m6 2v-4"
            stroke="currentColor"
            strokeWidth="1.5"
            strokeLinecap="round"
          />
        </>
      )}
      {expression === "sleepy" && (
        <path
          d="M11 38h4M22 22h4l-4 4h4"
          stroke="currentColor"
          strokeWidth="1.5"
          strokeLinecap="round"
          strokeLinejoin="round"
        />
      )}
      {expression === "unknown" && (
        <>
          <path
            d="M10 36h5"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
          />
          <path
            d="M22 24q0-4 3-4t3 2q0 2-3 3v1"
            stroke="currentColor"
            strokeWidth="1.5"
            strokeLinecap="round"
          />
          <circle cx="25" cy="29" r=".7" fill="currentColor" />
        </>
      )}
    </svg>
  );
}

export function RiskMeter({ probability = 0, risk = "unknown" }) {
  const value = Math.max(
    0,
    Math.min(100, Math.round(Number(probability) * 100)),
  );
  return (
    <div className="meter-wrap" aria-label={`Phishing probability ${value}%`}>
      <div className="meter-track">
        <span className={`meter-fill ${risk}`} style={{ width: `${value}%` }} />
      </div>
      <strong>{value}%</strong>
    </div>
  );
}

const reasonText = {
  // Legacy mappings for backwards compatibility
  c_form_action_external: "the login form sends your data to a different website",
  c_has_password: "the page asks for a password",
  c_claimed_brand_mismatch: "the page claims a brand that does not match its domain",
  t_lookalike_dist: "the domain looks very close to a popular brand",
  t_brand_in_domain: "a brand name appears in an unrelated domain",
  subdomain_len: "the domain has an unusually long subdomain",
  dots_host: "the hostname has several nested sections",
  suspicious_path_keyword: "the URL path uses language common in scam pages",
  // FihhGuard v2 Schema Feature mappings
  url_length: "the URL is unusually long",
  hostname_length: "the hostname is unusually long",
  path_length: "the URL path is unusually deep or long",
  query_length: "the URL query string is unusually long",
  url_entropy: "the URL has high character randomness",
  hostname_entropy: "the hostname has high character randomness",
  subdomain_depth: "the domain has an unusually high number of subdomains",
  tld_risk_score: "the top-level domain is associated with elevated phishing risk",
  has_ip_host: "the URL uses a raw numeric IP address instead of a domain name",
  has_userinfo: "the URL embeds credentials (@ in host), a deceptive tactic",
  has_punycode: "the hostname uses Punycode encoding, possible homograph attack",
  idn_homograph_score: "the domain uses characters visually mimicking another brand",
  shortener_flag: "the URL uses a known link-shortening service",
  shared_hosting_flag: "the site is hosted on a free or shared hosting platform",
  qty_dots_url: "the URL contains an unusual number of dots",
  qty_hyphens_url: "the URL contains multiple hyphens",
  brand_edit_distance_min: "the domain closely resembles a known brand name",
  brand_homoglyph_score: "the domain uses lookalike characters to mimic a brand",
  brand_keyword_in_subdomain: "a well-known brand name is embedded in an unrelated subdomain",
  brand_keyword_in_path: "a well-known brand name appears inside the URL path",
  page_claimed_brand_mismatch: "the page claims to be a brand that does not match its domain",
  has_password_field: "the page contains a credential or password input field",
  has_card_field: "the page asks for credit card or payment details",
  has_otp_field: "the page asks for a two-factor one-time passcode (OTP)",
  form_action_cross_domain: "the login form submits credentials to a different website",
  null_action_form: "the form has no destination, a common data harvesting pattern",
  hidden_iframe_count: "the page embeds hidden iframes",
  js_obfuscation_score: "JavaScript code on the page is obfuscated",
  right_click_disabled: "right-click is disabled to prevent security inspection",
  meta_refresh_present: "the page forces a silent meta-refresh redirect",
  urgency_keyword_score: "the page uses urgent or threatening language to trick users",
  redirect_count: "the link redirects multiple times through a redirect chain",
  external_css_ratio: "the page references external third-party styling",
  external_script_ratio: "the page loads scripts from third-party websites",
  external_link_ratio: "links on the page predominantly lead outside the site",
  text_to_html_ratio: "the page has very little text relative to code (cloned template pattern)",
  login_form_on_unknown_domain: "a login form is hosted on an unverified or untrusted domain",
  title_domain_overlap: "the page title does not match the domain identity",
};

export function ReasonList({ reasons = [], limit = 4 }) {
  const items = (Array.isArray(reasons) ? reasons : []).slice(0, limit);
  if (!items.length)
    return <p className="muted">no single signal did all the talking.</p>;
  return (
    <ul className="reason-list">
      {items.map((reason, index) => {
        let text = "";
        let key = index;
        if (typeof reason === "string") {
          text = reason;
          key = `str-${index}-${reason.slice(0, 15)}`;
        } else if (reason && typeof reason === "object") {
          const feat = reason.feature || reason.name || "";
          key = `${feat || "item"}-${index}`;
          text =
            reason.reason ||
            reason.description ||
            (feat && reasonText[feat]) ||
            (feat
              ? `the URL has a ${String(feat).replaceAll("_", " ")} signal`
              : "anomalous pattern detected by security model");
        } else {
          text = String(reason);
          key = `val-${index}`;
        }
        return (
          <li key={key}>
            <span aria-hidden="true">→</span>
            {text}
          </li>
        );
      })}
    </ul>
  );
}

export function ScanModeBadge({ mode }) {
  const isHybrid =
    mode === "url+content" ||
    mode === "full" ||
    mode === "hybrid" ||
    mode === "url-hybrid";
  return (
    <span
      className="mode-badge"
      title={
        isHybrid
          ? "URL pattern plus analyzed page structure and HTML content."
          : "URL pattern only; page content was not available."
      }
    >
      {isHybrid ? "full page scan ✓" : "link-only scan"}
    </span>
  );
}

export function VerdictCard({ result, loading = false }) {
  if (loading)
    return (
      <section className="verdict-card loading-card" aria-live="polite">
        <FihhMascot mood="sleepy" />
        <div>
          <h2>sniffing around the page...</h2>
          <p className="muted">one sec. fihh is checking the vibes.</p>
        </div>
      </section>
    );
  if (!result) return null;
  const risk = result.risk_level || "unknown";
  const mood =
    risk === "safe"
      ? "chill"
      : risk === "suspicious"
        ? "sidee"
        : risk === "dangerous"
          ? "alarmed"
          : "unknown";
  const verdict = risk === "dangerous" ? "phishing" : risk;
  const message =
    risk === "safe"
      ? "looks clean. go forth and scroll."
      : risk === "suspicious"
        ? "hmm, this one's giving sketchy."
        : risk === "dangerous"
          ? "nope. this site is fishing for your info."
          : "couldn't read this link. don't trust it blindly.";
  return (
    <section className={`verdict-card ${risk}`} aria-live="polite">
      <div className="verdict-top">
        <FihhMascot mood={mood} size={104} />
        <div>
          <span className="eyebrow">fihh says</span>
          <h2>{verdict}</h2>
          <p>{message}</p>
        </div>
      </div>
      <div className="verdict-meta">
        <ScanModeBadge
          mode={result.model_mode || result.evidence_summary?.model_mode}
        />
        <RiskMeter probability={result.phishing_probability} risk={risk} />
      </div>
      {result.fetch_error && (
        <p className="plain-reason">link-only scan: {result.fetch_error}</p>
      )}
      <div className="why">
        <h3>why we think so</h3>
        <ReasonList
          reasons={
            result.evidence_summary?.hybrid_reasons || result.reasons || []
          }
        />
      </div>
      {result.explanation && (
        <p className="plain-reason">{result.explanation}</p>
      )}
    </section>
  );
}

export function UrlInput({ onScan, initialValue = "", compact = false }) {
  const [value, setValue] = useState(initialValue);
  const [error, setError] = useState("");
  const submit = (event) => {
    event.preventDefault();
    try {
      const parsed = new URL(value.trim());
      if (!["http:", "https:"].includes(parsed.protocol)) throw new Error();
    } catch {
      setError("drop in a full http:// or https:// link.");
      return;
    }
    setError("");
    onScan(value.trim());
  };
  return (
    <form className={`url-form ${compact ? "compact" : ""}`} onSubmit={submit}>
      <label htmlFor="scan-url">paste a link. fihh will take a look.</label>
      <div className="url-row">
        <input
          id="scan-url"
          value={value}
          onChange={(event) => setValue(event.target.value)}
          placeholder="https://somewhere.com/login"
          aria-invalid={Boolean(error)}
        />
        <button className="btn btn-primary surface-accent" type="submit">
          scan it
        </button>
      </div>
      {error && (
        <span className="field-error" role="alert">
          {error}
        </span>
      )}
    </form>
  );
}
