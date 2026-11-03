import Link from "next/link";

export default function Education() {
  return (
    <article className="prose">
      <span className="eyebrow">the honest bit</span>
      <h1>how it works</h1>
      <p>
        fihhguard looks for patterns that show up in phishing links: lookalike
        domains, strange subdomains, sketchy paths, and pages that ask for
        secrets while sending them somewhere unexpected.
      </p>
      <h2>what the scan means</h2>
      <p>
        <strong>safe</strong> means the signals look ordinary.{" "}
        <strong>suspicious</strong> means something deserves a closer look.{" "}
        <strong>phishing</strong> means multiple high-risk signals showed up.
        None of these replace checking the address yourself.
      </p>
      <h2>what we do not promise</h2>
      <p>
        no detector is perfect, so stay sharp. A brand-new scam can slip
        through, and a weird-looking legitimate URL can get flagged. Never enter
        a password because a site “looks right”.
      </p>
      <h2>need the browser buddy?</h2>
      <p>
        The extension can check clicked links and, when available, sanitized
        page structure.
      </p>
      <Link className="btn btn-primary" href="/">
        check a link →
      </Link>
    </article>
  );
}
