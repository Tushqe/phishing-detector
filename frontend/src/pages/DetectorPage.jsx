import React, { useState, useRef } from "react";
import RiskGauge from "../components/RiskGauge";
import FeatureList from "../components/FeatureList";
import styles from "./DetectorPage.module.css";

const EXAMPLES = [
  "https://paypal.com/signin",
  "http://paypal-secure.tk/login?redirect=http://evil.com",
  "http://192.168.1.1/verify/account",
  "https://github.com/anthropics/claude-code",
  "http://amaz0n.account-verify.ml/confirm?user=you&token=abc123",
];

export default function DetectorPage() {
  const [url, setUrl] = useState("");
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const inputRef = useRef(null);

  async function handleSubmit(e) {
    e.preventDefault();
    const trimmed = url.trim();
    if (!trimmed) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const res = await fetch("/api/predict", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: trimmed }),
      });
      if (!res.ok) {
        const data = await res.json();
        throw new Error(data.detail || `HTTP ${res.status}`);
      }
      setResult(await res.json());
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  }

  function loadExample(ex) {
    setUrl(ex);
    setResult(null);
    setError(null);
    inputRef.current?.focus();
  }

  const verdict = result?.label;
  const verdictClass =
    verdict === "phishing"
      ? styles.phishing
      : verdict === "legitimate"
      ? styles.legitimate
      : "";

  return (
    <div className={styles.page}>
      <section className={styles.hero}>
        <h1 className={styles.title}>URL Risk Analyser</h1>
        <p className={styles.subtitle}>
          Paste any URL to scan it against our ML-powered phishing detection model.
          Results include a risk score, probability estimate, and a breakdown of
          suspicious signals.
        </p>
      </section>

      <form className={styles.form} onSubmit={handleSubmit}>
        <div className={styles.inputRow}>
          <input
            ref={inputRef}
            className={styles.input}
            type="text"
            placeholder="https://example.com/login?token=…"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            spellCheck={false}
            autoComplete="off"
          />
          <button className={styles.btn} type="submit" disabled={loading || !url.trim()}>
            {loading ? "Scanning…" : "Scan URL"}
          </button>
        </div>
        <div className={styles.examples}>
          <span className={styles.exLabel}>Try:</span>
          {EXAMPLES.map((ex) => (
            <button
              key={ex}
              type="button"
              className={styles.exBtn}
              onClick={() => loadExample(ex)}
            >
              {ex.length > 50 ? ex.slice(0, 50) + "…" : ex}
            </button>
          ))}
        </div>
      </form>

      {error && (
        <div className={styles.errorBox}>
          <strong>Error:</strong> {error}
        </div>
      )}

      {result && (
        <div className={`${styles.results} ${verdictClass}`}>
          <div className={styles.gaugePanel}>
            <RiskGauge score={result.risk_score} label={result.label} />
            <div className={styles.prob}>
              <span className={styles.probVal}>
                {(result.probability * 100).toFixed(1)}%
              </span>
              <span className={styles.probLabel}>phishing probability</span>
            </div>
            <div className={`${styles.verdict} ${verdictClass}`}>
              {result.label === "phishing" ? "⚠ PHISHING" : "✓ LEGITIMATE"}
            </div>
          </div>

          <div className={styles.detailPanel}>
            <div className={styles.urlDisplay}>
              <span className={styles.urlLabel}>Analysed URL</span>
              <code className={styles.urlVal}>{result.url}</code>
            </div>

            {result.suspicious_features.length > 0 ? (
              <FeatureList features={result.suspicious_features} />
            ) : (
              <p className={styles.noFindings}>
                No suspicious features detected. This URL appears clean.
              </p>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
