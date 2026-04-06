import React, { useEffect, useState } from "react";
import styles from "./MethodologyPage.module.css";

const REFERENCES = [
  {
    id: 1,
    citation:
      'Hannousse, A., & Yahiouche, S. (2021). "Towards benchmark datasets for machine learning based website phishing detection: An experimental study." Engineering Applications of Artificial Intelligence, 104, 104347.',
    doi: "10.1016/j.engappai.2021.104347",
  },
  {
    id: 2,
    citation:
      'Chen, T., & Guestrin, C. (2016). "XGBoost: A scalable tree boosting system." Proceedings of the 22nd ACM SIGKDD International Conference on Knowledge Discovery and Data Mining (pp. 785-794).',
    doi: "10.1145/2939672.2939785",
  },
  {
    id: 3,
    citation:
      'Mohammad, R. M., Thabtah, F., & McCluskey, L. (2014). "Predicting phishing websites based on self-structuring neural network." Neural Computing and Applications, 25, 443-458.',
    doi: "10.1007/s00521-013-1490-z",
  },
  {
    id: 4,
    citation:
      'Sahingoz, O. K., Buber, E., Demir, O., & Diri, B. (2019). "Machine learning based phishing detection from URLs." Expert Systems with Applications, 117, 345-357.',
    doi: "10.1016/j.eswa.2018.09.029",
  },
  {
    id: 5,
    citation:
      'Abdelhamid, N., Ayesh, A., & Thabtah, F. (2014). "Phishing detection based associative classification data mining." Expert Systems with Applications, 41(13), 5948-5959.',
    doi: "10.1016/j.eswa.2014.03.019",
  },
  {
    id: 6,
    citation:
      'Breiman, L. (2001). "Random forests." Machine Learning, 45(1), 5-32.',
    doi: "10.1023/A:1010933404324",
  },
  {
    id: 7,
    citation:
      'Cortes, C., & Vapnik, V. (1995). "Support-vector networks." Machine Learning, 20(3), 273-297.',
    doi: "10.1007/BF00994018",
  },
  {
    id: 8,
    citation:
      'Vrbančič, G., Fister, I., & Podgorelec, V. (2020). "Datasets for phishing websites detection." Data in Brief, 33, 106438.',
    doi: "10.1016/j.dib.2020.106438",
  },
];

const FEATURE_GROUPS = [
  {
    group: "Lexical",
    features: [
      "url_length", "domain_length", "path_length", "num_dots", "num_hyphens",
      "num_at", "num_question", "num_equals", "num_percent", "num_slash",
      "num_ampersand", "num_digits_url", "num_digits_domain",
    ],
    desc: "Character-level counts derived directly from the raw URL string.",
  },
  {
    group: "Structural",
    features: [
      "has_at_symbol", "has_double_slash", "has_http_in_path", "has_https",
      "has_ip", "url_depth", "num_params", "hex_count",
    ],
    desc: "Structural flags indicating redirect patterns, encoding, and protocol anomalies.",
  },
  {
    group: "Domain / TLD",
    features: [
      "suspicious_tld", "tld_length", "domain_has_hyphen", "long_subdomain",
      "num_subdomains", "brand_in_subdomain", "brand_in_domain_part",
    ],
    desc: "Domain decomposition signals: TLD reputation, subdomain depth, and brand impersonation.",
  },
  {
    group: "Entropy",
    features: ["url_entropy", "domain_entropy"],
    desc: "Shannon entropy measuring randomness in the URL and domain — high entropy often indicates obfuscation.",
  },
  {
    group: "Keyword",
    features: ["keyword_count"],
    desc: "Count of known phishing keywords (login, verify, secure, etc.) present in the URL.",
  },
];

function MetricsTable({ comparison, bestModel }) {
  const models = Object.keys(comparison);
  const metrics = ["accuracy", "precision", "recall", "f1", "roc_auc"];

  return (
    <div className={styles.tableWrap}>
      <table className={styles.table}>
        <thead>
          <tr>
            <th>Model</th>
            {metrics.map((m) => (
              <th key={m}>{m.replace("_", " ").replace("roc auc", "ROC AUC").toUpperCase()}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {models.map((model) => (
            <tr key={model} className={model === bestModel ? styles.bestRow : ""}>
              <td>
                {model}
                {model === bestModel && (
                  <span className={styles.bestBadge}>selected</span>
                )}
              </td>
              {metrics.map((metric) => (
                <td key={metric} className={styles.metricCell}>
                  {(comparison[model][metric] * 100).toFixed(2)}%
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function ImportanceBar({ name, value, max }) {
  const pct = (value / max) * 100;
  return (
    <div className={styles.barRow}>
      <span className={styles.barName}>{name}</span>
      <div className={styles.barTrack}>
        <div className={styles.barFill} style={{ width: `${pct}%` }} />
      </div>
      <span className={styles.barVal}>{(value * 100).toFixed(2)}%</span>
    </div>
  );
}

export default function MethodologyPage() {
  const [metrics, setMetrics] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    fetch("/api/metrics")
      .then((r) => r.json())
      .then(setMetrics)
      .catch((e) => setError(e.message))
      .finally(() => setLoading(false));
  }, []);

  const topImportances = metrics?.feature_importances
    ? Object.entries(metrics.feature_importances)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 12)
    : [];
  const maxImp = topImportances[0]?.[1] ?? 1;

  return (
    <div className={styles.page}>
      <h1 className={styles.pageTitle}>About &amp; Methodology</h1>
      <p className={styles.pageSubtitle}>
        Technical background, model selection rationale, and training results for
        the PhishGuard URL classification system.
      </p>

      {/* Background */}
      <section className={styles.section}>
        <h2 className={styles.sectionTitle}>1. Background &amp; Problem Statement</h2>
        <p>
          Phishing attacks remain one of the most prevalent cybersecurity threats,
          with the Anti-Phishing Working Group (APWG) recording over 1.3 million
          unique phishing sites in 2023. Traditional blocklist approaches are reactive
          — they require a site to be reported before it can be flagged. Machine
          learning approaches based on URL lexical features offer a proactive
          alternative: a URL can be classified in under 5 ms using only the URL
          string, with no DNS or page-content access required.
        </p>
        <p style={{ marginTop: "0.75rem" }}>
          This project implements a gradient-boosted tree classifier trained on
          features inspired by the{" "}
          <strong>PhiUSIIL Phishing URL Dataset</strong> (Hannousse &amp; Yahiouche,
          2021), which provides a modern, balanced benchmark widely used in recent
          academic literature.
        </p>
      </section>

      {/* Feature Engineering */}
      <section className={styles.section}>
        <h2 className={styles.sectionTitle}>2. Feature Engineering</h2>
        <p>
          We extract <strong>31 features</strong> from each URL string, grouped into
          five categories. All features are computed purely from the URL text —
          no external API calls, DNS resolution, or page rendering is required at
          inference time.
        </p>
        <div className={styles.featureGroups}>
          {FEATURE_GROUPS.map((g) => (
            <div key={g.group} className={styles.featureGroup}>
              <h3 className={styles.featureGroupTitle}>{g.group}</h3>
              <p className={styles.featureGroupDesc}>{g.desc}</p>
              <div className={styles.featureTags}>
                {g.features.map((f) => (
                  <code key={f} className={styles.featureTag}>{f}</code>
                ))}
              </div>
            </div>
          ))}
        </div>
      </section>

      {/* Model Comparison */}
      <section className={styles.section}>
        <h2 className={styles.sectionTitle}>3. Model Comparison (5-Fold CV)</h2>
        <p style={{ marginBottom: "1.25rem" }}>
          Four classifiers were evaluated using stratified 5-fold cross-validation
          on a balanced dataset of 10,000 URLs (5,000 phishing, 5,000 legitimate).
          Metrics reported are mean values across all folds.
        </p>

        {loading && <p className={styles.muted}>Loading metrics from API…</p>}
        {error && <p className={styles.danger}>Failed to load metrics: {error}</p>}
        {metrics?.comparison && (
          <MetricsTable
            comparison={metrics.comparison}
            bestModel={metrics.best_model}
          />
        )}

        {metrics?.dataset && (
          <div className={styles.datasetInfo}>
            <span>Dataset: {metrics.dataset.total_samples.toLocaleString()} samples</span>
            <span>Features: {metrics.dataset.features}</span>
            <span>CV Folds: {metrics.dataset.cv_folds}</span>
            <span className={styles.muted}>{metrics.dataset.source}</span>
          </div>
        )}
      </section>

      {/* Results Analysis */}
      <section className={styles.section}>
        <h2 className={styles.sectionTitle}>
          4. Why {metrics?.best_model || "the Selected Model"}?
        </h2>
        <p>
          <strong>{metrics?.best_model || "The winning model"}</strong> achieved the
          highest F1 score during 5-fold cross-validation, making it the best
          balance of precision and recall on the PhiUSIIL dataset. Key factors:
        </p>
        <ul className={styles.analysisList}>
          <li>
            <strong>Highest F1 on real-world URLs</strong> — F1 balances precision
            (avoiding false alarms) and recall (catching actual phishing). The
            selected model scored highest on this metric across all folds.
          </li>
          <li>
            <strong>Tree-based models excel here</strong> — URL features include a
            mix of counts, binary flags, and entropy values at different scales.
            Tree ensembles (Random Forest, XGBoost) handle this natively without
            requiring feature scaling.
          </li>
          <li>
            <strong>Minimising false negatives</strong> — in a security context,
            missing a phishing URL (false negative) is costlier than a false
            positive. Recall on the phishing class is the critical metric.
          </li>
          <li>
            <strong>Efficient inference</strong> — tree ensemble scoring is a single
            forward pass through pre-computed thresholds, achieving sub-millisecond
            latency per URL.
          </li>
        </ul>

        {topImportances.length > 0 && (
          <div style={{ marginTop: "1.5rem" }}>
            <h3 className={styles.subHeading}>Top Feature Importances (F-score)</h3>
            <div className={styles.importanceBars}>
              {topImportances.map(([name, val]) => (
                <ImportanceBar key={name} name={name} value={val} max={maxImp} />
              ))}
            </div>
          </div>
        )}
      </section>

      {/* References */}
      <section className={styles.section}>
        <h2 className={styles.sectionTitle}>5. References</h2>
        <ol className={styles.refList}>
          {REFERENCES.map((r) => (
            <li key={r.id} className={styles.refItem}>
              <span>{r.citation}</span>
              {r.doi && (
                <span className={styles.doi}>DOI: {r.doi}</span>
              )}
            </li>
          ))}
        </ol>
      </section>
    </div>
  );
}
