import React from "react";
import styles from "./FeatureList.module.css";

const SEVERITY_COLOR = {
  critical: "var(--danger)",
  high:     "#e05c30",
  medium:   "var(--warn)",
  low:      "var(--muted)",
};

const SEVERITY_BG = {
  critical: "var(--danger-bg)",
  high:     "#1f1108",
  medium:   "var(--warn-bg)",
  low:      "rgba(255,255,255,0.03)",
};

export default function FeatureList({ features }) {
  return (
    <div>
      <h3 className={styles.heading}>
        Suspicious Signals <span className={styles.count}>({features.length})</span>
      </h3>
      <ul className={styles.list}>
        {features.map((f, i) => (
          <li
            key={i}
            className={styles.item}
            style={{
              borderLeftColor: SEVERITY_COLOR[f.severity] || "var(--muted)",
              background: SEVERITY_BG[f.severity] || "transparent",
            }}
          >
            <div className={styles.row}>
              <span className={styles.label}>{f.label}</span>
              <span
                className={styles.badge}
                style={{ color: SEVERITY_COLOR[f.severity] }}
              >
                {f.severity}
              </span>
            </div>
            <p className={styles.desc}>{f.description}</p>
          </li>
        ))}
      </ul>
    </div>
  );
}
