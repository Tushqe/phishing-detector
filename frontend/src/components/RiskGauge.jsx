import React from "react";
import styles from "./RiskGauge.module.css";

/**
 * SVG semi-circle gauge showing risk score 0-100.
 */
export default function RiskGauge({ score }) {
  const R = 60;
  const strokeW = 12;
  const cx = 90;
  const cy = 80;
  const circumference = Math.PI * R;
  const progress = (score / 100) * circumference;

  const color =
    score >= 70 ? "var(--danger)" : score >= 40 ? "var(--warn)" : "var(--safe)";

  // Arc endpoints: 180° (left) → 0° (right)
  const startX = cx - R;
  const startY = cy;
  const endX = cx + R;
  const endY = cy;

  const arcD = `M ${startX} ${startY} A ${R} ${R} 0 0 1 ${endX} ${endY}`;

  return (
    <div className={styles.wrap}>
      <svg
        width="180"
        height="110"
        viewBox="0 0 180 110"
      >
        {/* Track */}
        <path
          d={arcD}
          fill="none"
          stroke="var(--border)"
          strokeWidth={strokeW}
          strokeLinecap="round"
        />
        {/* Progress */}
        <path
          d={arcD}
          fill="none"
          stroke={color}
          strokeWidth={strokeW}
          strokeLinecap="round"
          strokeDasharray={`${progress} ${circumference}`}
          style={{ transition: "stroke-dasharray 0.5s ease" }}
        />
        {/* Score number */}
        <text
          x={cx}
          y={cy - 16}
          textAnchor="middle"
          fill="var(--text)"
          fontSize="28"
          fontWeight="700"
          fontFamily="var(--mono)"
        >
          {score}
        </text>
        <text
          x={cx}
          y={cy + 2}
          textAnchor="middle"
          fill="var(--muted)"
          fontSize="10"
          fontFamily="var(--font)"
        >
          RISK SCORE
        </text>
        {/* Min/Max labels */}
        <text x={startX} y={cy + 18} textAnchor="middle" fill="var(--muted)" fontSize="9" fontFamily="var(--font)">0</text>
        <text x={endX} y={cy + 18} textAnchor="middle" fill="var(--muted)" fontSize="9" fontFamily="var(--font)">100</text>
      </svg>
    </div>
  );
}
