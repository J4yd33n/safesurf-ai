import { useState, useEffect } from "react";
import { type RiskLevel } from "@/lib/phishing-analyzer";

interface RiskGaugeProps {
  score: number;
  level: RiskLevel;
  animating?: boolean;
}

export function RiskGauge({ score, level, animating }: RiskGaugeProps) {
  const [displayScore, setDisplayScore] = useState(0);

  useEffect(() => {
    if (animating) {
      setDisplayScore(0);
      return;
    }
    let current = 0;
    const target = score;
    const step = target / 40;
    const interval = setInterval(() => {
      current += step;
      if (current >= target) {
        current = target;
        clearInterval(interval);
      }
      setDisplayScore(Math.round(current));
    }, 20);
    return () => clearInterval(interval);
  }, [score, animating]);

  const radius = 80;
  const circumference = Math.PI * radius;
  const offset = circumference - (displayScore / 100) * circumference;

  const colorClass =
    level === "dangerous"
      ? "text-destructive"
      : level === "suspicious"
      ? "text-warning"
      : "text-safe";

  const glowClass =
    level === "dangerous"
      ? "glow-danger"
      : level === "suspicious"
      ? "glow-warning"
      : "glow-safe";

  return (
    <div className={`relative flex flex-col items-center gap-3 ${glowClass} rounded-full p-1`}>
      <svg width="200" height="120" viewBox="0 0 200 120" className="drop-shadow-lg">
        {/* Background arc */}
        <path
          d="M 10 110 A 80 80 0 0 1 190 110"
          fill="none"
          stroke="hsl(var(--muted))"
          strokeWidth="12"
          strokeLinecap="round"
        />
        {/* Score arc */}
        <path
          d="M 10 110 A 80 80 0 0 1 190 110"
          fill="none"
          className={`stroke-current ${colorClass}`}
          strokeWidth="12"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          style={{ transition: "stroke-dashoffset 0.3s ease-out" }}
        />
        {/* Score text */}
        <text
          x="100"
          y="90"
          textAnchor="middle"
          className={`fill-current ${colorClass} font-mono`}
          fontSize="36"
          fontWeight="bold"
        >
          {displayScore}
        </text>
        <text
          x="100"
          y="108"
          textAnchor="middle"
          className="fill-current text-muted-foreground font-mono"
          fontSize="11"
        >
          RISK SCORE
        </text>
      </svg>
      <span
        className={`font-mono text-sm font-bold uppercase tracking-widest ${colorClass}`}
      >
        {animating ? "SCANNING..." : level}
      </span>
    </div>
  );
}
