import { type AnalysisIndicator } from "@/lib/phishing-analyzer";
import { Shield, ShieldAlert, ShieldX, ShieldCheck } from "lucide-react";

interface IndicatorListProps {
  indicators: AnalysisIndicator[];
}

export function IndicatorList({ indicators }: IndicatorListProps) {
  const sorted = [...indicators].sort((a, b) => {
    if (a.detected !== b.detected) return a.detected ? -1 : 1;
    return b.weight - a.weight;
  });

  return (
    <div className="space-y-2">
      <h3 className="font-mono text-sm font-semibold uppercase tracking-wider text-muted-foreground">
        Risk Indicators
      </h3>
      <div className="space-y-1.5">
        {sorted.map((indicator, i) => (
          <div
            key={i}
            className={`flex items-start gap-3 rounded-md border p-3 transition-colors ${
              indicator.detected
                ? indicator.severity === "critical"
                  ? "border-destructive/40 bg-destructive/5"
                  : indicator.severity === "high"
                  ? "border-destructive/20 bg-destructive/5"
                  : indicator.severity === "medium"
                  ? "border-warning/20 bg-warning/5"
                  : "border-muted bg-muted/30"
                : "border-muted/50 bg-transparent opacity-50"
            }`}
          >
            <div className="mt-0.5">
              {indicator.detected ? (
                indicator.severity === "critical" ? (
                  <ShieldX className="h-4 w-4 text-destructive" />
                ) : indicator.severity === "high" ? (
                  <ShieldAlert className="h-4 w-4 text-destructive" />
                ) : (
                  <Shield className="h-4 w-4 text-warning" />
                )
              ) : (
                <ShieldCheck className="h-4 w-4 text-safe" />
              )}
            </div>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2">
                <span className="font-mono text-xs font-semibold text-foreground">
                  {indicator.name}
                </span>
                {indicator.detected && (
                  <span
                    className={`rounded px-1.5 py-0.5 font-mono text-[10px] font-bold uppercase ${
                      indicator.severity === "critical"
                        ? "bg-destructive/20 text-destructive"
                        : indicator.severity === "high"
                        ? "bg-destructive/10 text-destructive"
                        : indicator.severity === "medium"
                        ? "bg-warning/10 text-warning"
                        : "bg-muted text-muted-foreground"
                    }`}
                  >
                    {indicator.severity}
                  </span>
                )}
              </div>
              <p className="mt-0.5 font-mono text-[11px] text-muted-foreground">
                {indicator.description}
              </p>
            </div>
            <span className="font-mono text-[10px] text-muted-foreground">
              w:{indicator.weight}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
