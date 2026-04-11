import { type AnalysisResult } from "@/lib/phishing-analyzer";
import { Clock, ExternalLink, ShieldCheck, ShieldAlert, ShieldX } from "lucide-react";

interface HistoryPanelProps {
  history: AnalysisResult[];
  onSelect: (result: AnalysisResult) => void;
}

export function HistoryPanel({ history, onSelect }: HistoryPanelProps) {
  if (history.length === 0) {
    return (
      <div className="rounded-lg border border-border bg-card/30 p-6 text-center">
        <p className="font-mono text-xs text-muted-foreground">No scan history yet</p>
      </div>
    );
  }

  return (
    <div className="space-y-2">
      <h3 className="font-mono text-sm font-semibold uppercase tracking-wider text-muted-foreground">
        Scan History ({history.length})
      </h3>
      <div className="space-y-1.5 max-h-[300px] overflow-y-auto pr-1">
        {history.map((result, i) => (
          <button
            key={i}
            onClick={() => onSelect(result)}
            className="w-full flex items-center gap-3 rounded-md border border-border bg-card/30 p-3 text-left transition-colors hover:bg-secondary/50"
          >
            {result.riskLevel === "dangerous" ? (
              <ShieldX className="h-4 w-4 shrink-0 text-destructive" />
            ) : result.riskLevel === "suspicious" ? (
              <ShieldAlert className="h-4 w-4 shrink-0 text-warning" />
            ) : (
              <ShieldCheck className="h-4 w-4 shrink-0 text-safe" />
            )}
            <div className="flex-1 min-w-0">
              <p className="truncate font-mono text-xs text-foreground">{result.url}</p>
              <div className="mt-1 flex items-center gap-2">
                <span
                  className={`font-mono text-[10px] font-bold uppercase ${
                    result.riskLevel === "dangerous"
                      ? "text-destructive"
                      : result.riskLevel === "suspicious"
                      ? "text-warning"
                      : "text-safe"
                  }`}
                >
                  {result.riskLevel} ({result.riskScore}%)
                </span>
                <span className="flex items-center gap-1 font-mono text-[10px] text-muted-foreground">
                  <Clock className="h-3 w-3" />
                  {result.analysisTimeMs.toFixed(1)}ms
                </span>
              </div>
            </div>
            <ExternalLink className="h-3 w-3 shrink-0 text-muted-foreground" />
          </button>
        ))}
      </div>
    </div>
  );
}
