import { useState } from "react";
import { Navigate } from "react-router-dom";
import { useAuth } from "@/hooks/useAuth";
import { supabase } from "@/integrations/supabase/client";
import { analyzeURL, type AnalysisResult } from "@/lib/phishing-analyzer";
import { Loader2, FileText, Download, Shield, ShieldAlert, ShieldX, ShieldCheck, Zap } from "lucide-react";
import { toast } from "sonner";

export default function BulkScan() {
  const { user, loading } = useAuth();
  const [urlInput, setUrlInput] = useState("");
  const [results, setResults] = useState<AnalysisResult[]>([]);
  const [scanning, setScanning] = useState(false);
  const [progress, setProgress] = useState(0);

  const handleBulkScan = async () => {
    const urls = urlInput
      .split("\n")
      .map((u) => u.trim())
      .filter((u) => u.length > 0);
    if (urls.length === 0) return;
    if (urls.length > 500) {
      toast.error("Maximum 500 URLs per batch");
      return;
    }

    setScanning(true);
    setResults([]);
    setProgress(0);

    const allResults: AnalysisResult[] = [];

    for (let i = 0; i < urls.length; i++) {
      const result = analyzeURL(urls[i]);
      allResults.push(result);
      setResults([...allResults]);
      setProgress(((i + 1) / urls.length) * 100);
      // Small delay to show progress
      if (i % 10 === 0) await new Promise((r) => setTimeout(r, 10));
    }

    // Save to database
    if (user) {
      const inserts = allResults.map((r) => ({
        user_id: user.id,
        url: r.url,
        risk_score: r.riskScore,
        risk_level: r.riskLevel,
        indicators: JSON.parse(JSON.stringify(r.indicators)),
        url_features: JSON.parse(JSON.stringify(r.urlFeatures)),
        analysis_time_ms: r.analysisTimeMs,
      }));
      // Batch insert
      for (let i = 0; i < inserts.length; i += 100) {
        await supabase.from("scan_results").insert(inserts.slice(i, i + 100));
      }
    }

    setScanning(false);
    toast.success(`Scanned ${allResults.length} URLs`);
  };

  const exportCSV = () => {
    if (results.length === 0) return;
    const header = "URL,Risk Score,Risk Level,Indicators Detected,Analysis Time (ms)\n";
    const rows = results.map((r) =>
      `"${r.url}",${r.riskScore},${r.riskLevel},${r.indicators.filter((i) => i.detected).length},${r.analysisTimeMs.toFixed(2)}`
    ).join("\n");
    const blob = new Blob([header + rows], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `phishguard-bulk-scan-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const exportJSON = () => {
    if (results.length === 0) return;
    const data = results.map((r) => ({
      url: r.url,
      riskScore: r.riskScore,
      riskLevel: r.riskLevel,
      indicators: r.indicators.filter((i) => i.detected).map((i) => ({ name: i.name, severity: i.severity })),
      urlFeatures: r.urlFeatures,
    }));
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `phishguard-bulk-scan-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  if (loading) return null;
  if (!user) return <Navigate to="/auth" replace />;

  const stats = {
    safe: results.filter((r) => r.riskLevel === "safe").length,
    suspicious: results.filter((r) => r.riskLevel === "suspicious").length,
    dangerous: results.filter((r) => r.riskLevel === "dangerous").length,
  };

  return (
    <div className="mx-auto max-w-6xl px-4 py-8">
      <h1 className="mb-6 font-mono text-xl font-bold text-foreground">
        <Zap className="mr-2 inline h-5 w-5 text-primary" />
        Bulk URL Scanner
      </h1>

      <div className="grid gap-6 lg:grid-cols-2">
        {/* Input */}
        <div className="space-y-4">
          <div>
            <label className="mb-2 block font-mono text-xs text-muted-foreground">
              Paste URLs (one per line, max 500)
            </label>
            <textarea
              value={urlInput}
              onChange={(e) => setUrlInput(e.target.value)}
              placeholder={"https://suspicious-site.tk/login\nhttps://google.com\nhttp://192.168.1.1/admin"}
              className="h-[300px] w-full rounded-lg border border-border bg-card/60 px-4 py-3 font-mono text-xs text-foreground placeholder:text-muted-foreground focus:border-primary focus:outline-none"
              disabled={scanning}
            />
          </div>
          <div className="flex gap-2">
            <button
              onClick={handleBulkScan}
              disabled={scanning || !urlInput.trim()}
              className="flex-1 rounded-md bg-primary py-3 font-mono text-sm font-bold text-primary-foreground hover:opacity-90 disabled:opacity-50"
            >
              {scanning ? (
                <span className="flex items-center justify-center gap-2">
                  <Loader2 className="h-4 w-4 animate-spin" />
                  Scanning... {Math.round(progress)}%
                </span>
              ) : (
                `SCAN ${urlInput.split("\n").filter((u) => u.trim()).length} URLs`
              )}
            </button>
          </div>
          {scanning && (
            <div className="h-2 overflow-hidden rounded-full bg-muted">
              <div
                className="h-full bg-primary transition-all"
                style={{ width: `${progress}%` }}
              />
            </div>
          )}
        </div>

        {/* Results */}
        <div className="space-y-4">
          {results.length > 0 && (
            <>
              {/* Quick Stats */}
              <div className="flex gap-3 font-mono text-xs">
                <span className="rounded bg-safe/10 px-2 py-1 text-safe">
                  <ShieldCheck className="mr-1 inline h-3 w-3" />{stats.safe} Safe
                </span>
                <span className="rounded bg-warning/10 px-2 py-1 text-warning">
                  <ShieldAlert className="mr-1 inline h-3 w-3" />{stats.suspicious} Suspicious
                </span>
                <span className="rounded bg-destructive/10 px-2 py-1 text-destructive">
                  <ShieldX className="mr-1 inline h-3 w-3" />{stats.dangerous} Dangerous
                </span>
              </div>

              {/* Export */}
              <div className="flex gap-2">
                <button
                  onClick={exportCSV}
                  className="flex items-center gap-1.5 rounded-md border border-border bg-card/40 px-3 py-2 font-mono text-xs text-muted-foreground hover:text-foreground"
                >
                  <Download className="h-3 w-3" /> Export CSV
                </button>
                <button
                  onClick={exportJSON}
                  className="flex items-center gap-1.5 rounded-md border border-border bg-card/40 px-3 py-2 font-mono text-xs text-muted-foreground hover:text-foreground"
                >
                  <Download className="h-3 w-3" /> Export JSON
                </button>
              </div>

              {/* Results Table */}
              <div className="rounded-lg border border-border bg-card/40 overflow-hidden">
                <div className="max-h-[400px] overflow-auto">
                  <table className="w-full font-mono text-xs">
                    <thead className="sticky top-0 bg-card">
                      <tr className="border-b border-border text-muted-foreground">
                        <th className="px-3 py-2 text-left">URL</th>
                        <th className="px-3 py-2 text-center">Score</th>
                        <th className="px-3 py-2 text-center">Level</th>
                        <th className="px-3 py-2 text-center">Threats</th>
                      </tr>
                    </thead>
                    <tbody>
                      {results.map((r, i) => (
                        <tr key={i} className="border-b border-border/50 hover:bg-secondary/30">
                          <td className="max-w-[250px] truncate px-3 py-2 text-foreground">{r.url}</td>
                          <td className="px-3 py-2 text-center">{r.riskScore}</td>
                          <td className={`px-3 py-2 text-center font-bold uppercase ${r.riskLevel === "dangerous" ? "text-destructive" : r.riskLevel === "suspicious" ? "text-warning" : "text-safe"}`}>
                            {r.riskLevel}
                          </td>
                          <td className="px-3 py-2 text-center text-muted-foreground">
                            {r.indicators.filter((ind) => ind.detected).length}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </>
          )}

          {results.length === 0 && !scanning && (
            <div className="flex h-full items-center justify-center rounded-lg border border-border bg-card/20 p-12">
              <div className="text-center">
                <FileText className="mx-auto h-10 w-10 text-muted-foreground/20" />
                <p className="mt-3 font-mono text-xs text-muted-foreground">
                  Paste URLs and click scan to analyze in bulk
                </p>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
