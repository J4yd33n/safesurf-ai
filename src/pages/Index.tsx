import { useState, useCallback } from "react";
import { Search, Loader2, Shield } from "lucide-react";
import { analyzeURL, fetchWhois, type AnalysisResult } from "@/lib/phishing-analyzer";
import { RiskGauge } from "@/components/RiskGauge";
import { IndicatorList } from "@/components/IndicatorList";
import { URLFeaturesPanel } from "@/components/URLFeaturesPanel";
import { HistoryPanel } from "@/components/HistoryPanel";
import { useAuth } from "@/hooks/useAuth";
import { supabase } from "@/integrations/supabase/client";

export default function Index() {
  const { user } = useAuth();
  const [url, setUrl] = useState("");
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [history, setHistory] = useState<AnalysisResult[]>([]);
  const [scanning, setScanning] = useState(false);

  const handleScan = useCallback(() => {
    if (!url.trim()) return;
    setScanning(true);
    setResult(null);

    setTimeout(async () => {
      const analysis = analyzeURL(url.trim());
      // WHOIS enrichment (non-blocking failure)
      const supaUrl = import.meta.env.VITE_SUPABASE_URL as string;
      const anonKey = import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY as string;
      const whois = await fetchWhois(
        analysis.urlFeatures.domain,
        `${supaUrl}/functions/v1`,
        anonKey,
      );
      if (whois) {
        analysis.whois = whois;
        // Penalize very young domains
        if (whois.isYoung) {
          analysis.riskScore = Math.min(100, analysis.riskScore + 15);
          if (analysis.riskScore >= 60) analysis.riskLevel = "dangerous";
          else if (analysis.riskScore >= 30) analysis.riskLevel = "suspicious";
        }
      }
      setResult(analysis);
      setHistory((prev) => [analysis, ...prev].slice(0, 50));
      setScanning(false);

      // Save to database if logged in
      if (user) {
        await supabase.from("scan_results").insert({
          user_id: user.id,
          url: analysis.url,
          risk_score: analysis.riskScore,
          risk_level: analysis.riskLevel,
          indicators: JSON.parse(JSON.stringify(analysis.indicators)),
          url_features: JSON.parse(JSON.stringify(analysis.urlFeatures)),
          analysis_time_ms: analysis.analysisTimeMs,
        });
      }
    }, 1200 + Math.random() * 800);
  }, [url, user]);

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter") handleScan();
  };

  const stats = {
    total: history.length,
    safe: history.filter((r) => r.riskLevel === "safe").length,
    suspicious: history.filter((r) => r.riskLevel === "suspicious").length,
    dangerous: history.filter((r) => r.riskLevel === "dangerous").length,
  };

  return (
    <div className="mx-auto max-w-6xl px-4 py-8">
      {/* Header */}
      <header className="mb-10 text-center">
        <p className="font-mono text-xs text-muted-foreground">
          Real-Time Phishing URL Detection & Risk Classification System
        </p>
        {!user && (
          <p className="mt-2 font-mono text-[10px] text-primary">
            Sign in to save your scan history to the cloud
          </p>
        )}
      </header>

      {/* Scanner Input */}
      <div className="mx-auto mb-10 max-w-2xl">
        <div className="group relative flex items-center rounded-lg border border-border bg-card/60 transition-all focus-within:border-primary focus-within:glow-primary">
          <Search className="ml-4 h-4 w-4 shrink-0 text-muted-foreground" />
          <input
            type="text"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Enter URL to analyze (e.g., https://suspicious-site.tk/login)"
            className="flex-1 bg-transparent px-3 py-4 font-mono text-sm text-foreground placeholder:text-muted-foreground focus:outline-none"
            disabled={scanning}
          />
          <button
            onClick={handleScan}
            disabled={scanning || !url.trim()}
            className="mr-2 rounded-md bg-primary px-5 py-2 font-mono text-sm font-bold text-primary-foreground transition-all hover:opacity-90 disabled:opacity-40"
          >
            {scanning ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              "SCAN"
            )}
          </button>
        </div>
      </div>

      {/* Stats Bar */}
      {history.length > 0 && (
        <div className="mb-8 flex justify-center gap-6 font-mono text-xs">
          <span className="text-muted-foreground">
            Total: <span className="text-foreground font-semibold">{stats.total}</span>
          </span>
          <span className="text-safe">Safe: {stats.safe}</span>
          <span className="text-warning">Suspicious: {stats.suspicious}</span>
          <span className="text-destructive">Dangerous: {stats.dangerous}</span>
        </div>
      )}

      {/* Results */}
      {(scanning || result) && (
        <div className="grid gap-6 lg:grid-cols-3">
          <div className="space-y-6">
            <div className="flex justify-center rounded-lg border border-border bg-card/40 p-6">
              <RiskGauge
                score={result?.riskScore ?? 0}
                level={result?.riskLevel ?? "safe"}
                animating={scanning}
              />
            </div>
            {result && <URLFeaturesPanel features={result.urlFeatures} />}
          </div>
          <div className="lg:col-span-2">
            {result && <IndicatorList indicators={result.indicators} />}
            {scanning && (
              <div className="flex flex-col items-center justify-center gap-3 rounded-lg border border-border bg-card/30 p-12">
                <Loader2 className="h-8 w-8 animate-spin text-primary" />
                <p className="font-mono text-xs text-muted-foreground animate-pulse">
                  Analyzing URL features and risk indicators...
                </p>
              </div>
            )}
          </div>
        </div>
      )}

      {/* History */}
      {history.length > 0 && (
        <div className="mt-8">
          <HistoryPanel
            history={history}
            onSelect={(r) => {
              setResult(r);
              setUrl(r.url);
            }}
          />
        </div>
      )}

      {/* Empty state */}
      {!scanning && !result && history.length === 0 && (
        <div className="mt-12 text-center">
          <Shield className="mx-auto h-16 w-16 text-muted-foreground/30" />
          <p className="mt-4 font-mono text-sm text-muted-foreground">
            Enter a URL above to begin real-time phishing analysis
          </p>
          <div className="mt-6 flex flex-wrap justify-center gap-2">
            {[
              "https://secure-banking-login.tk/verify",
              "https://google.com",
              "http://192.168.1.1/admin/login.php",
              "https://paypa1-secure.xyz/account/verify?id=12345",
            ].map((example) => (
              <button
                key={example}
                onClick={() => setUrl(example)}
                className="rounded border border-border bg-card/30 px-3 py-1.5 font-mono text-[10px] text-muted-foreground transition-colors hover:border-primary hover:text-primary"
              >
                {example.length > 40 ? example.slice(0, 40) + "..." : example}
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Footer */}
      <footer className="mt-16 border-t border-border pt-6 text-center">
        <p className="font-mono text-[10px] text-muted-foreground">
          PhishGuard — Final Year Project • Heuristic-Based Real-Time Phishing Detection System
        </p>
      </footer>
    </div>
  );
}
