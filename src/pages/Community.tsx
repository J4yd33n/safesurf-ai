import { useEffect, useState } from "react";
import { ThumbsUp, Flag, Loader2, Link as LinkIcon } from "lucide-react";
import { useAuth } from "@/hooks/useAuth";
import { supabase } from "@/integrations/supabase/client";
import { analyzeURL } from "@/lib/phishing-analyzer";
import { toast } from "sonner";

interface Report {
  id: string;
  url: string;
  category: string;
  description: string | null;
  risk_score: number;
  upvotes: number;
  status: string;
  created_at: string;
  user_id: string;
}

const CATEGORIES = ["phishing", "scam", "malware", "fake-store", "credential-harvest", "other"];

export default function Community() {
  const { user } = useAuth();
  const [reports, setReports] = useState<Report[]>([]);
  const [loading, setLoading] = useState(true);
  const [url, setUrl] = useState("");
  const [category, setCategory] = useState("phishing");
  const [description, setDescription] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [myUpvotes, setMyUpvotes] = useState<Set<string>>(new Set());

  const load = async () => {
    setLoading(true);
    const { data } = await supabase
      .from("community_reports")
      .select("*")
      .order("upvotes", { ascending: false })
      .order("created_at", { ascending: false })
      .limit(100);
    setReports((data as Report[]) || []);
    if (user) {
      const { data: ups } = await supabase
        .from("report_upvotes")
        .select("report_id")
        .eq("user_id", user.id);
      setMyUpvotes(new Set((ups || []).map((u: { report_id: string }) => u.report_id)));
    }
    setLoading(false);
  };

  useEffect(() => {
    load();
  }, [user]);

  const submit = async () => {
    if (!user) {
      toast.error("Sign in to submit a report");
      return;
    }
    if (!url.trim()) return;
    setSubmitting(true);
    const analysis = analyzeURL(url.trim());
    const { error } = await supabase.from("community_reports").insert({
      user_id: user.id,
      url: url.trim(),
      category,
      description: description.trim() || null,
      risk_score: analysis.riskScore,
    });
    if (error) {
      toast.error("Failed to submit report");
    } else {
      toast.success("Report submitted — thanks for protecting the community!");
      setUrl("");
      setDescription("");
      load();
    }
    setSubmitting(false);
  };

  const toggleUpvote = async (reportId: string) => {
    if (!user) {
      toast.error("Sign in to upvote");
      return;
    }
    if (myUpvotes.has(reportId)) {
      await supabase
        .from("report_upvotes")
        .delete()
        .eq("user_id", user.id)
        .eq("report_id", reportId);
      const report = reports.find((r) => r.id === reportId);
      if (report) {
        await supabase
          .from("community_reports")
          .update({ upvotes: Math.max(0, report.upvotes - 1) })
          .eq("id", reportId);
      }
    } else {
      await supabase.from("report_upvotes").insert({ user_id: user.id, report_id: reportId });
      const report = reports.find((r) => r.id === reportId);
      if (report) {
        await supabase
          .from("community_reports")
          .update({ upvotes: report.upvotes + 1 })
          .eq("id", reportId);
      }
    }
    load();
  };

  return (
    <div className="mx-auto max-w-4xl px-4 py-8">
      <header className="mb-8">
        <h1 className="font-mono text-2xl font-bold text-foreground">
          Community <span className="text-primary">Threat Feed</span>
        </h1>
        <p className="mt-2 font-mono text-xs text-muted-foreground">
          User-reported phishing & scam URLs. Upvote what you've seen in the wild.
        </p>
      </header>

      {/* Submit */}
      <div className="mb-8 rounded-lg border border-border bg-card/50 p-4">
        <h2 className="mb-3 font-mono text-sm font-semibold uppercase tracking-wider text-muted-foreground">
          Report a suspicious URL
        </h2>
        <div className="space-y-2">
          <input
            type="text"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://suspicious-site.example/login"
            className="w-full rounded-md border border-border bg-background px-3 py-2 font-mono text-xs text-foreground focus:border-primary focus:outline-none"
          />
          <div className="flex gap-2">
            <select
              value={category}
              onChange={(e) => setCategory(e.target.value)}
              className="rounded-md border border-border bg-background px-3 py-2 font-mono text-xs text-foreground focus:border-primary focus:outline-none"
            >
              {CATEGORIES.map((c) => (
                <option key={c} value={c}>
                  {c}
                </option>
              ))}
            </select>
            <input
              type="text"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="Optional: how did you encounter it?"
              className="flex-1 rounded-md border border-border bg-background px-3 py-2 font-mono text-xs text-foreground focus:border-primary focus:outline-none"
            />
            <button
              onClick={submit}
              disabled={submitting || !url.trim()}
              className="rounded-md bg-primary px-4 py-2 font-mono text-xs font-bold text-primary-foreground transition-all hover:opacity-90 disabled:opacity-40"
            >
              {submitting ? <Loader2 className="h-4 w-4 animate-spin" /> : "REPORT"}
            </button>
          </div>
        </div>
      </div>

      {/* Feed */}
      {loading ? (
        <div className="flex justify-center py-12">
          <Loader2 className="h-6 w-6 animate-spin text-primary" />
        </div>
      ) : reports.length === 0 ? (
        <div className="text-center py-12">
          <Flag className="mx-auto h-12 w-12 text-muted-foreground/30" />
          <p className="mt-4 font-mono text-xs text-muted-foreground">
            No reports yet. Be the first to flag a threat.
          </p>
        </div>
      ) : (
        <div className="space-y-2">
          {reports.map((r) => (
            <div
              key={r.id}
              className="flex items-start gap-3 rounded-lg border border-border bg-card/40 p-3"
            >
              <button
                onClick={() => toggleUpvote(r.id)}
                className={`flex flex-col items-center gap-0.5 rounded-md px-2 py-1.5 font-mono text-xs transition-colors ${
                  myUpvotes.has(r.id)
                    ? "bg-primary/20 text-primary"
                    : "text-muted-foreground hover:bg-secondary/50"
                }`}
              >
                <ThumbsUp className="h-3.5 w-3.5" />
                <span>{r.upvotes}</span>
              </button>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <LinkIcon className="h-3 w-3 text-muted-foreground shrink-0" />
                  <span className="font-mono text-xs text-foreground break-all">{r.url}</span>
                  <span className="rounded bg-secondary px-1.5 py-0.5 font-mono text-[10px] uppercase text-muted-foreground">
                    {r.category}
                  </span>
                  <span
                    className={`rounded px-1.5 py-0.5 font-mono text-[10px] font-bold ${
                      r.risk_score >= 60
                        ? "bg-destructive/20 text-destructive"
                        : r.risk_score >= 30
                        ? "bg-warning/20 text-warning"
                        : "bg-safe/20 text-safe"
                    }`}
                  >
                    risk: {r.risk_score}
                  </span>
                </div>
                {r.description && (
                  <p className="mt-1 font-mono text-[11px] text-muted-foreground">{r.description}</p>
                )}
                <p className="mt-1 font-mono text-[10px] text-muted-foreground/70">
                  {new Date(r.created_at).toLocaleString()}
                </p>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}