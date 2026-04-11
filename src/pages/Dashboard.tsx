import { useEffect, useState } from "react";
import { Navigate } from "react-router-dom";
import { useAuth } from "@/hooks/useAuth";
import { supabase } from "@/integrations/supabase/client";
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell, LineChart, Line, Area, AreaChart } from "recharts";
import { Shield, ShieldAlert, ShieldX, ShieldCheck, Activity, TrendingUp, Clock } from "lucide-react";

interface ScanResult {
  id: string;
  url: string;
  risk_score: number;
  risk_level: string;
  created_at: string;
  analysis_time_ms: number;
}

export default function Dashboard() {
  const { user, loading } = useAuth();
  const [scans, setScans] = useState<ScanResult[]>([]);
  const [fetching, setFetching] = useState(true);

  useEffect(() => {
    if (!user) return;
    supabase
      .from("scan_results")
      .select("*")
      .order("created_at", { ascending: false })
      .limit(200)
      .then(({ data }) => {
        setScans((data as ScanResult[]) || []);
        setFetching(false);
      });
  }, [user]);

  if (loading) return null;
  if (!user) return <Navigate to="/auth" replace />;

  const stats = {
    total: scans.length,
    safe: scans.filter((s) => s.risk_level === "safe").length,
    suspicious: scans.filter((s) => s.risk_level === "suspicious").length,
    dangerous: scans.filter((s) => s.risk_level === "dangerous").length,
    avgScore: scans.length ? Math.round(scans.reduce((s, r) => s + r.risk_score, 0) / scans.length) : 0,
    avgTime: scans.length ? (scans.reduce((s, r) => s + r.analysis_time_ms, 0) / scans.length).toFixed(1) : "0",
  };

  const pieData = [
    { name: "Safe", value: stats.safe, color: "hsl(145, 70%, 45%)" },
    { name: "Suspicious", value: stats.suspicious, color: "hsl(38, 95%, 55%)" },
    { name: "Dangerous", value: stats.dangerous, color: "hsl(0, 85%, 55%)" },
  ].filter((d) => d.value > 0);

  // Group by date for trend
  const dateMap = new Map<string, { safe: number; suspicious: number; dangerous: number }>();
  scans.forEach((s) => {
    const day = new Date(s.created_at).toLocaleDateString("en-US", { month: "short", day: "numeric" });
    const entry = dateMap.get(day) || { safe: 0, suspicious: 0, dangerous: 0 };
    entry[s.risk_level as "safe" | "suspicious" | "dangerous"]++;
    dateMap.set(day, entry);
  });
  const trendData = Array.from(dateMap.entries())
    .map(([date, data]) => ({ date, ...data }))
    .reverse()
    .slice(-14);

  // Score distribution
  const scoreBuckets = Array.from({ length: 10 }, (_, i) => ({
    range: `${i * 10}-${i * 10 + 9}`,
    count: scans.filter((s) => s.risk_score >= i * 10 && s.risk_score < (i + 1) * 10).length,
  }));

  const statCards = [
    { label: "Total Scans", value: stats.total, icon: Activity, color: "text-primary" },
    { label: "Safe", value: stats.safe, icon: ShieldCheck, color: "text-safe" },
    { label: "Suspicious", value: stats.suspicious, icon: ShieldAlert, color: "text-warning" },
    { label: "Dangerous", value: stats.dangerous, icon: ShieldX, color: "text-destructive" },
    { label: "Avg Score", value: stats.avgScore, icon: TrendingUp, color: "text-primary" },
    { label: "Avg Time", value: `${stats.avgTime}ms`, icon: Clock, color: "text-muted-foreground" },
  ];

  return (
    <div className="mx-auto max-w-6xl px-4 py-8">
      <h1 className="mb-6 font-mono text-xl font-bold text-foreground">
        <Shield className="mr-2 inline h-5 w-5 text-primary" />
        Analytics Dashboard
      </h1>

      {/* Stat Cards */}
      <div className="mb-8 grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
        {statCards.map((s) => (
          <div key={s.label} className="rounded-lg border border-border bg-card/40 p-4 text-center">
            <s.icon className={`mx-auto h-5 w-5 ${s.color}`} />
            <p className={`mt-2 font-mono text-lg font-bold ${s.color}`}>{s.value}</p>
            <p className="font-mono text-[10px] text-muted-foreground">{s.label}</p>
          </div>
        ))}
      </div>

      {scans.length === 0 ? (
        <div className="rounded-lg border border-border bg-card/30 p-12 text-center">
          <p className="font-mono text-sm text-muted-foreground">
            {fetching ? "Loading scan data..." : "No scans yet. Start scanning URLs to see analytics here."}
          </p>
        </div>
      ) : (
        <div className="grid gap-6 lg:grid-cols-2">
          {/* Risk Distribution Pie */}
          <div className="rounded-lg border border-border bg-card/40 p-4">
            <h3 className="mb-4 font-mono text-sm font-semibold uppercase tracking-wider text-muted-foreground">
              Risk Distribution
            </h3>
            <ResponsiveContainer width="100%" height={220}>
              <PieChart>
                <Pie data={pieData} cx="50%" cy="50%" innerRadius={50} outerRadius={80} dataKey="value" label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}>
                  {pieData.map((entry, i) => (
                    <Cell key={i} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip contentStyle={{ background: "hsl(225, 50%, 9%)", border: "1px solid hsl(225, 30%, 18%)", fontFamily: "JetBrains Mono", fontSize: "11px", color: "hsl(200, 20%, 90%)" }} />
              </PieChart>
            </ResponsiveContainer>
          </div>

          {/* Score Distribution */}
          <div className="rounded-lg border border-border bg-card/40 p-4">
            <h3 className="mb-4 font-mono text-sm font-semibold uppercase tracking-wider text-muted-foreground">
              Score Distribution
            </h3>
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={scoreBuckets}>
                <CartesianGrid strokeDasharray="3 3" stroke="hsl(225, 30%, 18%)" />
                <XAxis dataKey="range" tick={{ fill: "hsl(215, 15%, 50%)", fontSize: 10, fontFamily: "JetBrains Mono" }} />
                <YAxis tick={{ fill: "hsl(215, 15%, 50%)", fontSize: 10 }} />
                <Tooltip contentStyle={{ background: "hsl(225, 50%, 9%)", border: "1px solid hsl(225, 30%, 18%)", fontFamily: "JetBrains Mono", fontSize: "11px", color: "hsl(200, 20%, 90%)" }} />
                <Bar dataKey="count" fill="hsl(187, 100%, 50%)" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>

          {/* Trend */}
          <div className="rounded-lg border border-border bg-card/40 p-4 lg:col-span-2">
            <h3 className="mb-4 font-mono text-sm font-semibold uppercase tracking-wider text-muted-foreground">
              Scan Trend (Last 14 Days)
            </h3>
            <ResponsiveContainer width="100%" height={220}>
              <AreaChart data={trendData}>
                <CartesianGrid strokeDasharray="3 3" stroke="hsl(225, 30%, 18%)" />
                <XAxis dataKey="date" tick={{ fill: "hsl(215, 15%, 50%)", fontSize: 10, fontFamily: "JetBrains Mono" }} />
                <YAxis tick={{ fill: "hsl(215, 15%, 50%)", fontSize: 10 }} />
                <Tooltip contentStyle={{ background: "hsl(225, 50%, 9%)", border: "1px solid hsl(225, 30%, 18%)", fontFamily: "JetBrains Mono", fontSize: "11px", color: "hsl(200, 20%, 90%)" }} />
                <Area type="monotone" dataKey="safe" stackId="1" stroke="hsl(145, 70%, 45%)" fill="hsl(145, 70%, 45%)" fillOpacity={0.3} />
                <Area type="monotone" dataKey="suspicious" stackId="1" stroke="hsl(38, 95%, 55%)" fill="hsl(38, 95%, 55%)" fillOpacity={0.3} />
                <Area type="monotone" dataKey="dangerous" stackId="1" stroke="hsl(0, 85%, 55%)" fill="hsl(0, 85%, 55%)" fillOpacity={0.3} />
              </AreaChart>
            </ResponsiveContainer>
          </div>

          {/* Recent Scans Table */}
          <div className="rounded-lg border border-border bg-card/40 p-4 lg:col-span-2">
            <h3 className="mb-4 font-mono text-sm font-semibold uppercase tracking-wider text-muted-foreground">
              Recent Scans
            </h3>
            <div className="max-h-[300px] overflow-auto">
              <table className="w-full font-mono text-xs">
                <thead>
                  <tr className="border-b border-border text-muted-foreground">
                    <th className="px-3 py-2 text-left">URL</th>
                    <th className="px-3 py-2 text-center">Score</th>
                    <th className="px-3 py-2 text-center">Level</th>
                    <th className="px-3 py-2 text-right">Time</th>
                  </tr>
                </thead>
                <tbody>
                  {scans.slice(0, 20).map((s) => (
                    <tr key={s.id} className="border-b border-border/50 hover:bg-secondary/30">
                      <td className="max-w-[300px] truncate px-3 py-2 text-foreground">{s.url}</td>
                      <td className="px-3 py-2 text-center">{s.risk_score}</td>
                      <td className={`px-3 py-2 text-center font-bold uppercase ${s.risk_level === "dangerous" ? "text-destructive" : s.risk_level === "suspicious" ? "text-warning" : "text-safe"}`}>
                        {s.risk_level}
                      </td>
                      <td className="px-3 py-2 text-right text-muted-foreground">
                        {new Date(s.created_at).toLocaleDateString()}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
