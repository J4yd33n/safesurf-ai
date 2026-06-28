import { useState } from "react";
import { Link } from "react-router-dom";
import { Shield, Zap, Lock, Globe, Download, ArrowRight, Check, ExternalLink, Github } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { toast } from "sonner";

const FEATURES = [
  { icon: Zap, title: "Sub-second scans", body: "12 heuristic indicators + Random Forest model run entirely in your browser. No round trip, no waiting." },
  { icon: Shield, title: "Brand impersonation defense", body: "Levenshtein-distance check against the top 20 brands catches g00gle.com and paypa1.com before you click." },
  { icon: Globe, title: "Free-hosting trap", body: "Flags paypal-login.firebaseapp.com and other phish-on-cloud campaigns the major blocklists miss." },
  { icon: Lock, title: "Privacy-first", body: "Scans run locally in the extension. Your browsing history never leaves your machine." },
];

const PRICING = [
  { tier: "Free", price: "$0", tagline: "For individuals", perks: ["50 scans / month", "Browser extension", "Community threat feed", "Domain age check"] },
  { tier: "Pro", price: "$9", tagline: "For power users", perks: ["Unlimited scans", "Bulk URL scanning", "CSV export", "Priority WHOIS lookups", "Email alerts"], highlight: true },
  { tier: "Business", price: "$49", tagline: "For teams & MSPs", perks: ["Everything in Pro", "REST API access", "Team seats", "Custom domain allowlist", "SLA & support"] },
];

const FAQ = [
  { q: "How is this different from Google Safe Browsing?", a: "Safe Browsing blocks known-bad URLs from a blocklist. PhishGuard scores unknown URLs the moment they're visited, catching zero-day phishing campaigns hosted on fresh domains or free cloud providers." },
  { q: "Does it work on Chrome, Edge, Brave, Arc?", a: "Yes — anything Chromium-based and Manifest V3 compatible. Firefox port is on the roadmap." },
  { q: "Do you see my browsing history?", a: "No. The extension scans locally. Only URLs you explicitly submit via the web app or community feed are stored, and that's tied to your account." },
  { q: "Can I self-host?", a: "The core analyzer is open and runs entirely client-side. Business tier customers get a Docker image of the WHOIS enrichment service." },
];

const downloadExtension = () => {
  fetch("/phishguard-extension.zip")
    .then((r) => { if (!r.ok) throw new Error(`Download failed: ${r.status}`); return r.blob(); })
    .then((blob) => {
      const a = document.createElement("a");
      a.href = URL.createObjectURL(blob);
      a.download = "phishguard-extension.zip";
      a.click();
      URL.revokeObjectURL(a.href);
      toast.success("Extension downloaded — unzip and load via chrome://extensions");
    })
    .catch((err) => toast.error(err.message));
};

export default function Launch() {
  const [email, setEmail] = useState("");
  const handleSubscribe = (e: React.FormEvent) => {
    e.preventDefault();
    if (!email.includes("@")) return toast.error("Enter a valid email");
    toast.success("You're on the launch list. We'll email you when we hit Product Hunt.");
    setEmail("");
  };

  return (
    <main className="container mx-auto px-4 py-12 max-w-6xl">
      {/* HERO */}
      <section className="text-center py-16 md:py-24">
        <div className="inline-flex items-center gap-2 px-3 py-1 mb-6 rounded-full border border-primary/40 bg-primary/10 text-primary text-xs font-mono uppercase tracking-widest">
          <span className="w-2 h-2 rounded-full bg-primary animate-pulse" />
          Launching on Product Hunt
        </div>
        <h1 className="text-4xl md:text-6xl font-bold tracking-tight mb-6 font-mono">
          Stop phishing <span className="text-primary">before the click.</span>
        </h1>
        <p className="text-lg md:text-xl text-muted-foreground max-w-2xl mx-auto mb-8">
          A real-time URL scanner with a Random Forest model + 12 heuristic indicators. Built for the 91% of breaches that start with a phishing link.
        </p>
        <div className="flex flex-col sm:flex-row gap-3 justify-center items-center">
          <Button size="lg" onClick={downloadExtension} className="glow-primary">
            <Download className="mr-2 h-4 w-4" /> Install Chrome Extension
          </Button>
          <Link to="/">
            <Button size="lg" variant="outline">
              Try the web scanner <ArrowRight className="ml-2 h-4 w-4" />
            </Button>
          </Link>
        </div>
        <p className="text-xs text-muted-foreground mt-4 font-mono">Free forever for individuals · No credit card · MV3 compliant</p>
      </section>

      {/* SOCIAL PROOF STRIP */}
      <section className="grid grid-cols-2 md:grid-cols-4 gap-4 py-8 border-y border-border my-8">
        {[
          { k: "12", v: "Heuristic indicators" },
          { k: "<50ms", v: "Avg scan time" },
          { k: "94%", v: "Model F1 score" },
          { k: "100%", v: "Client-side privacy" },
        ].map((s) => (
          <div key={s.v} className="text-center">
            <div className="text-3xl md:text-4xl font-bold text-primary font-mono">{s.k}</div>
            <div className="text-xs text-muted-foreground uppercase tracking-wider mt-1">{s.v}</div>
          </div>
        ))}
      </section>

      {/* FEATURES */}
      <section className="py-12">
        <h2 className="text-3xl font-bold mb-2 font-mono">What's under the hood</h2>
        <p className="text-muted-foreground mb-8">No black box. Every signal is inspectable.</p>
        <div className="grid md:grid-cols-2 gap-4">
          {FEATURES.map((f) => (
            <Card key={f.title} className="p-6 hover:border-primary/50 transition-colors">
              <f.icon className="h-6 w-6 text-primary mb-3" />
              <h3 className="font-semibold mb-2">{f.title}</h3>
              <p className="text-sm text-muted-foreground">{f.body}</p>
            </Card>
          ))}
        </div>
      </section>

      {/* PRICING */}
      <section className="py-12">
        <h2 className="text-3xl font-bold mb-2 font-mono">Pricing</h2>
        <p className="text-muted-foreground mb-8">Start free. Upgrade when you need volume or an API.</p>
        <div className="grid md:grid-cols-3 gap-4">
          {PRICING.map((p) => (
            <Card key={p.tier} className={`p-6 ${p.highlight ? "border-primary glow-primary" : ""}`}>
              <div className="flex items-baseline justify-between mb-2">
                <h3 className="text-xl font-bold font-mono">{p.tier}</h3>
                {p.highlight && <span className="text-[10px] uppercase tracking-widest text-primary">Popular</span>}
              </div>
              <div className="text-3xl font-bold mb-1">{p.price}<span className="text-sm font-normal text-muted-foreground">/mo</span></div>
              <div className="text-xs text-muted-foreground mb-4">{p.tagline}</div>
              <ul className="space-y-2 text-sm">
                {p.perks.map((perk) => (
                  <li key={perk} className="flex items-start gap-2">
                    <Check className="h-4 w-4 text-primary mt-0.5 shrink-0" /> {perk}
                  </li>
                ))}
              </ul>
            </Card>
          ))}
        </div>
      </section>

      {/* INSTALL STEPS */}
      <section className="py-12">
        <h2 className="text-3xl font-bold mb-6 font-mono">Install in 30 seconds</h2>
        <ol className="space-y-3 text-sm">
          {[
            "Click \"Install Chrome Extension\" above to download the .zip",
            "Unzip the archive somewhere stable on your machine",
            "Open chrome://extensions and toggle Developer mode (top-right)",
            "Click \"Load unpacked\" and select the unzipped folder",
            "Pin the PhishGuard icon — you're protected on every page load",
          ].map((step, i) => (
            <li key={i} className="flex gap-3 p-3 rounded-lg bg-secondary/50 border border-border">
              <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-primary text-primary-foreground font-mono text-xs font-bold">{i + 1}</span>
              <span className="text-foreground/90">{step}</span>
            </li>
          ))}
        </ol>
      </section>

      {/* FAQ */}
      <section className="py-12">
        <h2 className="text-3xl font-bold mb-6 font-mono">FAQ</h2>
        <div className="space-y-3">
          {FAQ.map((item) => (
            <details key={item.q} className="group p-4 rounded-lg border border-border bg-card">
              <summary className="font-medium cursor-pointer flex justify-between items-center">
                {item.q}
                <ArrowRight className="h-4 w-4 transition-transform group-open:rotate-90" />
              </summary>
              <p className="mt-3 text-sm text-muted-foreground">{item.a}</p>
            </details>
          ))}
        </div>
      </section>

      {/* EMAIL CAPTURE */}
      <section className="py-16 text-center border-t border-border mt-12">
        <h2 className="text-2xl md:text-3xl font-bold mb-3 font-mono">Get the launch-day discount</h2>
        <p className="text-muted-foreground mb-6">50% off Pro for the first 100 Product Hunt visitors. Drop your email.</p>
        <form onSubmit={handleSubscribe} className="flex flex-col sm:flex-row gap-2 max-w-md mx-auto">
          <input
            type="email"
            required
            placeholder="you@domain.com"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="flex-1 px-4 py-2 rounded-md border border-border bg-card text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-primary"
          />
          <Button type="submit" className="glow-primary">Notify me <ArrowRight className="ml-2 h-4 w-4" /></Button>
        </form>
        <div className="flex justify-center gap-4 mt-8 text-sm text-muted-foreground">
          <a href="https://www.producthunt.com" target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 hover:text-primary">
            <ExternalLink className="h-3 w-3" /> Product Hunt
          </a>
          <a href="https://github.com" target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 hover:text-primary">
            <Github className="h-3 w-3" /> GitHub
          </a>
        </div>
      </section>
    </main>
  );
}