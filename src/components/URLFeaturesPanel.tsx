import { type URLFeatures } from "@/lib/phishing-analyzer";

interface URLFeaturesProps {
  features: URLFeatures;
}

export function URLFeaturesPanel({ features }: URLFeaturesProps) {
  const rows = [
    { label: "Domain", value: features.domain },
    { label: "TLD", value: `.${features.tld}` },
    { label: "Protocol", value: features.hasHttps ? "HTTPS ✓" : "HTTP ✗", warn: !features.hasHttps },
    { label: "Path", value: features.path || "/" },
    { label: "URL Length", value: `${features.urlLength} chars`, warn: features.urlLength > 75 },
    { label: "Subdomains", value: String(features.subdomainCount), warn: features.subdomainCount >= 3 },
    { label: "Query Params", value: String(features.queryParams) },
    { label: "Special Chars", value: String(features.specialCharCount), warn: features.specialCharCount > 5 },
    { label: "Domain Entropy", value: features.entropy.toFixed(3), warn: features.entropy > 3.5 },
    { label: "IP Address", value: features.hasIPAddress ? "Yes ✗" : "No ✓", warn: features.hasIPAddress },
    { label: "Suspicious Keywords", value: features.suspiciousKeywords.length > 0 ? features.suspiciousKeywords.join(", ") : "None", warn: features.suspiciousKeywords.length > 0 },
  ];

  return (
    <div className="space-y-2">
      <h3 className="font-mono text-sm font-semibold uppercase tracking-wider text-muted-foreground">
        URL Features Extracted
      </h3>
      <div className="rounded-lg border border-border bg-card/50 overflow-hidden">
        <table className="w-full font-mono text-xs">
          <tbody>
            {rows.map((row, i) => (
              <tr key={i} className={i % 2 === 0 ? "bg-muted/20" : ""}>
                <td className="px-3 py-2 text-muted-foreground whitespace-nowrap">{row.label}</td>
                <td className={`px-3 py-2 break-all ${row.warn ? "text-warning" : "text-foreground"}`}>
                  {row.value}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
