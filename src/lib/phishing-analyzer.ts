export type RiskLevel = "safe" | "suspicious" | "dangerous";

export interface AnalysisIndicator {
  name: string;
  description: string;
  severity: "low" | "medium" | "high" | "critical";
  detected: boolean;
  weight: number;
}

export interface AnalysisResult {
  url: string;
  riskLevel: RiskLevel;
  riskScore: number; // 0-100
  indicators: AnalysisIndicator[];
  timestamp: Date;
  analysisTimeMs: number;
  urlFeatures: URLFeatures;
}

export interface URLFeatures {
  domain: string;
  tld: string;
  path: string;
  queryParams: number;
  urlLength: number;
  subdomainCount: number;
  hasHttps: boolean;
  hasIPAddress: boolean;
  specialCharCount: number;
  entropy: number;
  suspiciousKeywords: string[];
}

const SUSPICIOUS_KEYWORDS = [
  "login", "signin", "verify", "account", "secure", "update", "confirm",
  "banking", "paypal", "ebay", "amazon", "apple", "microsoft", "google",
  "netflix", "facebook", "instagram", "whatsapp", "telegram",
  "password", "credential", "ssn", "social-security",
  "wallet", "crypto", "bitcoin", "eth",
  "free", "winner", "prize", "gift", "reward", "bonus",
  "urgent", "suspended", "locked", "expired", "limited",
  "click-here", "act-now", "immediately",
];

const SUSPICIOUS_TLDS = [
  "tk", "ml", "ga", "cf", "gq", "buzz", "top", "xyz", "club",
  "work", "date", "racing", "win", "bid", "stream", "download",
  "loan", "trade", "cricket", "party", "science", "review",
];

const LEGITIMATE_DOMAINS = [
  "google.com", "youtube.com", "facebook.com", "amazon.com", "wikipedia.org",
  "twitter.com", "instagram.com", "linkedin.com", "reddit.com", "microsoft.com",
  "apple.com", "github.com", "stackoverflow.com", "netflix.com", "paypal.com",
  "ebay.com", "whatsapp.com", "zoom.us", "office.com", "live.com",
];

function calculateEntropy(str: string): number {
  const freq: Record<string, number> = {};
  for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
  const len = str.length;
  return -Object.values(freq).reduce((sum, f) => {
    const p = f / len;
    return sum + p * Math.log2(p);
  }, 0);
}

function extractURLFeatures(urlStr: string): URLFeatures {
  let parsed: URL;
  try {
    parsed = new URL(urlStr.startsWith("http") ? urlStr : `https://${urlStr}`);
  } catch {
    parsed = new URL("https://invalid.example.com");
  }

  const domain = parsed.hostname;
  const parts = domain.split(".");
  const tld = parts[parts.length - 1];
  const subdomainCount = Math.max(0, parts.length - 2);
  const specialChars = (urlStr.match(/[@!#$%^&*()_\-+=~`{}\[\]|\\:;"'<>,?]/g) || []).length;
  const hasIP = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(domain);
  const queryParams = parsed.searchParams.toString() ? parsed.searchParams.toString().split("&").length : 0;

  const lowerUrl = urlStr.toLowerCase();
  const foundKeywords = SUSPICIOUS_KEYWORDS.filter(k => lowerUrl.includes(k));

  return {
    domain,
    tld,
    path: parsed.pathname,
    queryParams,
    urlLength: urlStr.length,
    subdomainCount,
    hasHttps: parsed.protocol === "https:",
    hasIPAddress: hasIP,
    specialCharCount: specialChars,
    entropy: calculateEntropy(domain),
    suspiciousKeywords: foundKeywords,
  };
}

function runIndicators(features: URLFeatures, urlStr: string): AnalysisIndicator[] {
  const indicators: AnalysisIndicator[] = [];

  // 1. IP address in URL
  indicators.push({
    name: "IP Address Usage",
    description: "URL uses an IP address instead of a domain name",
    severity: "critical",
    detected: features.hasIPAddress,
    weight: 25,
  });

  // 2. No HTTPS
  indicators.push({
    name: "Missing HTTPS",
    description: "Connection is not encrypted with SSL/TLS",
    severity: "high",
    detected: !features.hasHttps,
    weight: 15,
  });

  // 3. Suspicious TLD
  indicators.push({
    name: "Suspicious TLD",
    description: `Top-level domain ".${features.tld}" is commonly used in phishing`,
    severity: "high",
    detected: SUSPICIOUS_TLDS.includes(features.tld),
    weight: 20,
  });

  // 4. Excessive subdomains
  indicators.push({
    name: "Excessive Subdomains",
    description: `${features.subdomainCount} subdomains detected (used to mimic legitimate sites)`,
    severity: "medium",
    detected: features.subdomainCount >= 3,
    weight: 15,
  });

  // 5. URL length
  indicators.push({
    name: "Abnormal URL Length",
    description: `URL is ${features.urlLength} characters long (phishing URLs tend to be lengthy)`,
    severity: "medium",
    detected: features.urlLength > 75,
    weight: 10,
  });

  // 6. Suspicious keywords
  indicators.push({
    name: "Phishing Keywords",
    description: features.suspiciousKeywords.length > 0
      ? `Contains: ${features.suspiciousKeywords.slice(0, 5).join(", ")}`
      : "No suspicious keywords found",
    severity: features.suspiciousKeywords.length > 2 ? "high" : "medium",
    detected: features.suspiciousKeywords.length > 0,
    weight: features.suspiciousKeywords.length > 2 ? 20 : 10,
  });

  // 7. High entropy domain
  indicators.push({
    name: "High Domain Entropy",
    description: `Domain randomness score: ${features.entropy.toFixed(2)} (random strings suggest auto-generated domains)`,
    severity: "medium",
    detected: features.entropy > 3.5,
    weight: 12,
  });

  // 8. Special characters
  indicators.push({
    name: "Excessive Special Characters",
    description: `${features.specialCharCount} special characters found (used for obfuscation)`,
    severity: "medium",
    detected: features.specialCharCount > 5,
    weight: 10,
  });

  // 9. @ symbol in URL
  indicators.push({
    name: "@ Symbol in URL",
    description: "The @ symbol can redirect to a different site than displayed",
    severity: "critical",
    detected: urlStr.includes("@"),
    weight: 25,
  });

  // 10. Homograph/typosquatting
  const typosquat = LEGITIMATE_DOMAINS.some(legit => {
    const legitBase = legit.split(".")[0];
    const domainBase = features.domain.split(".")[0];
    if (domainBase === legitBase) return false;
    // Simple Levenshtein-like check
    if (domainBase.includes(legitBase) && domainBase !== legitBase) return true;
    if (legitBase.includes(domainBase) && domainBase !== legitBase) return true;
    return false;
  });
  indicators.push({
    name: "Brand Impersonation",
    description: "Domain resembles a legitimate brand (possible typosquatting)",
    severity: "critical",
    detected: typosquat,
    weight: 30,
  });

  // 11. Data URI / encoded content
  indicators.push({
    name: "URL Encoding Abuse",
    description: "Excessive URL encoding used to hide true destination",
    severity: "high",
    detected: (urlStr.match(/%[0-9a-fA-F]{2}/g) || []).length > 3,
    weight: 15,
  });

  // 12. Multiple query parameters
  indicators.push({
    name: "Excessive Parameters",
    description: `${features.queryParams} query parameters detected`,
    severity: "low",
    detected: features.queryParams > 4,
    weight: 5,
  });

  return indicators;
}

export function analyzeURL(urlStr: string): AnalysisResult {
  const start = performance.now();
  const features = extractURLFeatures(urlStr);
  const indicators = runIndicators(features, urlStr);

  // Check if it's a known legitimate domain
  const isLegitimate = LEGITIMATE_DOMAINS.some(d => features.domain === d || features.domain.endsWith(`.${d}`));

  let riskScore = indicators
    .filter(i => i.detected)
    .reduce((sum, i) => sum + i.weight, 0);

  if (isLegitimate) riskScore = Math.max(0, riskScore - 50);
  riskScore = Math.min(100, riskScore);

  let riskLevel: RiskLevel = "safe";
  if (riskScore >= 60) riskLevel = "dangerous";
  else if (riskScore >= 30) riskLevel = "suspicious";

  return {
    url: urlStr,
    riskLevel,
    riskScore,
    indicators,
    timestamp: new Date(),
    analysisTimeMs: performance.now() - start,
    urlFeatures: features,
  };
}
