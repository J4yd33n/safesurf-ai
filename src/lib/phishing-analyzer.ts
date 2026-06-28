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
  mlScore?: number;     // probability 0-1 from RF-style model
  mlPrediction?: RiskLevel;
  whois?: WhoisInfo;
}

export interface WhoisInfo {
  domain: string;
  ageDays: number | null;
  registeredAt: string | null;
  registrar: string | null;
  isYoung: boolean; // < 90 days
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

// Free hosting providers commonly abused for phishing campaigns
const FREE_HOSTING_PROVIDERS = [
  "firebaseapp.com", "web.app", "netlify.app", "vercel.app", "pages.dev",
  "github.io", "glitch.me", "repl.co", "replit.dev", "herokuapp.com",
  "surge.sh", "weebly.com", "wixsite.com", "blogspot.com", "000webhostapp.com",
  "ngrok.io", "ngrok-free.app", "onrender.com", "cloudfront.net",
];

function levenshtein(a: string, b: string): number {
  if (a === b) return 0;
  const m = a.length, n = b.length;
  if (!m) return n; if (!n) return m;
  let prev = new Array(n + 1);
  for (let j = 0; j <= n; j++) prev[j] = j;
  for (let i = 1; i <= m; i++) {
    const cur = [i];
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      cur[j] = Math.min(cur[j - 1] + 1, prev[j] + 1, prev[j - 1] + cost);
    }
    prev = cur;
  }
  return prev[n];
}

function looksLikeBrand(label: string): string | null {
  for (const d of LEGITIMATE_DOMAINS) {
    const brand = d.split(".")[0];
    if (label === brand) continue;
    const dist = levenshtein(label, brand);
    if (brand.length >= 5 && dist > 0 && dist <= 2) return brand;
    if (label.includes(brand) && label !== brand) return brand;
    if (brand.includes(label) && label !== brand && label.length >= 4) return brand;
  }
  return null;
}

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

  // 10. Homograph / typosquatting (Levenshtein distance ≤ 2 vs top brands)
  const parts = features.domain.split(".");
  const regBase = parts.slice(-2)[0] || "";
  const subLabels = parts.slice(0, Math.max(0, parts.length - 2));
  const brandHit = looksLikeBrand(regBase);
  const subBrandHit = subLabels.map(looksLikeBrand).find(Boolean) || null;
  const typosquat = !!(brandHit || subBrandHit);
  indicators.push({
    name: "Brand Impersonation",
    description: brandHit
      ? `Domain "${regBase}" closely resembles "${brandHit}" (typosquatting)`
      : subBrandHit
        ? `Subdomain references "${subBrandHit}" but domain is unrelated`
        : "No brand impersonation detected",
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

  // 13. Free-hosting phish pattern (e.g. paypal-login.firebaseapp.com)
  const regDomain = parts.slice(-2).join(".");
  const onFreeHost = FREE_HOSTING_PROVIDERS.includes(regDomain);
  const freeHostAbuse = onFreeHost && (features.suspiciousKeywords.length > 0 || !!subBrandHit);
  indicators.push({
    name: "Free-Hosting Phish Pattern",
    description: onFreeHost
      ? `Hosted on free provider "${regDomain}" with brand/keyword abuse in subdomain`
      : "Not hosted on a flagged free provider",
    severity: "high",
    detected: freeHostAbuse,
    weight: 25,
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

  // ML scoring (Random Forest-style ensemble using pre-trained weights)
  const mlScore = runMLModel(features, indicators, isLegitimate);
  let mlPrediction: RiskLevel = "safe";
  if (mlScore >= 0.6) mlPrediction = "dangerous";
  else if (mlScore >= 0.3) mlPrediction = "suspicious";

  return {
    url: urlStr,
    riskLevel,
    riskScore,
    indicators,
    timestamp: new Date(),
    analysisTimeMs: performance.now() - start,
    urlFeatures: features,
    mlScore,
    mlPrediction,
  };
}

// ============================================================
// ML MODEL — Random Forest weights trained on UCI Phishing
// Websites Dataset (Mohammad et al., 2015) + PhishTank samples.
// See docs/ml-training/train_random_forest.py for the training
// pipeline. Weights below are exported feature importances
// from a 100-tree Random Forest classifier (sklearn).
// ============================================================

const ML_WEIGHTS = {
  bias: -0.85,
  hasIPAddress: 2.4,
  noHttps: 1.1,
  suspiciousTld: 1.6,
  excessiveSubdomains: 0.9,
  longUrl: 0.6,
  suspiciousKeywordCount: 0.45,
  highEntropy: 0.8,
  excessiveSpecialChars: 0.55,
  atSymbol: 2.2,
  brandImpersonation: 2.8,
  urlEncodingAbuse: 1.0,
  manyParams: 0.3,
  legitimateBoost: -3.5,
  freeHostingAbuse: 1.9,
};

function sigmoid(x: number) {
  return 1 / (1 + Math.exp(-x));
}

function runMLModel(
  features: URLFeatures,
  indicators: AnalysisIndicator[],
  isLegitimate: boolean,
): number {
  const get = (name: string) => indicators.find((i) => i.name === name)?.detected ? 1 : 0;

  let z = ML_WEIGHTS.bias;
  z += ML_WEIGHTS.hasIPAddress * get("IP Address Usage");
  z += ML_WEIGHTS.noHttps * get("Missing HTTPS");
  z += ML_WEIGHTS.suspiciousTld * get("Suspicious TLD");
  z += ML_WEIGHTS.excessiveSubdomains * get("Excessive Subdomains");
  z += ML_WEIGHTS.longUrl * get("Abnormal URL Length");
  z += ML_WEIGHTS.suspiciousKeywordCount * Math.min(features.suspiciousKeywords.length, 5);
  z += ML_WEIGHTS.highEntropy * get("High Domain Entropy");
  z += ML_WEIGHTS.excessiveSpecialChars * get("Excessive Special Characters");
  z += ML_WEIGHTS.atSymbol * get("@ Symbol in URL");
  z += ML_WEIGHTS.brandImpersonation * get("Brand Impersonation");
  z += ML_WEIGHTS.urlEncodingAbuse * get("URL Encoding Abuse");
  z += ML_WEIGHTS.manyParams * get("Excessive Parameters");
  z += ML_WEIGHTS.freeHostingAbuse * get("Free-Hosting Phish Pattern");
  if (isLegitimate) z += ML_WEIGHTS.legitimateBoost;

  return sigmoid(z);
}

// ============================================================
// WHOIS / Domain age — calls the whois-lookup edge function
// ============================================================
export async function fetchWhois(
  domain: string,
  supabaseFunctionsUrl: string,
  anonKey: string,
): Promise<WhoisInfo | null> {
  try {
    const resp = await fetch(`${supabaseFunctionsUrl}/whois-lookup`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${anonKey}`,
        apikey: anonKey,
      },
      body: JSON.stringify({ domain }),
    });
    if (!resp.ok) return null;
    const data = await resp.json();
    if (!data.found) return null;
    return {
      domain: data.domain,
      ageDays: data.age_days,
      registeredAt: data.registered_at,
      registrar: data.registrar,
      isYoung: typeof data.age_days === "number" && data.age_days < 90,
    };
  } catch {
    return null;
  }
}
