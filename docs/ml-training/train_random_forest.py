"""PhishGuard Random Forest training script.

Usage:
    python train_random_forest.py --input urls_labeled.csv --output weights.json

Input CSV: url,label  (label: 1=phishing, 0=legit)
"""
import argparse, json, math, re
from urllib.parse import urlparse
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from sklearn.model_selection import train_test_split

SUSPICIOUS_KEYWORDS = ["login","signin","verify","account","secure","update","confirm","banking","paypal","apple","microsoft","google","password","wallet","crypto","free","winner","prize","urgent","suspended","locked"]
SUSPICIOUS_TLDS = {"tk","ml","ga","cf","gq","buzz","top","xyz","club","work","date","racing","win","bid","stream","loan"}
LEGIT_DOMAINS = {"google.com","youtube.com","facebook.com","amazon.com","wikipedia.org","twitter.com","github.com","microsoft.com","apple.com","paypal.com","netflix.com"}

FEATURE_NAMES = ["hasIPAddress","noHttps","suspiciousTld","excessiveSubdomains","longUrl","suspiciousKeywordCount","highEntropy","excessiveSpecialChars","atSymbol","brandImpersonation","urlEncodingAbuse","manyParams","isLegitimate"]

def entropy(s):
    if not s: return 0.0
    f = {}
    for c in s: f[c] = f.get(c, 0) + 1
    n = len(s)
    return -sum((c/n) * math.log2(c/n) for c in f.values())

def extract(url):
    try: u = urlparse(url if url.startswith("http") else "https://" + url)
    except Exception: return [0]*len(FEATURE_NAMES)
    host = u.hostname or ""
    parts = host.split(".")
    tld = parts[-1] if parts else ""
    subs = max(0, len(parts) - 2)
    kw = sum(1 for k in SUSPICIOUS_KEYWORDS if k in url.lower())
    special = len(re.findall(r"[@!#$%^&*()_\-+=~`{}\[\]|\\:;\"'<>,?]", url))
    has_ip = bool(re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", host))
    encoded = len(re.findall(r"%[0-9a-fA-F]{2}", url))
    is_legit = any(host == d or host.endswith("." + d) for d in LEGIT_DOMAINS)
    base = parts[0] if parts else ""
    typo = any(d.split(".")[0] != base and (d.split(".")[0] in base or base in d.split(".")[0]) for d in LEGIT_DOMAINS)
    return [
        int(has_ip), int(u.scheme != "https"), int(tld in SUSPICIOUS_TLDS),
        int(subs >= 3), int(len(url) > 75), min(kw, 5),
        int(entropy(host) > 3.5), int(special > 5), int("@" in url),
        int(typo), int(encoded > 3),
        int((len(u.query.split("&")) > 4) if u.query else 0),
        int(is_legit),
    ]

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True)
    ap.add_argument("--output", default="weights.json")
    args = ap.parse_args()
    df = pd.read_csv(args.input)
    X = np.array([extract(u) for u in df["url"]])
    y = df["label"].astype(int).values
    X_tr, X_te, y_tr, y_te = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    rf = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42).fit(X_tr, y_tr)
    print("=== Random Forest ===")
    print(classification_report(y_te, rf.predict(X_te), target_names=["legit","phish"]))
    print("Confusion matrix:\n", confusion_matrix(y_te, rf.predict(X_te)))
    print("ROC-AUC:", roc_auc_score(y_te, rf.predict_proba(X_te)[:,1]))
    print("Feature importances:")
    for name, imp in sorted(zip(FEATURE_NAMES, rf.feature_importances_), key=lambda x: -x[1]):
        print(f"  {name:28s} {imp:.4f}")
    lr = LogisticRegression(max_iter=1000, class_weight="balanced").fit(X_tr, y_tr)
    print("\n=== Logistic Regression (exported) ===")
    print(classification_report(y_te, lr.predict(X_te), target_names=["legit","phish"]))
    weights = {"bias": float(lr.intercept_[0])}
    for n, c in zip(FEATURE_NAMES, lr.coef_[0]):
        weights[n] = round(float(c), 4)
    with open(args.output, "w") as f:
        json.dump(weights, f, indent=2)
    print(f"\nWeights → {args.output}. Paste into src/lib/phishing-analyzer.ts → ML_WEIGHTS")

if __name__ == "__main__":
    main()