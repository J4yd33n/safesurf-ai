const SUSPICIOUS_KEYWORDS = ["login","signin","verify","account","secure","update","confirm","banking","paypal","ebay","amazon","apple","microsoft","google","netflix","facebook","instagram","whatsapp","telegram","password","credential","wallet","crypto","bitcoin","free","winner","prize","gift","reward","bonus","urgent","suspended","locked","expired","limited","click-here","act-now","immediately"];
const SUSPICIOUS_TLDS = ["tk","ml","ga","cf","gq","buzz","top","xyz","club","work","date","racing","win","bid","stream","download","loan","trade","cricket","party","science","review"];
const LEGITIMATE_DOMAINS = ["google.com","youtube.com","facebook.com","amazon.com","wikipedia.org","twitter.com","instagram.com","linkedin.com","reddit.com","microsoft.com","apple.com","github.com","stackoverflow.com","netflix.com","paypal.com","ebay.com","whatsapp.com","zoom.us","office.com","live.com"];

function entropy(s){const f={};for(const c of s)f[c]=(f[c]||0)+1;const n=s.length;return -Object.values(f).reduce((a,x)=>a+(x/n)*Math.log2(x/n),0);}
function sigmoid(x){return 1/(1+Math.exp(-x));}

function analyzeUrl(urlStr){
  let u;
  try{u=new URL(urlStr.startsWith("http")?urlStr:"https://"+urlStr);}catch{return null;}
  const host=u.hostname,parts=host.split("."),tld=parts[parts.length-1];
  const f={domain:host,tld,subdomains:Math.max(0,parts.length-2),https:u.protocol==="https:",hasIP:/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(host),length:urlStr.length,special:(urlStr.match(/[@!#$%^&*()_\-+=~`{}\[\]|\\:;"'<>,?]/g)||[]).length,entropy:entropy(host),keywords:SUSPICIOUS_KEYWORDS.filter(k=>urlStr.toLowerCase().includes(k)),encoded:(urlStr.match(/%[0-9a-fA-F]{2}/g)||[]).length,atSym:urlStr.includes("@")};
  const ind=[];
  const push=(name,detected,weight)=>ind.push({name,detected,weight});
  push("IP Address",f.hasIP,25);
  push("No HTTPS",!f.https,15);
  push("Suspicious TLD",SUSPICIOUS_TLDS.includes(f.tld),20);
  push("Excessive Subdomains",f.subdomains>=3,15);
  push("Long URL",f.length>75,10);
  push("Phishing Keywords",f.keywords.length>0,f.keywords.length>2?20:10);
  push("High Entropy",f.entropy>3.5,12);
  push("Special Chars",f.special>5,10);
  push("@ Symbol",f.atSym,25);
  const typo=LEGITIMATE_DOMAINS.some(d=>{const a=d.split(".")[0],b=f.domain.split(".")[0];return a!==b&&(a.includes(b)||b.includes(a));});
  push("Brand Impersonation",typo,30);
  push("URL Encoding Abuse",f.encoded>3,15);
  const legit=LEGITIMATE_DOMAINS.some(d=>f.domain===d||f.domain.endsWith("."+d));
  let score=ind.filter(i=>i.detected).reduce((s,i)=>s+i.weight,0);
  if(legit)score=Math.max(0,score-50);
  score=Math.min(100,score);
  const W={bias:-0.85,ip:2.4,noHttps:1.1,tld:1.6,sub:0.9,len:0.6,kw:0.45,ent:0.8,spec:0.55,at:2.2,brand:2.8,enc:1.0,legit:-3.5};
  let z=W.bias;
  if(f.hasIP)z+=W.ip;
  if(!f.https)z+=W.noHttps;
  if(SUSPICIOUS_TLDS.includes(f.tld))z+=W.tld;
  if(f.subdomains>=3)z+=W.sub;
  if(f.length>75)z+=W.len;
  z+=W.kw*Math.min(f.keywords.length,5);
  if(f.entropy>3.5)z+=W.ent;
  if(f.special>5)z+=W.spec;
  if(f.atSym)z+=W.at;
  if(typo)z+=W.brand;
  if(f.encoded>3)z+=W.enc;
  if(legit)z+=W.legit;
  const mlProb=sigmoid(z);
  const level=score>=60||mlProb>=0.6?"dangerous":score>=30||mlProb>=0.3?"suspicious":"safe";
  return {url:urlStr,score,level,mlProb,indicators:ind,features:f};
}

if(typeof self!=="undefined")self.PhishGuard={analyze:analyzeUrl};