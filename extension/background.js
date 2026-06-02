importScripts("analyzer.js");

chrome.webNavigation.onCommitted.addListener(async (details) => {
  if (details.frameId !== 0) return;
  if (!details.url.startsWith("http")) return;
  const result = self.PhishGuard.analyze(details.url);
  if (!result) return;
  await chrome.storage.session.set({ [`scan_${details.tabId}`]: result });
  const badge = result.level === "dangerous" ? "!" : result.level === "suspicious" ? "?" : "";
  const color = result.level === "dangerous" ? "#e74c3c" : result.level === "suspicious" ? "#f39c12" : "#2ecc71";
  await chrome.action.setBadgeText({ tabId: details.tabId, text: badge });
  await chrome.action.setBadgeBackgroundColor({ tabId: details.tabId, color });
  if (result.level === "dangerous") {
    try {
      chrome.notifications.create(`pg-${details.tabId}-${Date.now()}`, {
        type: "basic",
        iconUrl: "icon.png",
        title: "⚠️ PhishGuard: Dangerous URL",
        message: `${result.features.domain} scored ${result.score}/100. Verify before entering credentials.`,
        priority: 2,
      });
    } catch (e) { /* notifications optional */ }
  }
});