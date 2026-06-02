(async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const data = await chrome.storage.session.get(`scan_${tab.id}`);
  const result = data[`scan_${tab.id}`];
  document.getElementById("url").textContent = tab.url;
  const scoreEl = document.getElementById("score");
  const levelEl = document.getElementById("level");
  const indEl = document.getElementById("indicators");
  if (!result) {
    scoreEl.textContent = "—";
    scoreEl.className = "score safe";
    levelEl.textContent = "no scan data";
    indEl.innerHTML = '<div style="font-size:11px;color:#8a9099;text-align:center;">Reload the page to scan.</div>';
    return;
  }
  scoreEl.textContent = result.score;
  scoreEl.className = "score " + result.level;
  levelEl.textContent = `${result.level} · ML ${(result.mlProb * 100).toFixed(0)}%`;
  const detected = result.indicators.filter((i) => i.detected);
  indEl.innerHTML = detected.length === 0
    ? '<div style="font-size:11px;color:#2ecc71;text-align:center;">✓ No risk indicators detected</div>'
    : detected.map((i) => `<div class="indicator">⚠ ${i.name} (+${i.weight})</div>`).join("");
})();