// Chrome Manifest V3 Service Worker for Threat Analyze
const BACKEND_URL = 'http://localhost:3000';

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0) return;
  const url = details.url;
  if (!url.startsWith('http')) return;

  try {
    const res = await fetch(`${BACKEND_URL}/api/url/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target: url })
    });
    if (!res.ok) return;
    const data = await res.json();

    if (data.overallRisk === 'MALICIOUS') {
      chrome.notifications.create({
        type: 'basic',
        iconUrl: 'icon.png',
        title: 'THREAT ANALYZE: BLOCKED HIGH RISK DESTINATION',
        message: `Interception triggered for: ${data.domain}. Reason: ${data.reasons[0]}`
      });
    }
  } catch (e) {
    console.warn('Threat Analyze shield offline or unreachable', e);
  }
});
