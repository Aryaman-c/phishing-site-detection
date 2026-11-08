const BACKEND_HEALTH_URL = 'http://127.0.0.1:8000/health';
const BACKEND_PREDICT_URL = 'http://127.0.0.1:8000/predict';

document.addEventListener('DOMContentLoaded', async () => {
  const statusPill = document.getElementById('backend-status');
  const currentUrlEl = document.getElementById('current-url');
  const verdictBox = document.getElementById('verdict-box');
  const verdictIcon = document.getElementById('verdict-icon');
  const verdictText = document.getElementById('verdict-text');
  const confidenceEl = document.getElementById('current-confidence');
  const latencyEl = document.getElementById('current-latency');

  const manualInput = document.getElementById('manual-url-input');
  const btnInspect = document.getElementById('btn-inspect');
  const manualResult = document.getElementById('manual-result');
  const manualVerdict = document.getElementById('manual-verdict');
  const manualMetrics = document.getElementById('manual-metrics');

  // 1. Check Backend Status
  try {
    const res = await fetch(BACKEND_HEALTH_URL);
    if (res.ok) {
      statusPill.textContent = 'ONLINE';
      statusPill.className = 'status-pill status-online';
    } else {
      throw new Error();
    }
  } catch (err) {
    statusPill.textContent = 'OFFLINE';
    statusPill.className = 'status-pill status-offline';
  }

  // 2. Query Current Active Tab
  chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
    if (!tabs || tabs.length === 0) return;
    const activeTab = tabs[0];
    const url = activeTab.url || '';

    currentUrlEl.textContent = url || 'Blank Page';

    if (url.startsWith('chrome') || url.startsWith('about:')) {
      verdictBox.className = 'verdict-banner safe';
      verdictIcon.textContent = '✓';
      verdictText.textContent = 'INTERNAL BROWSER PAGE';
      confidenceEl.textContent = '100%';
      latencyEl.textContent = '0 ms';
      return;
    }

    // Check cached result from background script
    chrome.storage.local.get([`tab_${activeTab.id}`], async (result) => {
      let data = result[`tab_${activeTab.id}`];

      if (!data) {
        // Query prediction directly if not cached
        try {
          const res = await fetch(BACKEND_PREDICT_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: url })
          });
          if (res.ok) {
            data = await res.json();
            chrome.storage.local.set({ [`tab_${activeTab.id}`]: data });
          }
        } catch (e) {
          verdictBox.className = 'verdict-banner safe';
          verdictIcon.textContent = 'ℹ';
          verdictText.textContent = 'BACKEND OFFLINE';
          return;
        }
      }

      if (data) {
        if (data.is_phishing) {
          verdictBox.className = 'verdict-banner phishing';
          verdictIcon.textContent = '⚠️';
          verdictText.textContent = 'PHISHING DETECTED';
        } else {
          verdictBox.className = 'verdict-banner safe';
          verdictIcon.textContent = '✓';
          verdictText.textContent = 'SECURE & SAFE';
        }
        confidenceEl.textContent = `${data.confidence.toFixed(1)}%`;
        latencyEl.textContent = `${data.latency_ms.toFixed(1)} ms`;
      }
    });
  });

  // 3. Manual URL Inspector
  btnInspect.addEventListener('click', async () => {
    const testUrl = manualInput.value.trim();
    if (!testUrl) return;

    btnInspect.disabled = true;
    btnInspect.textContent = '...';

    try {
      const res = await fetch(BACKEND_PREDICT_URL, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: testUrl })
      });

      if (!res.ok) throw new Error('Inference error');
      const data = await res.json();

      manualResult.classList.remove('hidden');
      if (data.is_phishing) {
        manualVerdict.textContent = 'PHISHING';
        manualVerdict.className = 'tag-badge phishing';
      } else {
        manualVerdict.textContent = 'SAFE';
        manualVerdict.className = 'tag-badge safe';
      }
      manualMetrics.textContent = `${data.confidence.toFixed(1)}% | ${data.latency_ms.toFixed(1)} ms`;
    } catch (err) {
      manualResult.classList.remove('hidden');
      manualVerdict.textContent = 'ERROR';
      manualVerdict.className = 'tag-badge phishing';
      manualMetrics.textContent = 'Backend unreachable';
    } finally {
      btnInspect.disabled = false;
      btnInspect.textContent = 'Inspect';
    }
  });
});

