/**
 * Phishing Site Detection - Background Service Worker
 * Intercepts navigation requests and interacts asynchronously with FastAPI backend
 * to classify URLs and block phishing attempts instantly (<50ms pipeline).
 */

const BACKEND_API_URL = 'http://127.0.0.1:8000/predict';

// Intercept navigation requests before webpage loads
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  // Only inspect top-level frame navigation
  if (details.frameId !== 0) return;

  const url = details.url;
  if (!url || isInternalUrl(url)) return;

  try {
    const result = await classifyUrl(url);
    if (!result) return;

    // Cache scan result for popup UI
    await chrome.storage.local.set({ [`tab_${details.tabId}`]: result });

    if (result.is_phishing) {
      // Instantly block phishing attempts by redirecting to safety warning
      const blockedPageUrl = chrome.runtime.getURL(
        `blocked.html?url=${encodeURIComponent(url)}&confidence=${result.confidence}&latency=${result.latency_ms}`
      );

      chrome.tabs.update(details.tabId, { url: blockedPageUrl });
      updateBadge(details.tabId, 'WARN', '#ef4444');
    } else {
      updateBadge(details.tabId, 'OK', '#10b981');
    }
  } catch (error) {
    console.debug('Background inference check bypassed:', error.message);
  }
});

// Helper: ignore internal Chrome URLs
function isInternalUrl(url) {
  return (
    url.startsWith('chrome://') ||
    url.startsWith('chrome-extension://') ||
    url.startsWith('about:') ||
    url.startsWith('devtools://') ||
    url.startsWith('view-source:')
  );
}

// Asynchronously classify URL via high-performance FastAPI backend
async function classifyUrl(url, htmlContent = null) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 1500); // 1.5s max network timeout

  try {
    const response = await fetch(BACKEND_API_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: url, html: htmlContent }),
      signal: controller.signal
    });

    clearTimeout(timeoutId);
    if (!response.ok) {
      throw new Error(`Server returned HTTP ${response.status}`);
    }

    return await response.json();
  } catch (err) {
    clearTimeout(timeoutId);
    return null;
  }
}

// Update icon badge status
function updateBadge(tabId, text, color) {
  try {
    chrome.action.setBadgeText({ tabId, text });
    chrome.action.setBadgeBackgroundColor({ tabId, color });
  } catch (e) {
    // Tab may be closed or navigating
  }
}

// Clean up stored tab scan results on tab close
chrome.tabs.onRemoved.addListener((tabId) => {
  chrome.storage.local.remove([`tab_${tabId}`]);
});

// Message listener for popup and content script requests
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === 'CHECK_URL') {
    classifyUrl(request.url, request.html).then((result) => {
      sendResponse(result);
    });
    return true; // Keep message channel open for async response
  }

  if (request.action === 'SUSPICIOUS_PAGE_PARAMETERS') {
    // Content script reported suspicious form/parameters
    const tabId = sender.tab ? sender.tab.id : null;
    if (tabId && request.url) {
      classifyUrl(request.url, request.html).then((result) => {
        if (result && result.is_phishing) {
          const blockedPageUrl = chrome.runtime.getURL(
            `blocked.html?url=${encodeURIComponent(request.url)}&confidence=${result.confidence}&latency=${result.latency_ms}`
          );
          chrome.tabs.update(tabId, { url: blockedPageUrl });
          updateBadge(tabId, 'WARN', '#ef4444');
        }
      });
    }
  }
});

