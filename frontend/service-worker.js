const API = 'http://127.0.0.1:8000';

// Retrieve or initialize unique device ID in extension local storage
async function getDeviceId() {
  try {
    const data = await chrome.storage.local.get(['device_id']);
    if (data && data.device_id) return data.device_id;
    const newId = 'NEXAF-DEV-' + Math.random().toString(36).substr(2, 9).toUpperCase();
    await chrome.storage.local.set({ device_id: newId });
    return newId;
  } catch (e) {
    return 'NEXAF-DEV-DEFAULT';
  }
}

// Register device with NEXAF appliance backend
async function registerDevice() {
  try {
    const device_id = await getDeviceId();
    const isEdge = navigator.userAgent.includes('Edg');
    const isWindows = navigator.userAgent.includes('Windows');
    const isMac = navigator.userAgent.includes('Mac');
    const browserName = isEdge ? 'Edge' : 'Chrome';
    const osName = isWindows ? 'Windows' : isMac ? 'macOS' : 'Linux';
    const versionMatch = navigator.userAgent.match(/(?:Chrome|Edg)\/([0-9.]+)/);
    const browserVersion = versionMatch ? versionMatch[1] : 'Unknown';

    const r = await fetch(API + '/devices/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        device_id,
        device_name: `${browserName} Device`,
        browser_name: browserName,
        browser_version: browserVersion,
        os_name: osName,
        extension_version: chrome.runtime.getManifest().version,
        user_agent: navigator.userAgent
      })
    });
    if (r.ok) {
      await chrome.storage.local.set({ connection_status: 'ONLINE' });
    }
  } catch (e) {
    console.error('NEXAF registration failed:', e);
    await chrome.storage.local.set({ connection_status: 'OFFLINE' });
  }
}

// Send periodic heartbeat to keep appliance connection verified
async function sendHeartbeat() {
  try {
    const device_id = await getDeviceId();
    let current_tab_url = '';
    try {
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
      if (tabs && tabs.length > 0 && tabs[0].url) {
        current_tab_url = tabs[0].url;
      }
    } catch (e) { }

    const r = await fetch(API + '/devices/heartbeat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        device_id,
        extension_version: chrome.runtime.getManifest().version,
        current_tab_url,
        status: 'ONLINE'
      })
    });
    if (r.ok) {
      await chrome.storage.local.set({ connection_status: 'ONLINE' });
    } else if (r.status === 404) {
      await registerDevice();
    }
  } catch (e) {
    await chrome.storage.local.set({ connection_status: 'OFFLINE' });
  }
}

// Filter internal URLs (chrome://, edge://, about:blank, etc.) and NEXAF dashboard / backend
function shouldIgnoreUrl(url) {
  if (!url || typeof url !== 'string') return true;
  if (!url.startsWith('http://') && !url.startsWith('https://')) return true;

  try {
    const parsed = new URL(url);
    const host = parsed.hostname;
    const port = parsed.port;
    // Exclude NEXAF dashboard (port 5500) and backend API (port 8000) so they don't pollute logs
    if ((host === '127.0.0.1' || host === 'localhost') && (port === '5500' || port === '8000')) {
      return true;
    }
  } catch (e) {
    return true;
  }
  return false;
}

// In-memory cache to deduplicate rapid duplicate requests for the same tab & URL (e.g. within 2.5s)
const recentAnalysis = new Map();

// Main enforcement analyzer function
async function analyzeUrl(url, tabId) {
  if (shouldIgnoreUrl(url)) return;

  const key = `${tabId}:${url}`;
  const now = Date.now();
  if (recentAnalysis.has(key) && (now - recentAnalysis.get(key) < 2500)) {
    return;
  }
  recentAnalysis.set(key, now);

  // Evict old entries if cache grows
  if (recentAnalysis.size > 200) {
    for (const [k, ts] of recentAnalysis.entries()) {
      if (now - ts > 10000) recentAnalysis.delete(k);
    }
  }

  try {
    const device_id = await getDeviceId();
    const r = await fetch(API + '/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        url: url,
        method: 'GET',
        source: 'browser_extension',
        device_id: device_id,
        user_agent: navigator.userAgent
      })
    });

    if (!r.ok) return;
    const d = await r.json();

    if (tabId && tabId > 0) {
      await chrome.storage.local.set({ [`tab_${tabId}`]: { ...d, original_url: url } });

      // Visual badge indicator on extension icon
      if (chrome.action && chrome.action.setBadgeText) {
        if (d.decision === 'BLOCK') {
          chrome.action.setBadgeText({ text: '!', tabId }).catch(() => {});
          chrome.action.setBadgeBackgroundColor({ color: '#ef4444', tabId }).catch(() => {});
        } else {
          chrome.action.setBadgeText({ text: 'OK', tabId }).catch(() => {});
          chrome.action.setBadgeBackgroundColor({ color: '#10b981', tabId }).catch(() => {});
        }
      }
    }

    if (d.decision === 'BLOCK' && tabId && tabId > 0) {
      const queryParams = new URLSearchParams({
        decision: d.decision,
        attack_type: d.attack_type,
        risk_score: d.risk_score,
        explanation: d.explanation,
        action: d.action,
        execution_layer: d.execution_layer || 'APPLICATION_LAYER_DROP',
        original_url: url,
        rule_id: (d.protection_rule && d.protection_rule.rule_id) ? d.protection_rule.rule_id : 'none',
        ai_provider: d.ai_provider,
        device_id: device_id
      }).toString();

      const blockedUrl = chrome.runtime.getURL('block.html') + '?' + queryParams;
      chrome.tabs.update(tabId, { url: blockedUrl }).catch(err => {
        console.warn('Could not redirect blocked tab:', err);
      });
    }
  } catch (e) {
    console.error('NEXAF extension analysis failed:', e);
  }
}

// ---------------- Navigation Listeners ----------------
// 1. Initial main frame navigation (before page loads)
chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  if (details.frameId !== 0) return;
  if (!details.url) return;
  analyzeUrl(details.url, details.tabId);
});

// 2. SPA history navigations (e.g., pushState/replaceState on web apps)
chrome.webNavigation.onHistoryStateUpdated.addListener((details) => {
  if (details.frameId !== 0) return;
  if (!details.url) return;
  analyzeUrl(details.url, details.tabId);
});

// 3. Tab URL updates (covers omnibox input, programmatic redirects, etc.)
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.url) {
    analyzeUrl(changeInfo.url, tabId);
  }
});

// 4. Clean up state when tab is closed
chrome.tabs.onRemoved.addListener((tabId) => {
  chrome.storage.local.remove(`tab_${tabId}`).catch(() => {});
  for (const key of recentAnalysis.keys()) {
    if (key.startsWith(`${tabId}:`)) {
      recentAnalysis.delete(key);
    }
  }
});

// ---------------- Lifecycle & Alarms ----------------
chrome.runtime.onInstalled.addListener(() => {
  registerDevice().then(() => sendHeartbeat());
});

chrome.runtime.onStartup.addListener(() => {
  registerDevice().then(() => sendHeartbeat());
});

if (chrome.alarms) {
  try {
    chrome.alarms.create('heartbeat', { periodInMinutes: 0.5 });
    chrome.alarms.onAlarm.addListener((alarm) => {
      if (alarm.name === 'heartbeat') sendHeartbeat();
    });
  } catch (err) {
    console.warn('Alarms setup warning:', err);
  }
}

// Startup heartbeat and registration
registerDevice().then(() => sendHeartbeat());
