const API = 'http://127.0.0.1:8000';

async function getDeviceId() {
  const data = await chrome.storage.local.get(['device_id']);
  if (data.device_id) return data.device_id;
  const newId = 'NEXAF-DEV-' + Math.random().toString(36).substr(2, 9).toUpperCase();
  await chrome.storage.local.set({ device_id: newId });
  return newId;
}

async function registerDevice() {
  const device_id = await getDeviceId();
  try {
    await fetch(API + '/devices/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        device_id,
        device_name: 'Chrome Extension',
        browser_name: 'Chrome',
        browser_version: navigator.userAgent.match(/Chrome\/([0-9.]+)/)?.[1] || 'Unknown',
        os_name: navigator.userAgent.includes('Windows') ? 'Windows' : navigator.userAgent.includes('Mac') ? 'macOS' : 'Linux',
        extension_version: chrome.runtime.getManifest().version,
        user_agent: navigator.userAgent
      })
    });
  } catch (e) {
    console.error('NEXAF registration failed:', e);
  }
}

async function sendHeartbeat() {
  const device_id = await getDeviceId();
  let current_tab_url = '';
  try {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tabs.length > 0) current_tab_url = tabs[0].url || '';
  } catch (e) { }

  try {
    await fetch(API + '/devices/heartbeat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        device_id,
        extension_version: chrome.runtime.getManifest().version,
        current_tab_url,
        status: 'ONLINE'
      })
    });
    chrome.storage.local.set({ connection_status: 'ONLINE' });
  } catch (e) {
    chrome.storage.local.set({ connection_status: 'OFFLINE' });
  }
}

chrome.runtime.onInstalled.addListener(() => { registerDevice(); });
chrome.runtime.onStartup.addListener(() => { registerDevice(); });

chrome.alarms.create('heartbeat', { periodInMinutes: 0.75 });
chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === 'heartbeat') sendHeartbeat();
});
sendHeartbeat();

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  // Only analyze main frame navigation and skip our own simulator/dashboard/blocked pages
  if (details.frameId !== 0) return;
  if (details.url.startsWith('chrome') || details.url.includes('127.0.0.1:5500') || details.url.includes('localhost:5500')) return;

  try {
    const device_id = await getDeviceId();
    let r = await fetch(API + '/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        url: details.url,
        method: 'GET',
        source: 'browser_extension',
        device_id,
        user_agent: navigator.userAgent
      })
    });

    if (!r.ok) return;
    let d = await r.json();

    chrome.storage.local.set({ [`tab_${details.tabId}`]: { ...d, original_url: details.url } });

    if (d.decision === 'BLOCK') {
      let queryParams = new URLSearchParams({
        decision: d.decision,
        attack_type: d.attack_type,
        risk_score: d.risk_score,
        explanation: d.explanation,
        action: d.action,
        execution_layer: d.execution_layer || 'APPLICATION_LAYER_DROP',
        original_url: details.url,
        rule_id: (d.protection_rule && d.protection_rule.rule_id) ? d.protection_rule.rule_id : 'none',
        ai_provider: d.ai_provider,
        device_id: device_id
      }).toString();

      let blockedUrl = chrome.runtime.getURL('block.html') + '?' + queryParams;
      chrome.tabs.update(details.tabId, { url: blockedUrl });
    }
  } catch (e) {
    console.error('NEXAF extension analysis failed:', e);
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  chrome.storage.local.remove(`tab_${tabId}`);
});
