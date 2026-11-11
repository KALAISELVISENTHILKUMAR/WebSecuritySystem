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

const escapeHTML = (str) => {
    if (!str) return 'N/A';
    let p = document.createElement("p");
    p.appendChild(document.createTextNode(String(str)));
    return p.innerHTML;
};

chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
    if (!tabs || tabs.length === 0) return;
    const tab = tabs[0];
    const tabId = tab.id;
    const original_url = tab.url || '';
    const content = document.getElementById('content');
    const device_id = await getDeviceId();

    chrome.storage.local.get([`tab_${tabId}`, 'connection_status'], async (res) => {
        let d = res[`tab_${tabId}`];
        let connection_status = res['connection_status'] || 'ONLINE';

        // Check if page is an internal extension block page
        if (!d && original_url.includes('block.html')) {
            try {
                const u = new URL(original_url);
                d = {
                    decision: u.searchParams.get('decision') || 'BLOCK',
                    attack_type: u.searchParams.get('attack_type') || 'Detected Threat',
                    risk_score: parseInt(u.searchParams.get('risk_score') || '90'),
                    explanation: u.searchParams.get('explanation') || 'Request intercepted by NEXAF policy.',
                    action: u.searchParams.get('action') || 'DROP_REQUEST',
                    execution_layer: u.searchParams.get('execution_layer') || 'APPLICATION_LAYER_DROP',
                    protection_rule: { rule_id: u.searchParams.get('rule_id') || 'none' },
                    ai_provider: u.searchParams.get('ai_provider') || 'local-rules'
                };
            } catch (e) { }
        }

        // If internal browser page or dashboard
        if (!d && (!original_url.startsWith('http://') && !original_url.startsWith('https://'))) {
            content.innerHTML = `
                <div class="row"><div class="label">Decision</div> <div class="val allow">SYSTEM</div></div>
                <div class="row"><div class="label">Threat Category</div> <div class="val">Browser Internal</div></div>
                <div class="row"><div class="label">Device ID</div> <div class="val">${escapeHTML(device_id)}</div></div>
                <div class="row"><div class="label">Connection</div> <div class="val">${escapeHTML(connection_status)}</div></div>
                <div class="explanation-box">
                    <strong>Diagnostic Note:</strong> Internal browser page. NEXAF is active and monitoring network traffic.
                </div>
            `;
            return;
        }

        // If not cached yet, analyze on the fly
        if (!d) {
            content.innerHTML = '<div style="text-align:center; color:#718096; padding: 20px 0; font-size:12px;">Evaluating connection security...</div>';
            try {
                let r = await fetch('http://127.0.0.1:8000/analyze', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url: original_url, method: 'GET', source: 'browser_extension', device_id })
                });
                if (!r.ok) throw new Error('Analysis server returned error ' + r.status);
                d = await r.json();
                d.original_url = original_url;
                chrome.storage.local.set({ [`tab_${tabId}`]: d });
            } catch (e) {
                content.innerHTML = '<div style="padding: 16px; background: #fff5f5; border: 1px solid #feb2b2; color: #c53030; font-size:12px; border-radius:4px;"><strong>Appliance Offline.</strong><br>Failed to bridge connection to NEXAF Backend API (http://127.0.0.1:8000).</div>';
                return;
            }
        }

        const isBlock = d.decision === 'BLOCK';
        const colorClass = isBlock ? 'block' : 'allow';
        const ruleId = d.protection_rule?.rule_id || 'none';

        content.innerHTML = `
            <div class="row"><div class="label">Decision</div> <div class="val ${colorClass}">${escapeHTML(d.decision)}</div></div>
            <div class="row"><div class="label">Threat Category</div> <div class="val">${escapeHTML(d.attack_type || 'None')}</div></div>
            <div class="row"><div class="label">Risk Score</div> <div class="val">${d.risk_score || 0}%</div></div>
            <div class="row"><div class="label">Protection Rule</div> <div class="val">${escapeHTML(ruleId)}</div></div>
            <div class="row"><div class="label">Analysis Node</div> <div class="val">${escapeHTML(d.ai_provider || 'local-rules')}</div></div>
            <div class="row"><div class="label">Device ID</div> <div class="val">${escapeHTML(device_id)}</div></div>
            <div class="row"><div class="label">Connection</div> <div class="val">${escapeHTML(connection_status)}</div></div>
            
            <div class="explanation-box">
                <strong>Diagnostic Note:</strong> ${escapeHTML(d.explanation || 'No security explanation provided.')}
            </div>
            
            <div class="footer">
                [${escapeHTML(d.execution_layer || 'APPLICATION_LAYER')}] ${escapeHTML(d.action || 'ALLOW_REQUEST')}
            </div>
        `;
    });
});
