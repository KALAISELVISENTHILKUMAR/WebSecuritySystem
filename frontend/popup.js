chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    let tabId = tabs[0].id;
    chrome.storage.local.get([`tab_${tabId}`, 'device_id', 'connection_status'], async (res) => {
        let d = res[`tab_${tabId}`];
        let device_id = res['device_id'] || 'Registering...';
        let connection_status = res['connection_status'] || 'UNKNOWN';
        const content = document.getElementById('content');
        let original_url = tabs[0].url;

        if (!d) {
            content.innerHTML = '<div style="text-align:center; color:#718096; padding: 20px 0; font-size:12px;">Evaluating connection security...</div>';
            try {
                let r = await fetch('http://127.0.0.1:8000/analyze', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ url: original_url, method: 'GET', source: 'browser_extension', device_id })
                });
                d = await r.json();
                d.original_url = original_url;
                chrome.storage.local.set({ [`tab_${tabId}`]: d });
            } catch (e) {
                content.innerHTML = '<div style="padding: 16px; background: #fff5f5; border: 1px solid #feb2b2; color: #c53030; font-size:12px; border-radius:4px;"><strong>Appliance Offline.</strong><br>Failed to bridge connection to NEXAF Backend API.</div>';
                return;
            }
        }

        const escapeHTML = (str) => {
            if (!str) return 'N/A';
            let p = document.createElement("p");
            p.appendChild(document.createTextNode(String(str)));
            return p.innerHTML;
        };

        const isBlock = d.decision === 'BLOCK';
        const colorClass = isBlock ? 'block' : 'allow';
        let ruleId = d.protection_rule?.rule_id || 'none';

        content.innerHTML = `
            <div class="row"><div class="label">Decision</div> <div class="val ${colorClass}">${escapeHTML(d.decision)}</div></div>
            <div class="row"><div class="label">Threat Category</div> <div class="val">${escapeHTML(d.attack_type || 'None')}</div></div>
            <div class="row"><div class="label">Risk Score</div> <div class="val">${d.risk_score}%</div></div>
            <div class="row"><div class="label">Protection Rule</div> <div class="val">${escapeHTML(ruleId)}</div></div>
            <div class="row"><div class="label">Analysis Node</div> <div class="val">${escapeHTML(d.ai_provider || 'local-rules')}</div></div>
            <div class="row"><div class="label">Device ID</div> <div class="val">${escapeHTML(device_id)}</div></div>
            <div class="row"><div class="label">Connection</div> <div class="val">${escapeHTML(connection_status)}</div></div>
            
            <div class="explanation-box">
                <strong>Diagnostic Note:</strong> ${escapeHTML(d.explanation || '')}
            </div>
            
            <div class="footer">
                [${escapeHTML(d.execution_layer || 'APPLICATION_LAYER')}] ${escapeHTML(d.action || '')}
            </div>
        `;
    });
});
