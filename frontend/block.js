const escapeHTML = (str) => {
    if (!str) return 'N/A';
    let p = document.createElement("p");
    p.appendChild(document.createTextNode(String(str)));
    return p.innerHTML;
};

const params = new URLSearchParams(window.location.search);

const render = (d) => {
    document.getElementById('td-attack').innerHTML = escapeHTML(d.attack_type || '-');
    document.getElementById('td-risk').innerHTML = escapeHTML(d.risk_score || '0') + '%';
    document.getElementById('td-action').innerHTML = escapeHTML(d.action || '-');
    document.getElementById('td-layer').innerHTML = escapeHTML(d.execution_layer || '-');
    document.getElementById('td-rule').innerHTML = escapeHTML(d.rule_id || (d.protection_rule ? d.protection_rule.rule_id : false) || 'none');
    document.getElementById('td-device').innerHTML = escapeHTML(d.device_id || 'Unknown Device');
    document.getElementById('td-url').innerHTML = escapeHTML(d.original_url || '-');
    document.getElementById('td-explanation').innerHTML = `<strong>Diagnostic Reason:</strong> ` + escapeHTML(d.explanation || 'No AI explanation available.');
};

try {
    if (params.has('attack_type')) {
        render({
            attack_type: params.get('attack_type'),
            risk_score: params.get('risk_score'),
            action: params.get('action'),
            execution_layer: params.get('execution_layer'),
            rule_id: params.get('rule_id'),
            device_id: params.get('device_id'),
            original_url: params.get('original_url'),
            explanation: params.get('explanation')
        });
    } else {
        chrome.tabs.getCurrent(function (tab) {
            if (tab && tab.id) {
                chrome.storage.local.get("tab_" + tab.id, function (res) {
                    let d = res["tab_" + tab.id];
                    if (d) render(d);
                });
            }
        });
    }
} catch (e) {
    document.getElementById('td-explanation').innerHTML = `<strong>Error Executing Diagnostic Script:</strong> ` + escapeHTML(e.message);
}
