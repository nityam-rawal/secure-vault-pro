const DEFAULT_APP_URL = "https://nityam-rawal.github.io/secure-vault-pro/";
const extensionState = {
    items: [],
    summary: null
};

document.addEventListener("DOMContentLoaded", initPopup);

async function initPopup() {
    const stored = await storageGet({
        appUrl: DEFAULT_APP_URL,
        rangeDays: "30"
    });

    document.getElementById("appUrl").value = stored.appUrl || DEFAULT_APP_URL;
    document.getElementById("rangeDays").value = stored.rangeDays || "30";

    document.getElementById("refreshButton").addEventListener("click", refreshPreview);
    document.getElementById("exportButton").addEventListener("click", exportHistoryJson);
    document.getElementById("copySummaryButton").addEventListener("click", copyRiskSummary);
    document.getElementById("openAppButton").addEventListener("click", openApp);
    document.getElementById("appUrl").addEventListener("change", persistSettings);
    document.getElementById("rangeDays").addEventListener("change", async () => {
        await persistSettings();
        refreshPreview();
    });

    refreshPreview();
}

function storageGet(defaults) {
    return new Promise(resolve => {
        chrome.storage.local.get(defaults, resolve);
    });
}

function storageSet(values) {
    return new Promise(resolve => {
        chrome.storage.local.set(values, resolve);
    });
}

function historySearch(query) {
    return new Promise(resolve => {
        chrome.history.search(query, resolve);
    });
}

function downloadFile(options) {
    return new Promise((resolve, reject) => {
        chrome.downloads.download(options, downloadId => {
            if (chrome.runtime.lastError) {
                reject(new Error(chrome.runtime.lastError.message));
                return;
            }
            resolve(downloadId);
        });
    });
}

async function persistSettings() {
    await storageSet({
        appUrl: document.getElementById("appUrl").value.trim() || DEFAULT_APP_URL,
        rangeDays: document.getElementById("rangeDays").value
    });
}

function normalizeHostname(value) {
    try {
        return new URL(value).hostname.replace(/^www\./i, "").toLowerCase();
    } catch (error) {
        return "";
    }
}

function analyzeHistoryItem(item) {
    const domain = normalizeHostname(item.url);
    const riskyTlds = [".zip", ".top", ".xyz", ".click", ".country", ".gq", ".cf", ".tk", ".work"];
    const shorteners = ["bit.ly", "tinyurl.com", "t.co", "rb.gy", "cutt.ly", "is.gd", "ow.ly", "buff.ly"];
    const loginWords = /(login|signin|verify|update|secure|auth|password|reset|wallet|bank|invoice|support)/i;
    const reasons = [];
    let score = 0;

    if (item.url.startsWith("http://")) {
        reasons.push("unencrypted http");
        score += 18;
    }
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(domain)) {
        reasons.push("ip host");
        score += 30;
    }
    if (domain.startsWith("xn--")) {
        reasons.push("punycode");
        score += 28;
    }
    if (shorteners.includes(domain)) {
        reasons.push("shortener");
        score += 22;
    }
    if (riskyTlds.some(tld => domain.endsWith(tld))) {
        reasons.push("risky tld");
        score += 18;
    }
    if (loginWords.test(item.url.toLowerCase())) {
        reasons.push("login bait");
        score += 16;
    }
    if (/https?:\/\/[^/]*@/i.test(item.url)) {
        reasons.push("embedded credentials");
        score += 18;
    }
    if (domain.split(".").length >= 5) {
        reasons.push("deep subdomain chain");
        score += 10;
    }

    return {
        ...item,
        domain,
        score,
        reasons,
        severity: score >= 40 ? "high" : score >= 20 ? "medium" : "low"
    };
}

function buildSummary(items) {
    const analyzed = items.map(analyzeHistoryItem);
    const risky = analyzed.filter(item => item.score >= 20);
    const highRisk = analyzed.filter(item => item.score >= 40);
    const uniqueDomains = new Set(analyzed.map(item => item.domain).filter(Boolean));
    const topRiskDomains = Object.entries(analyzed.reduce((groups, item) => {
        if (item.score < 20 || !item.domain) {
            return groups;
        }
        groups[item.domain] = (groups[item.domain] || 0) + 1;
        return groups;
    }, {}))
        .sort((left, right) => right[1] - left[1])
        .slice(0, 5);

    const lines = [
        `Loaded ${items.length} visits across ${uniqueDomains.size} domains.`,
        highRisk.length
            ? `${highRisk.length} entries scored high risk by phishing-style heuristics.`
            : "No high-risk entries were flagged in this range.",
        risky.length && !highRisk.length
            ? `${risky.length} entries still landed in the medium-risk band.`
            : risky.length
                ? `${risky.length} entries landed in medium or high risk.`
                : "No medium-risk entries were flagged either.",
        topRiskDomains.length
            ? `Top risky domains: ${topRiskDomains.map(([domain, count]) => `${domain} (${count})`).join(", ")}.`
            : "No risky domains to highlight."
    ];

    return {
        analyzed,
        risky,
        highRisk,
        uniqueDomainCount: uniqueDomains.size,
        topRiskDomains,
        lines
    };
}

function renderMetrics(summary) {
    const metricGrid = document.getElementById("metricGrid");
    metricGrid.innerHTML = [
        { value: extensionState.items.length, label: "visits" },
        { value: summary.uniqueDomainCount, label: "domains" },
        { value: summary.highRisk.length, label: "high risk" },
        { value: summary.risky.length, label: "flagged" }
    ].map(metric => `
        <div class="metric-card">
            <strong>${metric.value}</strong>
            <span>${metric.label}</span>
        </div>
    `).join("");
}

function setStatus(message) {
    document.getElementById("statusText").textContent = message;
}

async function refreshPreview() {
    setStatus("Refreshing history preview...");
    await persistSettings();

    const rangeDays = Number(document.getElementById("rangeDays").value || "30");
    const startTime = Date.now() - rangeDays * 24 * 60 * 60 * 1000;
    const items = await historySearch({
        text: "",
        startTime,
        maxResults: 10000
    });

    extensionState.items = items.map(item => ({
        url: item.url,
        title: item.title || "",
        lastVisitTime: item.lastVisitTime || 0,
        visitCount: item.visitCount || 0,
        typedCount: item.typedCount || 0
    })).filter(item => item.url);

    extensionState.summary = buildSummary(extensionState.items);
    renderMetrics(extensionState.summary);
    document.getElementById("previewResult").textContent = extensionState.summary.lines.join("\n");
    setStatus("Preview updated. Export when you're ready.");
}

async function exportHistoryJson() {
    if (!extensionState.items.length) {
        await refreshPreview();
    }

    const rangeDays = Number(document.getElementById("rangeDays").value || "30");
    const payload = {
        exportedAt: new Date().toISOString(),
        source: "secure-vault-pro-companion",
        rangeDays,
        summary: {
            totalVisits: extensionState.items.length,
            uniqueDomains: extensionState.summary?.uniqueDomainCount || 0,
            highRiskCount: extensionState.summary?.highRisk.length || 0,
            flaggedCount: extensionState.summary?.risky.length || 0
        },
        items: extensionState.items
    };

    const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
    const objectUrl = URL.createObjectURL(blob);
    const filename = `secure-vault-history-${new Date().toISOString().slice(0, 10)}.json`;

    try {
        await downloadFile({
            url: objectUrl,
            filename,
            saveAs: true
        });
        setStatus("History JSON downloaded. Import it into Secure Vault Pro's history scanner.");
    } catch (error) {
        setStatus(`Download failed: ${error.message}`);
    } finally {
        setTimeout(() => URL.revokeObjectURL(objectUrl), 2000);
    }
}

async function copyRiskSummary() {
    if (!extensionState.summary) {
        await refreshPreview();
    }

    try {
        await navigator.clipboard.writeText(extensionState.summary.lines.join("\n"));
        setStatus("Risk summary copied.");
    } catch (error) {
        setStatus("Clipboard copy failed in this browser profile.");
    }
}

async function openApp() {
    await persistSettings();
    const appUrl = document.getElementById("appUrl").value.trim() || DEFAULT_APP_URL;
    chrome.tabs.create({ url: appUrl });
    setStatus("Opened Secure Vault Pro in a new tab.");
}
