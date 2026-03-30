const TEXT_FORMAT_PREFIX = "SVP-TEXT:2:";
const FILE_FORMAT_MAGIC = "SVP2";
const TEXT_LINK_LIMIT = 3500;
const INLINE_FILE_LINK_LIMIT = 6 * 1024;
const MAX_CHAT_ATTACHMENT_SIZE = 50 * 1024 * 1024;
const MAX_CONNECT_RETRIES = 3;
const AUTO_RECONNECT_DELAY_MS = 900;
const encoder = new TextEncoder();
const decoder = new TextDecoder();

const DEFAULT_ICE_SERVERS = [
    { urls: "stun:stun.l.google.com:19302" },
    { urls: "stun:stun1.l.google.com:19302" },
    { urls: "stun:openrelay.metered.ca:80" },
    {
        urls: [
            "turn:openrelay.metered.ca:80",
            "turn:openrelay.metered.ca:443",
            "turn:openrelay.metered.ca:443?transport=tcp"
        ],
        username: "openrelayproject",
        credential: "openrelayproject"
    }
];

const state = {
    chatWarningShown: false,
    lastEncryptedText: "",
    lastEncryptedFilePackage: null,
    importedEncryptedFilePackage: null,
    sharePackage: null,
    peer: null,
    currentConnection: null,
    pendingConnection: null,
    currentCall: null,
    localStream: null,
    mediaRecorder: null,
    recordedChunks: [],
    messageTimers: new Map()
};

const $ = id => document.getElementById(id);

document.addEventListener("DOMContentLoaded", initApp);
window.addEventListener("hashchange", handleSharedPayloadFromUrl);
window.addEventListener("online", updateOfflineBanner);
window.addEventListener("offline", updateOfflineBanner);
window.addEventListener("beforeunload", handleBeforeUnload);

function initApp() {
    checkTerms();
    updateOfflineBanner();
    updateChatComposerHeight();
    initPeer();
    handleSharedPayloadFromUrl();

    $("shareModal").addEventListener("click", event => {
        if (event.target.id === "shareModal") {
            closeShareModal();
        }
    });
}

function showTab(tab) {
    ["vault", "risk", "chat"].forEach(section => {
        $(section).classList.toggle("hidden", section !== tab);
        $(`${section}Tab`).classList.toggle("active", section === tab);
        $(`${section}Tab`).setAttribute("aria-selected", String(section === tab));
    });

    if (tab === "chat" && !state.chatWarningShown) {
        state.chatWarningShown = true;
        setTimeout(() => {
            appendSystemMessage("Use secure chat responsibly. Transport is protected, but the person on the other side can still record what they receive.");
        }, 120);
    }
}

function handleBeforeUnload(event) {
    const hasSensitiveDraft =
        Boolean(state.currentConnection?.open) ||
        Boolean(state.currentCall) ||
        Boolean(state.lastEncryptedText) ||
        Boolean(state.lastEncryptedFilePackage) ||
        Boolean(state.importedEncryptedFilePackage);

    if (!hasSensitiveDraft) {
        return;
    }

    event.preventDefault();
    event.returnValue = "Closing this tab clears local secure content and active sessions.";
}

function checkTerms() {
    const accepted = localStorage.getItem("termsAccepted") === "true";
    $("termsModal").classList.toggle("hidden", accepted);
}

function acceptTerms() {
    localStorage.setItem("termsAccepted", "true");
    $("termsModal").classList.add("hidden");
}

function updateOfflineBanner() {
    $("offlineBanner").classList.toggle("hidden", navigator.onLine);
}

function checkTextStrength() {
    displayStrength("textStrength", $("textPassword").value);
}

function checkFileStrength() {
    displayStrength("fileStrength", $("filePassword").value);
}

function checkRiskStrength() {
    displayStrength("riskStrength", $("passwordInput").value);
}

function calculateStrength(password) {
    if (!password) {
        return 0;
    }

    const checks = [
        password.length >= 10 ? 12 : 0,
        password.length >= 14 ? 16 : 0,
        password.length >= 18 ? 16 : 0,
        /[a-z]/.test(password) ? 12 : 0,
        /[A-Z]/.test(password) ? 12 : 0,
        /\d/.test(password) ? 12 : 0,
        /[^A-Za-z0-9]/.test(password) ? 16 : 0,
        /(.)\1{2,}/.test(password) ? -10 : 0,
        /password|admin|qwerty|letmein/i.test(password) ? -25 : 0,
        new Set(password).size >= Math.min(password.length, 10) ? 10 : 0
    ];

    return Math.max(0, Math.min(100, checks.reduce((sum, value) => sum + value, 0)));
}

function displayStrength(elementId, value) {
    const element = $(elementId);
    const score = calculateStrength(value);

    if (!value) {
        element.textContent = "";
        element.className = "strength";
        return;
    }

    if (score < 40) {
        element.textContent = "Weak: increase length and mix character types.";
        element.className = "strength weak";
    } else if (score < 65) {
        element.textContent = "Fair: stronger than average, but still worth improving.";
        element.className = "strength medium";
    } else if (score < 85) {
        element.textContent = "Strong: good entropy and structure.";
        element.className = "strength strong";
    } else {
        element.textContent = "Excellent: long, mixed, and resistant to reuse patterns.";
        element.className = "strength military";
    }
}

async function deriveAesKey(password, saltBytes, usages) {
    const keyMaterial = await crypto.subtle.importKey(
        "raw",
        encoder.encode(password),
        { name: "PBKDF2" },
        false,
        ["deriveKey"]
    );

    return crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: saltBytes,
            iterations: 250000,
            hash: "SHA-256"
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        false,
        usages
    );
}

function bytesToBase64(bytes) {
    let binary = "";
    const chunkSize = 0x8000;

    for (let index = 0; index < bytes.length; index += chunkSize) {
        const chunk = bytes.subarray(index, index + chunkSize);
        binary += String.fromCharCode(...chunk);
    }

    return btoa(binary);
}

function base64ToBytes(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);

    for (let index = 0; index < binary.length; index += 1) {
        bytes[index] = binary.charCodeAt(index);
    }

    return bytes;
}

function encodeJsonPayload(value) {
    return bytesToBase64(encoder.encode(JSON.stringify(value)));
}

function decodeJsonPayload(value) {
    return JSON.parse(decoder.decode(base64ToBytes(value)));
}

function escapeHtml(value) {
    return value.replace(/[&<>"']/g, char => ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        "\"": "&quot;",
        "'": "&#39;"
    }[char]));
}

function downloadBlob(blob, filename) {
    const objectUrl = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = objectUrl;
    anchor.download = filename;
    anchor.click();
    setTimeout(() => URL.revokeObjectURL(objectUrl), 1500);
}

function buildAppUrl(hashParams = {}, searchParams = {}) {
    const url = new URL(window.location.origin + window.location.pathname);
    Object.entries(searchParams).forEach(([key, value]) => {
        if (value) {
            url.searchParams.set(key, value);
        }
    });

    const hash = new URLSearchParams();
    Object.entries(hashParams).forEach(([key, value]) => {
        if (value) {
            hash.set(key, value);
        }
    });

    url.hash = hash.toString();
    return url.toString();
}

function showBanner(message, tone = "info") {
    const banner = $("importBanner");
    banner.textContent = message;
    banner.className = "status-msg";
    if (tone === "success") {
        banner.classList.add("connected");
    } else if (tone === "warning") {
        banner.classList.add("warning");
    } else if (tone === "error") {
        banner.classList.add("error");
    }
    banner.classList.remove("hidden");
}

function clearBanner() {
    $("importBanner").classList.add("hidden");
}

function updateShareSummary(targetId, title, lines) {
    const target = $(targetId);
    const cleanLines = lines.filter(Boolean);

    target.innerHTML = [
        `<strong>${escapeHtml(title)}</strong>`,
        ...cleanLines.map(line => `<p>${escapeHtml(line)}</p>`)
    ].join("");
    target.classList.remove("hidden");
}

function clearFileState() {
    state.lastEncryptedFilePackage = null;
    state.importedEncryptedFilePackage = null;
    $("fileShareSummary").classList.add("hidden");
}

async function encryptText() {
    const plainText = $("textInput").value;
    const password = $("textPassword").value;
    const confirmPassword = $("textConfirmPassword").value;

    if (!plainText.trim()) {
        alert("Enter the text you want to encrypt.");
        return;
    }

    if (!password || password !== confirmPassword) {
        alert("Passwords must match before encrypting.");
        return;
    }

    if (calculateStrength(password) < 40) {
        alert("Use a stronger password before sharing encrypted text.");
        return;
    }

    try {
        const salt = crypto.getRandomValues(new Uint8Array(16));
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const key = await deriveAesKey(password, salt, ["encrypt"]);
        const cipherBytes = new Uint8Array(await crypto.subtle.encrypt(
            {
                name: "AES-GCM",
                iv,
                additionalData: encoder.encode("SecureVaultTextV2")
            },
            key,
            encoder.encode(plainText)
        ));

        const envelope = {
            v: 2,
            salt: bytesToBase64(salt),
            iv: bytesToBase64(iv),
            data: bytesToBase64(cipherBytes),
            createdAt: new Date().toISOString()
        };

        const payload = TEXT_FORMAT_PREFIX + encodeJsonPayload(envelope);
        state.lastEncryptedText = payload;
        $("textOutput").value = payload;

        const shareLink = payload.length <= TEXT_LINK_LIMIT
            ? buildAppUrl({ mode: "text", payload })
            : buildAppUrl({ mode: "text" });

        updateShareSummary(
            "textShareSummary",
            "Encrypted text ready",
            payload.length <= TEXT_LINK_LIMIT
                ? [
                    "The share link already contains the encrypted payload.",
                    "Recipients will open the app with the message preloaded for decryption."
                ]
                : [
                    "The encrypted block is large, so the share dialog will include the app link plus a copyable message.",
                    "Recipients can paste the encrypted block into the app if their messenger trims long links."
                ]
        );

        appendSystemMessage(`Text encrypted. Share-ready link prepared: ${shareLink.length <= 2048 ? "compact" : "extended"} package.`);
    } catch (error) {
        alert(`Encryption failed: ${error.message}`);
    }
}

async function decryptText() {
    const input = ($("textInput").value || $("textOutput").value).trim();
    const password = $("textPassword").value;

    if (!input) {
        alert("Paste encrypted text into the input first.");
        return;
    }

    if (!password) {
        alert("Enter the decryption password.");
        return;
    }

    if (!input.startsWith(TEXT_FORMAT_PREFIX)) {
        alert("This app now expects the new self-contained text format. Re-encrypt the message with the updated build if needed.");
        return;
    }

    try {
        const envelope = decodeJsonPayload(input.slice(TEXT_FORMAT_PREFIX.length));
        const salt = base64ToBytes(envelope.salt);
        const iv = base64ToBytes(envelope.iv);
        const cipherBytes = base64ToBytes(envelope.data);
        const key = await deriveAesKey(password, salt, ["decrypt"]);
        const plainBuffer = await crypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv,
                additionalData: encoder.encode("SecureVaultTextV2")
            },
            key,
            cipherBytes
        );

        $("textOutput").value = decoder.decode(plainBuffer);
        appendSystemMessage("Text decrypted successfully.");
    } catch (error) {
        alert(`Decryption failed: ${error.message}`);
    }
}

function shareText() {
    const encryptedText = state.lastEncryptedText || $("textOutput").value.trim();

    if (!encryptedText) {
        alert("Encrypt some text first so there is something to share.");
        return;
    }

    const linkFits = encryptedText.length <= TEXT_LINK_LIMIT;
    const deepLink = linkFits
        ? buildAppUrl({ mode: "text", payload: encryptedText })
        : buildAppUrl({ mode: "text" });

    const shareTextMessage = linkFits
        ? `Open this Secure Vault Pro link and enter the agreed password to decrypt:\n${deepLink}`
        : `Open Secure Vault Pro with this link, then paste the encrypted block below.\n\n${deepLink}\n\nEncrypted text:\n${encryptedText}`;

    openShareModal({
        title: "Share encrypted text",
        description: "Choose the fastest route. Native share works best on mobile, while copy and messaging shortcuts are useful on desktop.",
        link: deepLink,
        text: shareTextMessage,
        hint: linkFits
            ? "This link already contains the encrypted text."
            : "This payload is too large for a compact deep link, so the share message includes both the app link and the encrypted block."
    });
}

function clearText() {
    $("textInput").value = "";
    $("textOutput").value = "";
    $("textPassword").value = "";
    $("textConfirmPassword").value = "";
    $("textStrength").textContent = "";
    $("textShareSummary").classList.add("hidden");
    state.lastEncryptedText = "";
}

function packFileEnvelope(metadata, cipherBytes) {
    const magicBytes = encoder.encode(FILE_FORMAT_MAGIC);
    const headerBytes = encoder.encode(JSON.stringify(metadata));
    const headerLength = new Uint8Array(4);
    new DataView(headerLength.buffer).setUint32(0, headerBytes.length, false);

    const payload = new Uint8Array(magicBytes.length + headerLength.length + headerBytes.length + cipherBytes.length);
    payload.set(magicBytes, 0);
    payload.set(headerLength, magicBytes.length);
    payload.set(headerBytes, magicBytes.length + headerLength.length);
    payload.set(cipherBytes, magicBytes.length + headerLength.length + headerBytes.length);
    return payload;
}

function unpackFileEnvelope(bytes) {
    const magic = decoder.decode(bytes.slice(0, 4));

    if (magic !== FILE_FORMAT_MAGIC) {
        return null;
    }

    const headerLength = new DataView(bytes.buffer, bytes.byteOffset + 4, 4).getUint32(0, false);
    const headerStart = 8;
    const headerEnd = headerStart + headerLength;
    const metadata = JSON.parse(decoder.decode(bytes.slice(headerStart, headerEnd)));
    const cipherBytes = bytes.slice(headerEnd);
    return { metadata, cipherBytes };
}

async function encryptFile() {
    const file = $("fileInput").files[0];
    const password = $("filePassword").value;
    const confirmPassword = $("fileConfirmPassword").value;

    if (!file) {
        alert("Choose a file before encrypting.");
        return;
    }

    if (!password || password !== confirmPassword) {
        alert("Passwords must match before file encryption.");
        return;
    }

    if (calculateStrength(password) < 40) {
        alert("Use a stronger password for the encrypted file package.");
        return;
    }

    try {
        const sourceBuffer = await file.arrayBuffer();
        const salt = crypto.getRandomValues(new Uint8Array(16));
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const key = await deriveAesKey(password, salt, ["encrypt"]);
        const cipherBytes = new Uint8Array(await crypto.subtle.encrypt(
            { name: "AES-GCM", iv },
            key,
            sourceBuffer
        ));

        const metadata = {
            v: 2,
            name: file.name,
            type: file.type || "application/octet-stream",
            size: file.size,
            salt: bytesToBase64(salt),
            iv: bytesToBase64(iv),
            createdAt: new Date().toISOString()
        };

        const payload = packFileEnvelope(metadata, cipherBytes);
        const blob = new Blob([payload], { type: "application/octet-stream" });
        const downloadName = `${file.name}.svp.enc`;

        state.lastEncryptedFilePackage = {
            blob,
            name: downloadName,
            metadata
        };
        state.importedEncryptedFilePackage = null;

        downloadBlob(blob, downloadName);

        updateShareSummary(
            "fileShareSummary",
            "Encrypted file package ready",
            [
                "A local encrypted file was downloaded immediately.",
                blob.size <= INLINE_FILE_LINK_LIMIT
                    ? "This package is small enough to embed in a deep link."
                    : "Native share can send the attachment plus an app link in one step on supported devices."
            ]
        );

        appendSystemMessage(`Encrypted file ready: ${downloadName}`);
    } catch (error) {
        alert(`File encryption failed: ${error.message}`);
    }
}

async function decryptFile() {
    const password = $("filePassword").value;
    const selectedFile = $("fileInput").files[0];
    const importedPackage = state.importedEncryptedFilePackage;

    if (!selectedFile && !importedPackage) {
        alert("Choose an encrypted file or open a shared deep link first.");
        return;
    }

    if (!password) {
        alert("Enter the decryption password.");
        return;
    }

    try {
        const source = selectedFile
            ? new Uint8Array(await selectedFile.arrayBuffer())
            : new Uint8Array(await importedPackage.blob.arrayBuffer());

        const modernEnvelope = unpackFileEnvelope(source);

        if (modernEnvelope) {
            const salt = base64ToBytes(modernEnvelope.metadata.salt);
            const iv = base64ToBytes(modernEnvelope.metadata.iv);
            const key = await deriveAesKey(password, salt, ["decrypt"]);
            const plainBuffer = await crypto.subtle.decrypt(
                { name: "AES-GCM", iv },
                key,
                modernEnvelope.cipherBytes
            );

            downloadBlob(
                new Blob([plainBuffer], { type: modernEnvelope.metadata.type || "application/octet-stream" }),
                modernEnvelope.metadata.name || "decrypted-file"
            );
            appendSystemMessage(`File decrypted: ${modernEnvelope.metadata.name}`);
            return;
        }

        const legacyIv = source.slice(0, 12);
        const legacyCipher = source.slice(12);
        const keyMaterial = await crypto.subtle.importKey(
            "raw",
            encoder.encode(password),
            { name: "PBKDF2" },
            false,
            ["deriveKey"]
        );
        const legacyKey = await crypto.subtle.deriveKey(
            {
                name: "PBKDF2",
                salt: encoder.encode("vault"),
                iterations: 120000,
                hash: "SHA-256"
            },
            keyMaterial,
            { name: "AES-GCM", length: 256 },
            false,
            ["decrypt"]
        );

        const plainBuffer = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: legacyIv },
            legacyKey,
            legacyCipher
        );

        const originalName = selectedFile
            ? selectedFile.name.replace(/\.enc$/i, "").replace(/\.svp$/i, "")
            : (importedPackage?.name || "decrypted-file").replace(/\.svp\.enc$/i, "");

        downloadBlob(new Blob([plainBuffer]), originalName || "decrypted-file");
        appendSystemMessage("Legacy encrypted file decrypted successfully.");
    } catch (error) {
        alert(`File decryption failed: ${error.message}`);
    }
}

async function shareFile() {
    const activePackage = state.lastEncryptedFilePackage || state.importedEncryptedFilePackage;

    if (!activePackage) {
        alert("Encrypt a file or open a shared package first.");
        return;
    }

    const fileBlob = activePackage.blob;
    const fileName = activePackage.name || activePackage.metadata?.name || "secure-package.svp.enc";
    const linkFits = fileBlob.size <= INLINE_FILE_LINK_LIMIT;
    let deepLink = buildAppUrl({ mode: "file", name: fileName });

    if (linkFits) {
        const inlinePayload = bytesToBase64(new Uint8Array(await fileBlob.arrayBuffer()));
        deepLink = buildAppUrl({ mode: "file", name: fileName, payload: inlinePayload });
    }

    const shareMessage = linkFits
        ? `Open this Secure Vault Pro link to receive the encrypted file package instantly:\n${deepLink}`
        : `Open Secure Vault Pro with this link, then use the attached encrypted file package named ${fileName}.\n${deepLink}`;

    openShareModal({
        title: "Share encrypted file package",
        description: "On devices with Web Share support, the fastest option is to send the encrypted attachment and app link together.",
        link: deepLink,
        text: shareMessage,
        hint: linkFits
            ? "This package is embedded in the deep link, so the recipient can open it directly in the app."
            : "Large encrypted files still need the .svp.enc attachment. The link gets the recipient straight back into the app.",
        file: new File([fileBlob], fileName, { type: "application/octet-stream" })
    });
}

function clearFile() {
    $("fileInput").value = "";
    $("filePassword").value = "";
    $("fileConfirmPassword").value = "";
    $("fileStrength").textContent = "";
    clearFileState();
}

function openShareModal(sharePackage) {
    state.sharePackage = sharePackage;
    $("shareModalTitle").textContent = sharePackage.title;
    $("shareModalDescription").textContent = sharePackage.description;
    $("shareHint").textContent = sharePackage.hint || "";
    $("shareLinkField").value = sharePackage.link || "";
    $("shareLinkWrap").classList.toggle("hidden", !sharePackage.link);
    renderShareActions(sharePackage);
    $("shareModal").classList.remove("hidden");
}

function closeShareModal() {
    state.sharePackage = null;
    $("shareModal").classList.add("hidden");
}

function renderShareActions(sharePackage) {
    const actionGrid = $("shareActionGrid");
    actionGrid.innerHTML = "";

    const actions = [
        navigator.share ? { type: "button", label: "Native share", onClick: () => shareViaNavigator(sharePackage) } : null,
        sharePackage.link ? { type: "button", label: "Copy link", onClick: () => copyToClipboard(sharePackage.link, "Share link copied.") } : null,
        sharePackage.text ? { type: "button", label: "Copy message", onClick: () => copyToClipboard(sharePackage.text, "Share message copied.") } : null,
        sharePackage.file ? { type: "button", label: "Download package", onClick: () => downloadBlob(sharePackage.file, sharePackage.file.name) } : null,
        sharePackage.text ? { type: "link", label: "Email", href: `mailto:?subject=${encodeURIComponent(sharePackage.title)}&body=${encodeURIComponent(sharePackage.text)}` } : null,
        sharePackage.text ? { type: "link", label: "WhatsApp", href: `https://wa.me/?text=${encodeURIComponent(sharePackage.text)}` } : null,
        sharePackage.text ? { type: "link", label: "Telegram", href: `https://t.me/share/url?url=${encodeURIComponent(sharePackage.link || "")}&text=${encodeURIComponent(sharePackage.text)}` } : null
    ].filter(Boolean);

    actions.forEach(action => {
        if (action.type === "button") {
            const button = document.createElement("button");
            button.type = "button";
            button.textContent = action.label;
            button.addEventListener("click", action.onClick);
            actionGrid.appendChild(button);
            return;
        }

        const link = document.createElement("a");
        link.href = action.href;
        link.target = "_blank";
        link.rel = "noopener noreferrer";
        link.textContent = action.label;
        actionGrid.appendChild(link);
    });
}

async function shareViaNavigator(sharePackage) {
    try {
        const shareData = {
            title: sharePackage.title,
            text: sharePackage.text
        };

        if (sharePackage.file && navigator.canShare?.({ files: [sharePackage.file] })) {
            shareData.files = [sharePackage.file];
        } else if (sharePackage.link) {
            shareData.url = sharePackage.link;
        }

        await navigator.share(shareData);
        closeShareModal();
    } catch (error) {
        if (error.name !== "AbortError") {
            alert(`Native sharing failed: ${error.message}`);
        }
    }
}

async function copyToClipboard(value, successMessage) {
    try {
        await navigator.clipboard.writeText(value);
        showBanner(successMessage, "success");
    } catch (error) {
        window.prompt("Copy this value:", value);
    }
}

function handleSharedPayloadFromUrl() {
    const rawHash = window.location.hash.startsWith("#")
        ? window.location.hash.slice(1)
        : "";

    if (!rawHash) {
        return;
    }

    const hashParams = new URLSearchParams(rawHash);
    const mode = hashParams.get("mode");

    if (mode === "text") {
        const payload = hashParams.get("payload");
        showTab("vault");
        clearBanner();

        if (payload) {
            $("textInput").value = payload;
            showBanner("Encrypted text loaded from the link. Enter the password to decrypt it.", "success");
        } else {
            showBanner("Secure link opened. If the sender used a long message fallback, paste the encrypted text into the vault.", "warning");
        }

        clearHashOnly();
    }

    if (mode === "file") {
        const payload = hashParams.get("payload");
        const name = hashParams.get("name") || "shared-package.svp.enc";
        showTab("vault");
        clearBanner();

        if (payload) {
            const bytes = base64ToBytes(payload);
            const blob = new Blob([bytes], { type: "application/octet-stream" });
            state.importedEncryptedFilePackage = { blob, name };
            state.lastEncryptedFilePackage = null;
            updateShareSummary(
                "fileShareSummary",
                "Shared package imported",
                [
                    `${name} is loaded from the deep link.`,
                    "Enter the agreed password and use Decrypt File."
                ]
            );
            showBanner("Encrypted file package loaded from the link.", "success");
        } else {
            showBanner(`Open the app, then attach the encrypted file package named ${name}.`, "warning");
        }

        clearHashOnly();
    }
}

function clearHashOnly() {
    history.replaceState({}, "", `${window.location.pathname}${window.location.search}`);
}

function detectEmailProvider(email) {
    const domain = (email.split("@")[1] || "").toLowerCase();

    if (domain === "gmail.com" || domain === "googlemail.com") {
        return {
            key: "google",
            label: "Google / Gmail",
            score: email.includes("+") ? 88 : 70
        };
    }

    if (domain.endsWith("proton.me") || domain.endsWith("protonmail.com") || domain.endsWith("pm.me")) {
        return {
            key: "proton",
            label: "Proton",
            score: email.includes("+") ? 90 : 76
        };
    }

    if (domain) {
        return {
            key: "custom",
            label: domain,
            score: email.includes("+") ? 78 : 66
        };
    }

    return {
        key: "unknown",
        label: "Unknown",
        score: 50
    };
}

function scorePhoneRecovery(phoneDigits) {
    if (!phoneDigits) {
        return 46;
    }

    const signals = [
        phoneDigits.length >= 11 ? 34 : 18,
        /^(\d)\1+$/.test(phoneDigits) ? -18 : 0,
        /(0123|1234|0000|1111|2222|9999)$/.test(phoneDigits) ? -10 : 0,
        phoneDigits.startsWith("00") ? -4 : 0
    ];

    return Math.max(0, Math.min(100, signals.reduce((sum, value) => sum + value, 20)));
}

function scoreUsernameReuse(username) {
    if (!username) {
        return 58;
    }

    const signals = [
        username.length >= 10 ? 28 : 14,
        /\d{4,}$/.test(username) ? -12 : 0,
        /[_\-.]/.test(username) ? 6 : 0,
        /^[a-z0-9._-]+$/i.test(username) ? 8 : 0
    ];

    return Math.max(0, Math.min(100, signals.reduce((sum, value) => sum + value, 22)));
}

function scoreContacts(contacts) {
    if (!contacts) {
        return 84;
    }
    if (contacts > 1500) {
        return 34;
    }
    if (contacts > 750) {
        return 52;
    }
    if (contacts > 300) {
        return 68;
    }
    return 86;
}

function scoreDeviceSignals() {
    const deviceSignals = [
        navigator.hardwareConcurrency >= 4 ? 25 : 12,
        navigator.deviceMemory >= 8 ? 24 : 12,
        navigator.connection?.effectiveType === "4g" ? 18 : 10,
        window.isSecureContext ? 24 : 8
    ];

    return deviceSignals.reduce((sum, value) => sum + value, 10);
}

function formatList(items) {
    return `<ul>${items.map(item => `<li>${escapeHtml(item)}</li>`).join("")}</ul>`;
}

function checkEmailBreach() {
    const email = $("emailInput").value.trim().toLowerCase();

    if (!email || !email.includes("@")) {
        alert("Enter a valid email address.");
        return;
    }

    const provider = detectEmailProvider(email);
    const localPart = email.split("@")[0];
    const findings = [
        `Provider profile: ${provider.label}.`,
        localPart.includes("+")
            ? "Alias-style addressing detected, which helps isolate service signups."
            : "No alias marker detected. Consider service-specific aliases for high-risk signups.",
        localPart.length >= 10
            ? "Longer mailbox names are a little harder to guess and reuse."
            : "Short mailbox names are easier to remember, but they are also easier to enumerate."
    ];

    $("emailBreachResult").innerHTML = formatList(findings);
    $("emailBreachResult").classList.remove("hidden");
}

function checkPhoneBreach() {
    const digits = $("phoneInput").value.replace(/\D/g, "");

    if (!digits) {
        alert("Enter a recovery phone number to analyze.");
        return;
    }

    const findings = [
        digits.length >= 11
            ? "Country code detected, which reduces ambiguity during account recovery."
            : "Add a country code if you use this number for recovery across services.",
        /^(\d)\1+$/.test(digits)
            ? "Repeated-number patterns are easy to spot and should not be reused as verification PINs."
            : "The number does not look like a simple repeated pattern.",
        /(0123|1234|0000|1111|2222|9999)$/.test(digits)
            ? "Simple trailing sequences are easy to leak through screenshots or support workflows."
            : "No obvious trailing sequence was detected."
    ];

    $("phoneBreachResult").innerHTML = formatList(findings);
    $("phoneBreachResult").classList.remove("hidden");
}

async function checkPasswordBreach() {
    const password = $("passwordInput").value;

    if (!password) {
        alert("Enter a password to test.");
        return;
    }

    const target = $("passwordBreachResult");
    target.classList.remove("hidden");
    target.innerHTML = "Checking password safely with k-anonymity...";

    try {
        const hashBuffer = await crypto.subtle.digest("SHA-1", encoder.encode(password));
        const hash = Array.from(new Uint8Array(hashBuffer), value => value.toString(16).padStart(2, "0")).join("").toUpperCase();
        const prefix = hash.slice(0, 5);
        const suffix = hash.slice(5);
        const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
        const text = await response.text();

        const match = text
            .split(/\r?\n/)
            .map(line => line.split(":"))
            .find(parts => parts[0] === suffix);

        const strength = calculateStrength(password);
        const findings = match
            ? [
                `Compromised password hash match found ${Number(match[1]).toLocaleString()} times.`,
                "Rotate this password immediately anywhere it is still active.",
                `Current local strength score: ${strength}/100.`
            ]
            : [
                "No match found in the returned k-anonymity range data.",
                `Current local strength score: ${strength}/100.`,
                "Still keep this password unique to a single service."
            ];

        target.innerHTML = formatList(findings);
    } catch (error) {
        target.innerHTML = formatList([
            "The password exposure check is unavailable right now.",
            "The rest of the privacy audit still works locally."
        ]);
    }
}

async function checkBreach(password) {
    if (!password) {
        return false;
    }

    try {
        const hashBuffer = await crypto.subtle.digest("SHA-1", encoder.encode(password));
        const hash = Array.from(new Uint8Array(hashBuffer), value => value.toString(16).padStart(2, "0")).join("").toUpperCase();
        const prefix = hash.slice(0, 5);
        const suffix = hash.slice(5);
        const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
        const text = await response.text();
        return text.includes(suffix);
    } catch (error) {
        return false;
    }
}

function buildPlaybooks(provider, recoveryProvider, passwordBreached) {
    const cards = [];

    if (provider.key === "google" || /google|gmail/i.test(recoveryProvider)) {
        cards.push({
            title: "Google recovery branch",
            description: "Tighten sign-in, devices, and privacy checkpoints around your Google account.",
            actions: [
                "Run Security Checkup and review any recommended actions.",
                "Check recent devices and sessions before reusing this address for recovery.",
                "Move high-risk signups to aliases instead of the primary inbox."
            ],
            links: [
                { label: "Security guidance", href: "https://support.google.com/accounts/answer/46526?hl=en-AU" },
                { label: "Privacy Checkup", href: "https://support.google.com/accounts/answer/12629483?hl=en" }
            ]
        });
    }

    if (provider.key === "proton" || /proton/i.test(recoveryProvider)) {
        cards.push({
            title: "Proton alias branch",
            description: "Use Proton aliases and separate identities so an exposed address does not map your whole account graph.",
            actions: [
                "Create dedicated aliases for new services and newsletters.",
                "Retire any exposed alias instead of reusing it across sites.",
                "Keep recovery channels separate from your main identity inbox."
            ],
            links: [
                { label: "Proton Mail support", href: "https://proton.me/support/mail" },
                { label: "Alias workflow", href: "https://proton.me/support/pass-send-email-alias" }
            ]
        });
    }

    cards.push({
        title: "Exposure response branch",
        description: "This app avoids hidden scraping and leak-dump mining. Focus on trusted checks and fast containment.",
        actions: [
            "Rotate any breached password before investigating secondary accounts.",
            "Map primary email, aliases, backup inboxes, and phone recovery in one place.",
            "Prioritize the five accounts with the largest blast radius: email, storage, banking, social, and work tools."
        ],
        links: []
    });

    if (passwordBreached) {
        cards.push({
            title: "Compromised secret branch",
            description: "Your password check indicates exposure, so reset speed matters more than more scanning.",
            actions: [
                "Rotate the password everywhere it may be reused.",
                "Invalidate sessions and app-specific tokens if the service allows it.",
                "Move shared or family-critical accounts to stronger recovery channels."
            ],
            links: []
        });
    }

    return cards;
}

function renderPlaybooks(cards) {
    const grid = $("playbookGrid");
    grid.innerHTML = cards.map(card => `
        <article class="playbook-card">
            <h3>${escapeHtml(card.title)}</h3>
            <p>${escapeHtml(card.description)}</p>
            ${formatList(card.actions)}
            ${card.links.length ? `
                <div class="playbook-links">
                    ${card.links.map(link => `<a href="${link.href}" target="_blank" rel="noopener noreferrer">${escapeHtml(link.label)}</a>`).join("")}
                </div>
            ` : ""}
        </article>
    `).join("");
}

function renderTimeline(items) {
    const timeline = $("breachTimeline");
    timeline.innerHTML = `
        <h3>Fastest response sequence</h3>
        <div class="timeline">
            ${items.map(item => `
                <div class="timeline-item">
                    <strong>${escapeHtml(item.title)}</strong><br>
                    ${escapeHtml(item.detail)}
                </div>
            `).join("")}
        </div>
    `;
    timeline.classList.remove("hidden");
}

function animateWheel(score) {
    const circle = $("progressCircle");
    const circumference = 2 * Math.PI * 85;
    let current = 0;

    const interval = setInterval(() => {
        current += 1;
        const progress = Math.min(current, score);
        circle.style.strokeDashoffset = circumference - (progress / 100) * circumference;
        $("scoreText").textContent = String(progress);

        if (progress >= score) {
            clearInterval(interval);
        }

        if (progress >= 75) {
            circle.style.stroke = "#34d399";
        } else if (progress >= 45) {
            circle.style.stroke = "#f59e0b";
        } else {
            circle.style.stroke = "#f97316";
        }
    }, 12);
}

async function runComprehensiveScan() {
    const email = $("emailInput").value.trim().toLowerCase();
    const phoneDigits = $("phoneInput").value.replace(/\D/g, "");
    const password = $("passwordInput").value;
    const username = $("usernameInput").value.trim();
    const contacts = Number($("contactInput").value) || 0;
    const recoveryProvider = $("recoveryProviderInput").value.trim();

    const provider = detectEmailProvider(email);
    const passwordStrength = calculateStrength(password);
    const passwordBreached = await checkBreach(password);

    const metrics = [
        {
            label: "Password quality",
            weight: 28,
            score: password ? passwordStrength : 38,
            summary: password ? `${passwordStrength}/100 local strength score.` : "No password entered for review."
        },
        {
            label: "Breach resistance",
            weight: 20,
            score: password ? (passwordBreached ? 18 : 88) : 42,
            summary: password ? (passwordBreached ? "Password appeared in breach data." : "No pwned-password match found.") : "Live breach check skipped."
        },
        {
            label: "Email compartmentalization",
            weight: 16,
            score: email ? provider.score : 42,
            summary: email ? `${provider.label} with ${email.includes("+") ? "alias-style addressing" : "a primary-style address"}.` : "No primary email entered."
        },
        {
            label: "Recovery channel hygiene",
            weight: 14,
            score: scorePhoneRecovery(phoneDigits),
            summary: phoneDigits ? "Phone recovery channel reviewed locally." : "No recovery phone reviewed."
        },
        {
            label: "Username reuse pressure",
            weight: 10,
            score: scoreUsernameReuse(username),
            summary: username ? "Handle reviewed for simple reuse patterns." : "No username entered."
        },
        {
            label: "Contact blast radius",
            weight: 12,
            score: scoreContacts(contacts),
            summary: contacts ? `${contacts} saved contacts entered.` : "No contact count entered."
        },
        {
            label: "Device readiness",
            weight: 10,
            score: scoreDeviceSignals(),
            summary: "Browser, device, and connection signals reviewed locally."
        }
    ];

    const totalWeight = metrics.reduce((sum, metric) => sum + metric.weight, 0);
    const totalScore = Math.round(metrics.reduce((sum, metric) => sum + metric.score * metric.weight, 0) / totalWeight);
    const findings = metrics.map(metric => `${metric.label}: ${metric.summary}`);
    const nextSteps = [
        passwordBreached ? "Rotate the tested password before continuing to lower-priority accounts." : "Keep the tested password unique even if it looked healthy.",
        email.includes("+") ? "Keep alias-style addressing for new signups." : "Start using aliases or service-specific addresses for risky signups.",
        contacts > 750 ? "Reduce over-shared address books where possible." : "Keep high-value contacts compartmentalized from public-facing apps.",
        recoveryProvider ? `Review the backup mailbox or provider you listed: ${recoveryProvider}.` : "Add and audit a dedicated recovery channel that is different from the primary inbox."
    ];

    $("resultText").classList.remove("hidden");
    $("resultText").innerHTML = formatList(findings);

    $("adviceText").classList.remove("hidden");
    $("adviceText").innerHTML = `
        <h3>Best next actions</h3>
        ${formatList(nextSteps)}
    `;

    renderPlaybooks(buildPlaybooks(provider, recoveryProvider, passwordBreached));
    renderTimeline([
        { title: "Lock the primary account", detail: "Review active sessions, recovery channels, and outstanding alerts first." },
        { title: "Rotate exposed secrets", detail: passwordBreached ? "Reset the tested password everywhere it may be reused." : "Confirm each important account has a unique secret." },
        { title: "Compartmentalize future signups", detail: provider.key === "proton" ? "Use Proton aliases to isolate new services." : "Use aliases and separate recovery paths for risky services." }
    ]);
    animateWheel(totalScore);
}

function getCustomIceServers() {
    try {
        const raw = localStorage.getItem("svp_turn_config");
        const parsed = raw ? JSON.parse(raw) : null;
        return Array.isArray(parsed) && parsed.length ? parsed : null;
    } catch (error) {
        return null;
    }
}

function getIceServers() {
    return getCustomIceServers() || DEFAULT_ICE_SERVERS;
}

function warnIfInsecureContext() {
    const isLocalhost = /^(localhost|127\.0\.0\.1)$/.test(window.location.hostname);
    if (!window.isSecureContext && !isLocalhost) {
        appendSystemMessage("Use HTTPS for the most reliable voice and video experience.");
    }
}

function initPeer() {
    warnIfInsecureContext();

    state.peer = new Peer({
        secure: window.location.protocol === "https:",
        debug: 0,
        pingInterval: 20000,
        config: {
            iceServers: getIceServers(),
            iceTransportPolicy: "all"
        }
    });

    state.peer.on("open", id => {
        $("myPeerId").value = id;
        updateConnectionStatus("Waiting for connection...");
        appendSystemMessage("Peer ready.");

        const params = new URLSearchParams(window.location.search);
        const connectId = params.get("connect");
        const tab = params.get("tab");

        if (tab === "chat") {
            showTab("chat");
        }

        if (connectId) {
            $("connectId").value = connectId;
            showTab("chat");
            setTimeout(() => connectToPeer(), 500);
        }
    });

    state.peer.on("connection", connection => {
        if (state.currentConnection) {
            connection.close();
            return;
        }

        setupConnectionHandlers(connection, connection.peer, 1);
    });

    state.peer.on("call", call => {
        if (state.currentCall) {
            call.close();
            return;
        }
        answerCall(call);
    });

    state.peer.on("error", error => {
        if (error.type === "peer-unavailable") {
            updateConnectionStatus("Peer unavailable", "warning");
            appendSystemMessage("Peer unavailable. Ask for a fresh invite link or ID.");
            return;
        }

        if (["network", "server-error", "socket-error"].includes(error.type)) {
            updateConnectionStatus("Reconnecting…", "warning");
            appendSystemMessage("Network issue detected. Reconnecting to signaling service.");
            if (state.peer?.disconnected) {
                state.peer.reconnect();
            }
            return;
        }

        updateConnectionStatus("Connection error", "error");
        appendSystemMessage(`Peer error: ${error.type || "unknown"}`);
    });

    state.peer.on("disconnected", () => {
        updateConnectionStatus("Reconnecting…", "warning");
        setTimeout(() => {
            try {
                state.peer.reconnect();
            } catch (error) {
                initPeer();
            }
        }, AUTO_RECONNECT_DELAY_MS);
    });

    state.peer.on("close", () => {
        updateConnectionStatus("Restarting peer…", "warning");
        setTimeout(() => initPeer(), AUTO_RECONNECT_DELAY_MS);
    });
}

function updateConnectionStatus(message, tone = "info") {
    const status = $("connectionStatus");
    status.textContent = message;
    status.className = "status-msg";
    if (tone === "success" || /connected/i.test(message)) {
        status.classList.add("connected");
    } else if (tone === "warning") {
        status.classList.add("warning");
    } else if (tone === "error") {
        status.classList.add("error");
    }
}

function connectToPeer() {
    const connectId = $("connectId").value.trim();

    if (!connectId) {
        alert("Paste a peer ID or open an invite link.");
        return;
    }

    if (connectId === $("myPeerId").value) {
        alert("You cannot connect to yourself.");
        return;
    }

    attemptPeerConnect(connectId, 1);
}

function attemptPeerConnect(connectId, attempt) {
    if (!state.peer || state.peer.destroyed) {
        initPeer();
        updateConnectionStatus("Preparing peer…", "warning");
        setTimeout(() => attemptPeerConnect(connectId, attempt), AUTO_RECONNECT_DELAY_MS);
        return;
    }

    if (state.peer.disconnected) {
        updateConnectionStatus("Reconnecting peer…", "warning");
        state.peer.reconnect();
        setTimeout(() => attemptPeerConnect(connectId, attempt), AUTO_RECONNECT_DELAY_MS);
        return;
    }

    if (state.currentConnection) {
        state.currentConnection.close();
    }

    if (state.pendingConnection) {
        try {
            state.pendingConnection.close();
        } catch (error) {
            void error;
        }
    }

    updateConnectionStatus(attempt > 1 ? `Retrying connection (${attempt}/${MAX_CONNECT_RETRIES})…` : "Connecting…", "warning");
    const connection = state.peer.connect(connectId, { reliable: true });
    state.pendingConnection = connection;
    setupConnectionHandlers(connection, connectId, attempt);
}

function setupConnectionHandlers(connection, peerId, attempt) {
    const onOpen = () => {
        state.pendingConnection = null;
        state.currentConnection = connection;
        updateConnectionStatus("Connected to peer", "success");
        $("connectId").value = "";
        $("callControls").classList.remove("hidden");
        appendSystemMessage("Secure channel established.");
        clearInviteSearchParams();
    };

    connection.on("open", onOpen);

    connection.on("data", data => {
        if (typeof data === "string") {
            appendMessage({ content: data, timestamp: Date.now() }, "peer");
            return;
        }

        if (data.type === "text") {
            appendMessage(data, "peer");
            return;
        }

        if (data.type === "media") {
            renderIncomingMedia(data);
            return;
        }

        if (data.type === "call-info") {
            appendSystemMessage(`${data.callType} incoming…`);
            return;
        }

        if (data.type === "call-error") {
            appendSystemMessage(`Peer call issue: ${data.reason}`);
        }
    });

    connection.on("error", error => {
        if (state.pendingConnection === connection) {
            state.pendingConnection = null;
        }

        if (error.type === "peer-unavailable" && attempt < MAX_CONNECT_RETRIES) {
            setTimeout(() => attemptPeerConnect(peerId, attempt + 1), 1200);
            return;
        }

        updateConnectionStatus("Connection failed", "error");
        appendSystemMessage(`Connection failed: ${error.type || "unknown error"}`);
    });

    connection.on("close", () => {
        if (state.currentConnection === connection) {
            state.currentConnection = null;
        }
        if (state.pendingConnection === connection) {
            state.pendingConnection = null;
        }

        $("callControls").classList.add("hidden");
        updateConnectionStatus("Connection closed");
        appendSystemMessage("Peer disconnected.");
        endCall(false);
    });
}

function clearInviteSearchParams() {
    const url = new URL(window.location.href);
    if (!url.searchParams.has("connect") && !url.searchParams.has("tab")) {
        return;
    }

    url.searchParams.delete("connect");
    url.searchParams.delete("tab");
    history.replaceState({}, "", `${url.pathname}${url.search}${url.hash}`);
}

function copyMyId() {
    const id = $("myPeerId").value.trim();
    if (!id) {
        return;
    }

    copyToClipboard(id, "Peer ID copied.");
}

function generateInviteLink() {
    const id = $("myPeerId").value.trim();

    if (!id) {
        alert("Your peer ID is still being generated.");
        return;
    }

    const inviteLink = buildAppUrl({}, { tab: "chat", connect: id });

    openShareModal({
        title: "Share secure chat invite",
        description: "This invite link opens the app on the chat tab and can auto-fill the peer connection ID.",
        link: inviteLink,
        text: `Join me in Secure Vault Pro chat with this invite link:\n${inviteLink}`,
        hint: "Open on the recipient device and the chat tab will be ready to connect."
    });
}

function appendMessage(message, type) {
    const chatMessages = $("chatMessages");
    const wrapper = document.createElement("div");
    wrapper.className = `chat-msg ${type}`;

    if (type === "system") {
        wrapper.textContent = message.content || message;
        chatMessages.appendChild(wrapper);
        scrollChatToBottom();
        return wrapper;
    }

    const body = document.createElement("div");
    body.className = "chat-msg-body";
    body.textContent = message.content;

    const meta = document.createElement("div");
    meta.className = "chat-msg-meta";
    const time = new Date(message.timestamp || Date.now()).toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit"
    });
    meta.innerHTML = `<span>${time}</span>`;

    if (message.expiresIn) {
        const countdown = document.createElement("span");
        countdown.className = "countdown-pill";
        meta.appendChild(countdown);
        scheduleMessageExpiry(wrapper, countdown, message.expiresIn);
    }

    wrapper.appendChild(body);
    wrapper.appendChild(meta);
    chatMessages.appendChild(wrapper);
    scrollChatToBottom();
    return wrapper;
}

function appendSystemMessage(content) {
    appendMessage({ content, timestamp: Date.now() }, "system");
}

function scheduleMessageExpiry(messageElement, countdownElement, expiresIn) {
    const expiresAt = Date.now() + expiresIn;
    const timerKey = Symbol("expiry");

    const update = () => {
        const remaining = Math.max(0, Math.ceil((expiresAt - Date.now()) / 1000));

        if (remaining <= 0) {
            countdownElement.textContent = "Expired";
            messageElement.innerHTML = `<span class="expired-msg">Message self-destructed.</span>`;
            const timer = state.messageTimers.get(timerKey);
            if (timer) {
                clearInterval(timer);
            }
            state.messageTimers.delete(timerKey);
            return;
        }

        countdownElement.textContent = `Self-destructs in ${remaining}s`;
    };

    update();
    const interval = setInterval(update, 1000);
    state.messageTimers.set(timerKey, interval);
}

function scrollChatToBottom() {
    const chatMessages = $("chatMessages");
    requestAnimationFrame(() => {
        chatMessages.scrollTop = chatMessages.scrollHeight;
    });
}

function updateChatComposerHeight() {
    const input = $("chatInput");
    input.style.height = "auto";
    input.style.height = `${Math.min(input.scrollHeight, 160)}px`;
}

function getSelfDestructMs() {
    if (!$("autoDestruct").checked) {
        return 0;
    }

    const seconds = Math.max(5, Math.min(300, Number($("destructTimer").value) || 60));
    return seconds * 1000;
}

function sendChatMessage() {
    if (!state.currentConnection?.open) {
        alert("Connect to a peer first.");
        return;
    }

    const input = $("chatInput");
    const content = input.value.trim();

    if (!content) {
        return;
    }

    const message = {
        type: "text",
        content,
        timestamp: Date.now(),
        expiresIn: getSelfDestructMs()
    };

    state.currentConnection.send(message);
    appendMessage(message, "self");
    input.value = "";
    updateChatComposerHeight();
}

function handleChatKeyPress(event) {
    if (event.key === "Enter" && !event.shiftKey) {
        event.preventDefault();
        sendChatMessage();
    }
}

function toggleAdvancedControls() {
    $("advancedCallControls").classList.toggle("hidden");
}

async function sendMediaFile() {
    if (!state.currentConnection?.open) {
        alert("Connect to a peer first.");
        return;
    }

    const input = $("mediaInput");
    const file = input.files[0];

    if (!file) {
        return;
    }

    if (file.size > MAX_CHAT_ATTACHMENT_SIZE) {
        alert("The secure chat attachment limit is 50 MB.");
        input.value = "";
        return;
    }

    const buffer = await file.arrayBuffer();
    const payload = {
        type: "media",
        mime: file.type || "application/octet-stream",
        name: file.name,
        buffer,
        expiresIn: getSelfDestructMs()
    };

    state.currentConnection.send(payload);
    appendMessage(
        {
            content: `Sent attachment: ${file.name}`,
            timestamp: Date.now(),
            expiresIn: payload.expiresIn
        },
        "self"
    );
    input.value = "";
}

function renderIncomingMedia(payload) {
    const chatMessages = $("chatMessages");
    const wrapper = document.createElement("div");
    wrapper.className = "chat-msg peer";

    const blob = new Blob([payload.buffer], { type: payload.mime });
    const objectUrl = URL.createObjectURL(blob);

    if (payload.mime.startsWith("image/") || payload.mime.startsWith("video/")) {
        wrapper.classList.add("media-message-container");
        const media = document.createElement(payload.mime.startsWith("image/") ? "img" : "video");
        media.src = objectUrl;
        if (media.tagName === "VIDEO") {
            media.controls = true;
        }

        const overlay = document.createElement("div");
        overlay.className = "media-overlay";
        overlay.textContent = "Hold to reveal";

        const meta = document.createElement("div");
        meta.className = "chat-msg-meta";
        meta.innerHTML = `<span>${escapeHtml(payload.name)}</span>`;

        if (payload.expiresIn) {
            const countdown = document.createElement("span");
            countdown.className = "countdown-pill";
            meta.appendChild(countdown);
            scheduleMessageExpiry(wrapper, countdown, payload.expiresIn);
        }

        const reveal = event => {
            if (event.type !== "touchstart") {
                event.preventDefault();
            }
            wrapper.classList.add("revealed");
            if (media.tagName === "VIDEO") {
                media.play().catch(() => undefined);
            }
        };

        const hide = () => wrapper.classList.remove("revealed");

        overlay.addEventListener("mousedown", reveal);
        overlay.addEventListener("touchstart", reveal, { passive: true });
        window.addEventListener("mouseup", hide, { once: true });
        window.addEventListener("touchend", hide, { once: true });

        wrapper.appendChild(media);
        wrapper.appendChild(overlay);
        wrapper.appendChild(meta);
    } else {
        const body = document.createElement("div");
        body.className = "chat-msg-body";
        const link = document.createElement("a");
        link.href = objectUrl;
        link.download = payload.name;
        link.textContent = `Download ${payload.name}`;
        body.appendChild(link);

        const meta = document.createElement("div");
        meta.className = "chat-msg-meta";
        meta.innerHTML = "<span>Attachment</span>";

        if (payload.expiresIn) {
            const countdown = document.createElement("span");
            countdown.className = "countdown-pill";
            meta.appendChild(countdown);
            scheduleMessageExpiry(wrapper, countdown, payload.expiresIn);
        }

        wrapper.appendChild(body);
        wrapper.appendChild(meta);
    }

    chatMessages.appendChild(wrapper);
    scrollChatToBottom();
}

function getMediaErrorHelp(error) {
    const name = error?.name || "";
    const message = error?.message || "";

    if (name === "NotAllowedError" || name === "PermissionDeniedError") {
        return "Microphone or camera permission was denied. Allow access in browser site settings and try again.";
    }

    if (name === "NotFoundError" || name === "DevicesNotFoundError") {
        return "No usable microphone or camera was found.";
    }

    if (name === "NotReadableError" || name === "TrackStartError") {
        return "The microphone or camera is busy in another app or tab.";
    }

    if (name === "OverconstrainedError" || name === "ConstraintNotSatisfiedError") {
        return "The device could not satisfy the requested media quality.";
    }

    return message || "Media access failed on this device.";
}

async function getCallMediaWithFallback(preferVideo) {
    const attempts = preferVideo
        ? [
            {
                label: "video+audio",
                constraints: {
                    video: {
                        width: { ideal: 960 },
                        height: { ideal: 540 },
                        frameRate: { ideal: 24, max: 30 },
                        facingMode: "user"
                    },
                    audio: {
                        noiseSuppression: true,
                        echoCancellation: true,
                        autoGainControl: true
                    }
                }
            },
            {
                label: "audio-only",
                constraints: {
                    video: false,
                    audio: {
                        noiseSuppression: true,
                        echoCancellation: true,
                        autoGainControl: true
                    }
                }
            }
        ]
        : [
            {
                label: "audio-only",
                constraints: {
                    video: false,
                    audio: {
                        noiseSuppression: true,
                        echoCancellation: true,
                        autoGainControl: true
                    }
                }
            },
            {
                label: "basic-audio",
                constraints: { video: false, audio: true }
            }
        ];

    let lastError = null;
    for (const attempt of attempts) {
        try {
            const stream = await navigator.mediaDevices.getUserMedia(attempt.constraints);
            return { stream, mode: attempt.label };
        } catch (error) {
            lastError = error;
        }
    }

    const fallback = createVirtualFallbackStream(preferVideo);
    if (fallback) {
        return { stream: fallback, mode: "virtual-fallback" };
    }

    throw lastError || new Error("Media access failed.");
}

function createVirtualFallbackStream(preferVideo) {
    try {
        const stream = new MediaStream();
        let addedTrack = false;

        try {
            const AudioContextClass = window.AudioContext || window.webkitAudioContext;
            if (AudioContextClass) {
                const audioContext = new AudioContextClass();
                const oscillator = audioContext.createOscillator();
                const gain = audioContext.createGain();
                const destination = audioContext.createMediaStreamDestination();
                gain.gain.value = 0.0001;
                oscillator.connect(gain).connect(destination);
                oscillator.start();
                const track = destination.stream.getAudioTracks()[0];
                if (track) {
                    stream.addTrack(track);
                    addedTrack = true;
                }
            }
        } catch (error) {
            void error;
        }

        if (preferVideo) {
            const canvas = document.createElement("canvas");
            canvas.width = 640;
            canvas.height = 360;
            const context = canvas.getContext("2d");
            if (context) {
                context.fillStyle = "#08111e";
                context.fillRect(0, 0, canvas.width, canvas.height);
                context.fillStyle = "#c6f5ff";
                context.font = "24px Bahnschrift";
                context.fillText("Camera unavailable", 190, 190);
            }

            const capture = canvas.captureStream?.(4);
            const track = capture?.getVideoTracks?.()[0];
            if (track) {
                stream.addTrack(track);
                addedTrack = true;
            }
        }

        return addedTrack ? stream : null;
    } catch (error) {
        return null;
    }
}

async function startCall(videoEnabled) {
    if (!state.currentConnection?.open) {
        alert("Connect to a peer before starting a call.");
        return;
    }

    if (state.currentCall) {
        alert("A call is already active.");
        return;
    }

    try {
        const media = await getCallMediaWithFallback(videoEnabled);
        state.localStream = media.stream;
        $("localVideo").srcObject = state.localStream;
        $("videoContainer").classList.remove("hidden");

        if ($("recordCall").checked) {
            initializeCallRecording(state.localStream, videoEnabled);
        }

        state.currentCall = state.peer.call(state.currentConnection.peer, state.localStream);
        setupCallHandlers(state.currentCall);
        state.currentConnection.send({
            type: "call-info",
            callType: videoEnabled ? "Video call" : "Voice call",
            timestamp: Date.now()
        });
        $("callControls").classList.add("hidden");
        appendSystemMessage(`Call started using ${media.mode}.`);
    } catch (error) {
        const help = getMediaErrorHelp(error);
        appendSystemMessage(help);
        alert(help);
        if (state.currentConnection?.open) {
            state.currentConnection.send({ type: "call-error", reason: help });
        }
    }
}

async function answerCall(call) {
    try {
        const useVideo = window.confirm("Incoming call. Answer with video enabled?");
        const media = await getCallMediaWithFallback(useVideo);
        state.localStream = media.stream;
        $("localVideo").srcObject = state.localStream;
        $("videoContainer").classList.remove("hidden");

        if ($("recordCall").checked) {
            initializeCallRecording(state.localStream, useVideo);
        }

        call.answer(state.localStream);
        state.currentCall = call;
        setupCallHandlers(call);
        $("callControls").classList.add("hidden");
        appendSystemMessage(`Call answered using ${media.mode}.`);
    } catch (error) {
        const help = getMediaErrorHelp(error);
        appendSystemMessage(help);
        alert(help);
        call.close();
    }
}

function setupCallHandlers(call) {
    call.on("stream", remoteStream => {
        $("remoteVideo").srcObject = remoteStream;
    });

    call.on("close", () => {
        endCall(false);
    });

    call.on("error", error => {
        appendSystemMessage(`Call error: ${error}`);
    });
}

function initializeCallRecording(stream, isVideo) {
    try {
        const options = {
            mimeType: isVideo ? "video/webm;codecs=vp8,opus" : "audio/webm;codecs=opus"
        };

        if (!MediaRecorder.isTypeSupported(options.mimeType)) {
            options.mimeType = isVideo ? "video/webm" : "audio/webm";
        }

        state.recordedChunks = [];
        state.mediaRecorder = new MediaRecorder(stream, options);
        state.mediaRecorder.ondataavailable = event => {
            if (event.data.size > 0) {
                state.recordedChunks.push(event.data);
            }
        };

        state.mediaRecorder.onstop = () => {
            const blob = new Blob(state.recordedChunks, { type: state.mediaRecorder.mimeType });
            encryptRecording(blob);
        };

        state.mediaRecorder.start();
        appendSystemMessage("Encrypted call recording started.");
    } catch (error) {
        appendSystemMessage("Call recording is unavailable in this browser.");
    }
}

async function encryptRecording(blob) {
    const password = window.prompt("Set a password to encrypt the call recording:");
    if (!password) {
        return;
    }

    try {
        const buffer = await blob.arrayBuffer();
        const salt = crypto.getRandomValues(new Uint8Array(16));
        const iv = crypto.getRandomValues(new Uint8Array(12));
        const key = await deriveAesKey(password, salt, ["encrypt"]);
        const cipherBytes = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, buffer));
        const metadata = {
            v: 2,
            name: `secure-call-${Date.now()}.webm`,
            type: blob.type || "video/webm",
            size: blob.size,
            salt: bytesToBase64(salt),
            iv: bytesToBase64(iv),
            createdAt: new Date().toISOString()
        };
        const payload = packFileEnvelope(metadata, cipherBytes);
        downloadBlob(new Blob([payload], { type: "application/octet-stream" }), `${metadata.name}.svp.enc`);
        appendSystemMessage("Encrypted call recording downloaded.");
    } catch (error) {
        alert(`Recording encryption failed: ${error.message}`);
    }
}

function endCall(announce = true) {
    const activeCall = state.currentCall;
    state.currentCall = null;

    if (state.mediaRecorder && state.mediaRecorder.state !== "inactive") {
        state.mediaRecorder.stop();
    }
    state.mediaRecorder = null;

    if (activeCall) {
        try {
            activeCall.close();
        } catch (error) {
            void error;
        }
    }

    if (state.localStream) {
        state.localStream.getTracks().forEach(track => track.stop());
        state.localStream = null;
    }

    $("videoContainer").classList.add("hidden");
    $("localVideo").srcObject = null;
    $("remoteVideo").srcObject = null;

    if (state.currentConnection?.open) {
        $("callControls").classList.remove("hidden");
    }

    if (announce) {
        appendSystemMessage("Call ended.");
    }
}
