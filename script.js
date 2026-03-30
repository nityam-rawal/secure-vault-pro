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

const SCAM_SCENARIOS = {
    general: {
        label: "Account scare",
        sample: "Your account has unusual activity. Click the link below immediately to verify and avoid service interruption.",
        actions: [
            "Do not click, pay, or share any OTP, PIN, or password.",
            "Open the official app or website yourself instead of using the incoming link.",
            "If money moved or access was lost, call 1930 and file a report on cybercrime.gov.in."
        ],
        hook: "Scammer sabse pehle aapka panic target karta hai.",
        audienceLine: "Pause, verify from the official app, and never act only because the message sounds urgent."
    },
    "digital-arrest": {
        label: "Digital arrest",
        sample: "This is Cyber Crime Branch. Your Aadhaar and phone number are linked to illegal activity. Stay on this call, do not tell anyone, and transfer funds for verification or you will be arrested today.",
        actions: [
            "Disconnect immediately and call the official police or helpline yourself.",
            "Never move money to a so-called safe account or verification account.",
            "Tell a family member right away because secrecy is part of the scam."
        ],
        hook: "Police kabhi WhatsApp ya video call par paisa transfer karake inquiry nahi karte.",
        audienceLine: "Digital arrest scripts use fear, secrecy, and urgent money transfer demands."
    },
    "kyc-freeze": {
        label: "KYC freeze",
        sample: "Dear customer, your bank KYC expired. Update PAN and Aadhaar within 30 minutes or your account and UPI will be blocked. Download the update app now.",
        actions: [
            "Do not install APK files or remote-help apps from messages.",
            "Check KYC status only from your bank's official app, website, or branch.",
            "Never share full card details, OTP, or MPIN during a KYC call."
        ],
        hook: "KYC ke naam par jo app install karwata hai, woh aksar account khaali karne aaya hai.",
        audienceLine: "Banks do not fix KYC by asking for OTP, MPIN, or sideloaded app installs."
    },
    "parcel-customs": {
        label: "Parcel customs",
        sample: "Your parcel is held by customs due to restricted items. Pay the release charge today or legal action will begin. Use the payment link now.",
        actions: [
            "Verify the shipment only on the courier's official site using your tracking number.",
            "Ignore payment links sent by unknown numbers or personal accounts.",
            "Do not continue if the sender adds police pressure or asks to keep the call private."
        ],
        hook: "Fake parcel aur customs scam ka goal sirf fee nahi, aapki identity aur banking access bhi hota hai.",
        audienceLine: "Customs pressure plus quick payment link is a common scam mix."
    },
    "upi-collect": {
        label: "UPI collect",
        sample: "I am sending you a collect request to receive your refund. Just approve the request or scan this QR to get the money instantly.",
        actions: [
            "Remember: scanning a QR or approving a collect request usually sends money, it does not receive money.",
            "Never approve UPI requests you did not start yourself.",
            "If money left the account, call 1930 and your bank immediately."
        ],
        hook: "UPI mein paise lene ke liye PIN nahi dalte, PIN dalte hi paise jaate hain.",
        audienceLine: "Refund, reward, and collect-request scripts are built to confuse payment direction."
    },
    "job-fee": {
        label: "Job fee",
        sample: "Congratulations, your interview is cleared. Pay the registration and security fee today for your joining letter. This amount is fully refundable after onboarding.",
        actions: [
            "Real hiring teams do not ask for registration or refundable joining fees.",
            "Verify job openings on the company's official careers page.",
            "Do not share ID proofs, bank details, or OTPs with recruiters on chat apps."
        ],
        hook: "Job scam mein sabse common red flag hota hai joining se pehle fee demand karna.",
        audienceLine: "Refundable processing fee is one of the oldest recruitment scam patterns."
    },
    "investment-tip": {
        label: "Investment tip",
        sample: "Join our private trading channel for guaranteed returns. Start with a small deposit today and we will double your capital using premium operator signals.",
        actions: [
            "Avoid guaranteed-return groups, premium Telegram channels, and pressure to top up fast.",
            "Do not install unknown trading apps or remote-support tools.",
            "Separate your investing identity from your main email, banking, and phone recovery."
        ],
        hook: "Guaranteed return ka promise aam taur par guaranteed fraud hota hai.",
        audienceLine: "High-return urgency plus private group pressure is a classic funnel into fraud."
    }
};

const state = {
    chatWarningShown: false,
    lastEncryptedText: "",
    lastEncryptedFilePackage: null,
    importedEncryptedFilePackage: null,
    auditData: {
        accountEntries: [],
        accountSummary: null,
        historyEntries: [],
        historySummary: null,
        scamAnalysis: null,
        awarenessPack: [],
        lastAuditReport: null
    },
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
    initPasswordToggles();
    updateChatComposerHeight();
    initPeer();
    handleSharedPayloadFromUrl();
    generateAwarenessPack(false);

    $("shareModal").addEventListener("click", event => {
        if (event.target.id === "shareModal") {
            closeShareModal();
        }
    });
}

function initPasswordToggles() {
    document.querySelectorAll('input[type="password"]').forEach(input => {
        if (input.parentElement?.classList.contains("password-field")) {
            return;
        }

        const wrapper = document.createElement("div");
        wrapper.className = "password-field";
        input.parentNode.insertBefore(wrapper, input);
        wrapper.appendChild(input);

        const toggle = document.createElement("button");
        toggle.type = "button";
        toggle.className = "password-toggle";
        toggle.setAttribute("aria-label", "Show password");
        toggle.setAttribute("aria-pressed", "false");
        toggle.innerHTML = getPasswordToggleIcon(false);
        toggle.addEventListener("click", () => togglePasswordVisibility(input, toggle));
        wrapper.appendChild(toggle);
    });
}

function getPasswordToggleIcon(visible) {
    return visible
        ? `
            <svg viewBox="0 0 24 24" aria-hidden="true">
                <path d="M3 3l18 18"></path>
                <path d="M10.6 10.7a2.5 2.5 0 003.5 3.5"></path>
                <path d="M9.4 5.3A11.6 11.6 0 0112 5c5 0 8.9 4 10 7-0.5 1.4-1.6 3-3.2 4.4"></path>
                <path d="M6.2 6.3C4 7.7 2.6 9.9 2 12c1.2 3.1 5 7 10 7 1.4 0 2.7-0.3 3.9-0.8"></path>
            </svg>
        `
        : `
            <svg viewBox="0 0 24 24" aria-hidden="true">
                <path d="M2 12c1.1-3 5-7 10-7s8.9 4 10 7c-1.1 3-5 7-10 7S3.1 15 2 12z"></path>
                <circle cx="12" cy="12" r="3"></circle>
            </svg>
        `;
}

function togglePasswordVisibility(input, toggle) {
    const isVisible = input.type === "text";
    input.type = isVisible ? "password" : "text";
    toggle.setAttribute("aria-label", isVisible ? "Show password" : "Hide password");
    toggle.setAttribute("aria-pressed", String(!isVisible));
    toggle.innerHTML = getPasswordToggleIcon(!isVisible);
    input.focus({ preventScroll: true });
    const length = input.value.length;
    input.setSelectionRange?.(length, length);
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

function getScenarioConfig(key) {
    return SCAM_SCENARIOS[key] || SCAM_SCENARIOS.general;
}

function buildEmergencyChecklist(analysis = state.auditData.scamAnalysis) {
    const lead = analysis
        ? `Pause. This sample matches ${analysis.scenarioLabel.toLowerCase()} tactics.`
        : "Pause before replying or paying anything.";

    return [
        lead,
        "Do not share OTP, MPIN, CVV, password, or screen access.",
        "Open the official app or website yourself instead of tapping the incoming link.",
        "If money moved or access changed, call 1930 immediately.",
        "File a report on cybercrime.gov.in and contact the bank or wallet provider.",
        "Warn family or the group where the message is spreading."
    ];
}

function copyEmergencyChecklist() {
    const text = [
        "Secure Vault Pro emergency checklist",
        ...buildEmergencyChecklist().map(item => `- ${item}`)
    ].join("\n");

    copyToClipboard(text, "Emergency checklist copied.");
}

function loadScamDecoderSample(key = "digital-arrest") {
    const scenario = getScenarioConfig(key);
    $("scamInput").value = scenario.sample;
    $("scamSourceInput").value = "";
    showBanner(`${scenario.label} sample loaded into Scam Decoder.`, "success");
}

function clearScamDecoder() {
    $("scamInput").value = "";
    $("scamSourceInput").value = "";
    hideMetricStrip("scamSummary");
    $("scamResult").classList.add("hidden");
    $("scamResult").innerHTML = "";
    state.auditData.scamAnalysis = null;
    generateAwarenessPack(false);
    renderAttackSurfaceInsights();
}

function extractExplicitUrls(text) {
    return [...new Set(
        (String(text || "").match(/\b(?:https?:\/\/|www\.)[^\s<>"']+|\b[a-z0-9-]+\.(?:com|in|org|net|me|app|co|xyz|top|click|zip)\b[^\s<>"']*/gi) || [])
            .map(match => match.replace(/[),.;]+$/, ""))
    )];
}

function buildScamAnalysis(message, source = "") {
    const combined = [message, source].filter(Boolean).join("\n").trim();
    const signalCatalog = [
        {
            scenario: "digital-arrest",
            weight: 28,
            pattern: /\b(digital arrest|crime branch|cbi|police|arrest|legal action|court notice)\b/i,
            reason: "Uses police or legal pressure to force quick compliance."
        },
        {
            scenario: "kyc-freeze",
            weight: 18,
            pattern: /\b(kyc|aadhaar|aadhar|pan|account blocked|account freeze|upi blocked|suspend)\b/i,
            reason: "Claims KYC or identity trouble that will freeze the account."
        },
        {
            scenario: "general",
            weight: 24,
            pattern: /\b(otp|cvv|mpin|pin|password|passcode)\b/i,
            reason: "Asks for OTP, PIN, password, or CVV."
        },
        {
            scenario: "kyc-freeze",
            weight: 30,
            pattern: /\b(anydesk|teamviewer|quicksupport|rustdesk|screen share|remote access)\b/i,
            reason: "Pushes screen sharing or remote access tools."
        },
        {
            scenario: "upi-collect",
            weight: 20,
            pattern: /\b(collect request|scan qr|scan the qr|refund|cashback|reward|upi|gpay|phonepe|paytm)\b/i,
            reason: "Uses UPI refund, collect request, or QR scan language."
        },
        {
            scenario: "parcel-customs",
            weight: 18,
            pattern: /\b(parcel|courier|shipment|customs|delivery)\b/i,
            reason: "Uses parcel, customs, or delivery pressure."
        },
        {
            scenario: "job-fee",
            weight: 20,
            pattern: /\b(job|interview|joining|registration fee|security fee|processing fee|refundable)\b/i,
            reason: "Uses job-offer language plus an upfront fee."
        },
        {
            scenario: "investment-tip",
            weight: 20,
            pattern: /\b(guaranteed return|double your money|trading tip|investment|profit signal|telegram channel)\b/i,
            reason: "Promises guaranteed profit or private investment signals."
        },
        {
            scenario: "general",
            weight: 12,
            pattern: /\b(urgent|immediately|today|now|last warning|within \d+|in \d+ minutes)\b/i,
            reason: "Creates artificial urgency."
        },
        {
            scenario: "digital-arrest",
            weight: 18,
            pattern: /\b(do not tell anyone|stay on this call|keep this private|confidential)\b/i,
            reason: "Asks for secrecy or tries to isolate the target."
        },
        {
            scenario: "general",
            weight: 18,
            pattern: /\b(safe account|verification account|deposit|release fee|top up|transfer funds)\b/i,
            reason: "Requests payment or transfer to solve a fake problem."
        },
        {
            scenario: "kyc-freeze",
            weight: 16,
            pattern: /\b(click here|download app|install app|apk)\b/i,
            reason: "Pushes unsafe links or app installs."
        }
    ];

    const signalMatches = signalCatalog
        .filter(signal => signal.pattern.test(combined))
        .map(signal => ({
            scenario: signal.scenario,
            weight: signal.weight,
            reason: signal.reason
        }));

    const rawLinks = extractExplicitUrls(combined);
    const urlFindings = rawLinks
        .map(link => readUrlCandidate(link))
        .filter(Boolean)
        .map(url => analyzeHistoryRecord({ url, title: "" }));
    const phoneMatches = [...new Set(combined.match(/(?:\+91[\s-]?)?[6-9]\d{9}\b/g) || [])];
    const upiMatches = [...new Set(combined.match(/\b[a-z0-9._-]{2,}@(ybl|ibl|axl|oksbi|okicici|okhdfcbank|paytm|upi)\b/gi) || [])];

    const scenarioWeights = signalMatches.reduce((totals, signal) => {
        totals[signal.scenario] = (totals[signal.scenario] || 0) + signal.weight;
        return totals;
    }, {});

    if (!Object.keys(scenarioWeights).length && urlFindings.length) {
        scenarioWeights.general = urlFindings.reduce((sum, finding) => sum + Math.min(18, finding.score), 0);
    }

    const scenarioKey = Object.entries(scenarioWeights)
        .sort((left, right) => right[1] - left[1])[0]?.[0] || "general";
    const scenario = getScenarioConfig(scenarioKey);
    const urlScore = urlFindings.reduce((sum, finding) => sum + Math.min(26, finding.score), 0);
    const indicatorScore = (phoneMatches.length ? 8 : 0) + (upiMatches.length ? 10 : 0);
    const score = Math.min(
        100,
        signalMatches.reduce((sum, signal) => sum + signal.weight, 0) + urlScore + indicatorScore
    );

    const severity = score >= 75
        ? "critical"
        : score >= 50
            ? "high"
            : score >= 28
                ? "medium"
                : "low";

    const reasons = [
        ...signalMatches.map(signal => signal.reason),
        ...urlFindings.flatMap(finding => finding.reasons.slice(0, 2).map(reason => `${finding.domain}: ${reason}`)),
        phoneMatches.length ? `${phoneMatches.length} phone number${phoneMatches.length > 1 ? "s" : ""} appear in the pasted content.` : "",
        upiMatches.length ? `${upiMatches.length} UPI handle${upiMatches.length > 1 ? "s" : ""} were found in the sample.` : ""
    ].filter(Boolean);

    const actions = [...new Set([
        ...scenario.actions,
        urlFindings.length ? "Type the official website manually instead of opening the shared link." : "",
        signalMatches.some(signal => /remote access|screen sharing/i.test(signal.reason))
            ? "Remove any remote-access app opened during the call and review device permissions."
            : "",
        phoneMatches.length ? "Verify the caller by dialing the official number from the bank or service website, not the incoming call." : "",
        upiMatches.length ? "Treat UPI handle requests as payment requests until you verify them in the official app." : "",
        severity === "critical" || severity === "high" ? "Escalate to 1930 fast if money, cards, or account access are already involved." : ""
    ].filter(Boolean)]).slice(0, 5);

    return {
        score,
        severity,
        scenarioKey,
        scenarioLabel: scenario.label,
        signalMatches,
        reasons,
        actions,
        indicators: {
            links: urlFindings.length,
            phones: phoneMatches.length,
            upiHandles: upiMatches.length
        }
    };
}

function renderScamDecoder(analysis) {
    renderMetricStrip("scamSummary", [
        { value: analysis.score, label: "risk score" },
        { value: analysis.severity.toUpperCase(), label: "severity" },
        { value: analysis.scenarioLabel, label: "likely pattern" },
        { value: analysis.signalMatches.length + analysis.indicators.links, label: "signals" }
    ]);

    const lines = [
        ...analysis.reasons.slice(0, 5),
        ...analysis.actions.map(action => `Action: ${action}`)
    ];

    $("scamResult").innerHTML = `
        <div class="decoder-head">
            <span class="decoder-badge ${analysis.severity}">${escapeHtml(`${analysis.severity} risk`)}</span>
            <p>${escapeHtml(`Likely pattern: ${analysis.scenarioLabel}.`)}</p>
        </div>
        ${formatList(lines)}
    `;
    $("scamResult").classList.remove("hidden");
}

function analyzeScamText() {
    const message = $("scamInput").value.trim();
    const source = $("scamSourceInput").value.trim();

    if (!message && !source) {
        alert("Paste a suspicious message, URL, or caller note first.");
        return;
    }

    const analysis = buildScamAnalysis(message, source);
    state.auditData.scamAnalysis = analysis;
    renderScamDecoder(analysis);
    generateAwarenessPack(false);
    renderAttackSurfaceInsights();
    showBanner(
        analysis.severity === "critical" || analysis.severity === "high"
            ? `${analysis.scenarioLabel} pattern detected. Pause and verify before doing anything else.`
            : `${analysis.scenarioLabel} review generated.`,
        analysis.severity === "low" ? "success" : "warning"
    );
}

function buildAwarenessPack(analysis = state.auditData.scamAnalysis) {
    const scenario = getScenarioConfig(analysis?.scenarioKey || "general");
    const severityLabel = analysis ? `${analysis.severity.toUpperCase()} risk` : "Community alert";
    const topAction = analysis?.actions?.[0] || scenario.actions[0];

    return [
        {
            id: "family-alert",
            channel: "WhatsApp",
            title: "Family Alert",
            hook: `${severityLabel}: ${scenario.hook}`,
            body: `Agar koi police, bank, courier, KYC, refund, ya job ke naam par urgency create kare, OTP, QR scan, ya payment mat karo. ${scenario.audienceLine}`,
            cta: "Save 1930, use official apps only, and forward this to the family group before the next scam wave."
        },
        {
            id: "reel-hook",
            channel: "Instagram Reels",
            title: "30-second Reel Hook",
            hook: `Hook: ${scenario.hook}`,
            body: `Script: Ek fake message ya call aapko daraata hai, jaldi karwata hai, aur verification ke naam par paisa ya access maangta hai. Red flag dekho, panic nahi. ${topAction}`,
            cta: "End card: Verify from the official app. If money moved, call 1930."
        },
        {
            id: "poster-copy",
            channel: "Community Poster",
            title: "Poster Copy",
            hook: `Headline: ${scenario.label} se bachne ke 3 rules`,
            body: "Rule 1: OTP, MPIN, CVV, password, ya screen access kabhi share mat karo. Rule 2: Incoming link ya number se verify mat karo. Rule 3: Payment ho gaya ho to 1930 aur cybercrime.gov.in use karo.",
            cta: "Use this in schools, RWAs, offices, coaching groups, and branch counters."
        },
        {
            id: "workshop-opener",
            channel: "Workshop",
            title: "60-second Opener",
            hook: "Most scams do not break systems first, they break attention first.",
            body: `Aaj ka sample ${scenario.label.toLowerCase()} pattern dikhata hai. Attackers fear, urgency, secrecy, ya refund story use karke victim ko official process se bahar le jaate hain. ${scenario.audienceLine}`,
            cta: "Close with one habit: pause, verify from the official app, and warn one more person."
        }
    ];
}

function renderAwarenessPack(cards) {
    $("awarenessPackGrid").innerHTML = cards.map(card => `
        <article class="awareness-card">
            <div class="awareness-card-top">
                <span class="channel-pill">${escapeHtml(card.channel)}</span>
                <button type="button" class="ghost-btn" onclick="copyAwarenessCard('${card.id}')">Copy</button>
            </div>
            <h4>${escapeHtml(card.title)}</h4>
            <p class="awareness-hook">${escapeHtml(card.hook)}</p>
            <p>${escapeHtml(card.body)}</p>
            <p class="awareness-cta">${escapeHtml(card.cta)}</p>
        </article>
    `).join("");
}

function formatAwarenessCard(card) {
    return [
        `${card.channel} | ${card.title}`,
        card.hook,
        "",
        card.body,
        "",
        card.cta
    ].join("\n");
}

function generateAwarenessPack(shouldNotify = true) {
    const pack = buildAwarenessPack();
    state.auditData.awarenessPack = pack;
    renderAwarenessPack(pack);
    if (shouldNotify) {
        showBanner("Awareness pack generated for sharing.", "success");
    }
}

function copyAwarenessCard(cardId) {
    if (!state.auditData.awarenessPack.length) {
        generateAwarenessPack(false);
    }

    const card = state.auditData.awarenessPack.find(item => item.id === cardId);
    if (!card) {
        alert("That awareness card is not available yet.");
        return;
    }

    copyToClipboard(formatAwarenessCard(card), `${card.title} copied.`);
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

function renderMetricStrip(targetId, metrics) {
    const target = $(targetId);
    target.innerHTML = metrics.map(metric => `
        <div class="metric-chip">
            <strong>${escapeHtml(String(metric.value))}</strong>
            <span>${escapeHtml(metric.label)}</span>
        </div>
    `).join("");
    target.classList.remove("hidden");
}

function hideMetricStrip(targetId) {
    const target = $(targetId);
    target.classList.add("hidden");
    target.innerHTML = "";
}

function normalizeHeaderLabel(label) {
    return String(label || "")
        .trim()
        .toLowerCase()
        .replace(/^\ufeff/, "")
        .replace(/[^a-z0-9]+/g, "");
}

function detectDelimiter(line) {
    const candidates = [",", ";", "\t", "|"];
    const counts = candidates.map(delimiter => ({
        delimiter,
        count: line.split(delimiter).length - 1
    }));
    return counts.sort((left, right) => right.count - left.count)[0]?.delimiter || ",";
}

function parseCsv(text) {
    const cleaned = String(text || "").replace(/\r\n/g, "\n").replace(/\r/g, "\n").replace(/^\ufeff/, "");
    const delimiter = detectDelimiter(cleaned.split("\n")[0] || ",");
    const rows = [];
    let currentRow = [];
    let currentValue = "";
    let inQuotes = false;

    for (let index = 0; index < cleaned.length; index += 1) {
        const char = cleaned[index];
        const next = cleaned[index + 1];

        if (char === "\"") {
            if (inQuotes && next === "\"") {
                currentValue += "\"";
                index += 1;
            } else {
                inQuotes = !inQuotes;
            }
            continue;
        }

        if (char === delimiter && !inQuotes) {
            currentRow.push(currentValue);
            currentValue = "";
            continue;
        }

        if (char === "\n" && !inQuotes) {
            currentRow.push(currentValue);
            if (currentRow.some(cell => String(cell).trim() !== "")) {
                rows.push(currentRow);
            }
            currentRow = [];
            currentValue = "";
            continue;
        }

        currentValue += char;
    }

    if (currentValue.length || currentRow.length) {
        currentRow.push(currentValue);
        if (currentRow.some(cell => String(cell).trim() !== "")) {
            rows.push(currentRow);
        }
    }

    return rows;
}

function findColumnIndex(headers, candidates) {
    const normalized = headers.map(normalizeHeaderLabel);
    return normalized.findIndex(header => candidates.includes(header));
}

function normalizeHostname(value) {
    const raw = String(value || "").trim();
    if (!raw) {
        return "";
    }

    try {
        const prepared = /^[a-z]+:\/\//i.test(raw) ? raw : `https://${raw.replace(/^\/\//, "")}`;
        return new URL(prepared).hostname.replace(/^www\./i, "").toLowerCase();
    } catch (error) {
        return "";
    }
}

function readUrlCandidate(value) {
    const raw = String(value || "").trim();
    if (!raw) {
        return "";
    }

    try {
        return new URL(/^[a-z]+:\/\//i.test(raw) ? raw : `https://${raw.replace(/^\/\//, "")}`).toString();
    } catch (error) {
        return "";
    }
}

function groupBy(items, getKey) {
    return items.reduce((groups, item) => {
        const key = getKey(item);
        if (!key) {
            return groups;
        }
        if (!groups[key]) {
            groups[key] = [];
        }
        groups[key].push(item);
        return groups;
    }, {});
}

async function readFileText(inputId) {
    const file = $(inputId).files[0];
    if (!file) {
        return "";
    }
    return file.text();
}

function parseAccountRows(text) {
    const trimmed = String(text || "").trim();
    try {
        if (trimmed.startsWith("[") || trimmed.startsWith("{")) {
            const parsed = JSON.parse(trimmed);
            const records = Array.isArray(parsed)
                ? parsed
                : Array.isArray(parsed?.items)
                    ? parsed.items
                    : Array.isArray(parsed?.accounts)
                        ? parsed.accounts
                        : [];

            const mapped = records.map(record => {
                const url = readUrlCandidate(record.url || record.website || record.origin || record.login_uri || "");
                const domain = normalizeHostname(url || record.domain || "");
                const username = String(record.username || record.user || record.email || record.login_username || "").trim();
                const password = String(record.password || record.pass || record.login_password || "").trim();
                const name = String(record.name || record.title || domain || username).trim();
                const note = String(record.note || record.notes || "").trim();
                return { name, url, domain, username, password, note };
            }).filter(entry => entry.domain || entry.username || entry.password);

            if (mapped.length) {
                return mapped;
            }
        }
    } catch (error) {
        void error;
    }

    const rows = parseCsv(text);
    if (!rows.length) {
        return [];
    }

    const headers = rows[0];
    const urlIndex = findColumnIndex(headers, ["url", "website", "site", "origin", "loginuri", "websiteurl", "uri"]);
    const usernameIndex = findColumnIndex(headers, ["username", "user", "login", "email", "loginusername"]);
    const passwordIndex = findColumnIndex(headers, ["password", "pass", "loginpassword"]);
    const nameIndex = findColumnIndex(headers, ["name", "title", "account", "label"]);
    const noteIndex = findColumnIndex(headers, ["note", "notes", "comment"]);

    return rows.slice(1)
        .map(row => {
            const url = readUrlCandidate(urlIndex >= 0 ? row[urlIndex] : "");
            const domain = normalizeHostname(url || row[urlIndex] || "");
            const username = String(usernameIndex >= 0 ? row[usernameIndex] : "").trim();
            const password = String(passwordIndex >= 0 ? row[passwordIndex] : "").trim();
            const name = String(nameIndex >= 0 ? row[nameIndex] : domain || username).trim();
            const note = String(noteIndex >= 0 ? row[noteIndex] : "").trim();

            return { name, url, domain, username, password, note };
        })
        .filter(entry => entry.domain || entry.username || entry.password);
}

function buildAccountSummary(entries, primaryEmail = "") {
    const uniqueDomains = [...new Set(entries.map(entry => entry.domain).filter(Boolean))];
    const passwordGroups = Object.values(groupBy(entries.filter(entry => entry.password), entry => entry.password))
        .filter(group => group.length > 1)
        .sort((left, right) => right.length - left.length);
    const weakPasswords = entries.filter(entry => entry.password && calculateStrength(entry.password) < 40);
    const httpEntries = entries.filter(entry => entry.url.startsWith("http://"));
    const primaryMatches = primaryEmail
        ? entries.filter(entry => entry.username.toLowerCase() === primaryEmail.toLowerCase()).length
        : 0;
    const domainsByUsername = Object.values(groupBy(entries.filter(entry => entry.username), entry => entry.username.toLowerCase()))
        .filter(group => group.length > 1)
        .sort((left, right) => right.length - left.length);
    const topDomains = Object.entries(groupBy(entries.filter(entry => entry.domain), entry => entry.domain))
        .map(([domain, group]) => ({ domain, count: group.length }))
        .sort((left, right) => right.count - left.count)
        .slice(0, 5);

    return {
        totalAccounts: entries.length,
        uniqueDomains: uniqueDomains.length,
        passwordGroups,
        weakPasswords,
        httpEntries,
        primaryMatches,
        domainsByUsername,
        topDomains
    };
}

function renderAccountImport(summary) {
    renderMetricStrip("accountImportSummary", [
        { value: summary.totalAccounts, label: "saved accounts" },
        { value: summary.uniqueDomains, label: "unique domains" },
        { value: summary.passwordGroups.length, label: "reuse clusters" },
        { value: summary.weakPasswords.length, label: "weak passwords" }
    ]);

    const lines = [
        `Imported ${summary.totalAccounts} saved accounts across ${summary.uniqueDomains} distinct domains.`,
        summary.primaryMatches
            ? `Your primary email matches ${summary.primaryMatches} saved logins.`
            : "No explicit primary-email matches were found in the imported usernames.",
        summary.passwordGroups.length
            ? `Largest password reuse cluster affects ${summary.passwordGroups[0].length} accounts.`
            : "No direct password reuse cluster was detected in the imported rows.",
        summary.weakPasswords.length
            ? `${summary.weakPasswords.length} saved passwords look weak by local entropy checks.`
            : "No clearly weak saved password was flagged by the local strength check.",
        summary.httpEntries.length
            ? `${summary.httpEntries.length} account records still point to HTTP URLs.`
            : "No HTTP-only login URL was detected in the import.",
        summary.topDomains.length
            ? `Top repeated domains: ${summary.topDomains.map(item => `${item.domain} (${item.count})`).join(", ")}.`
            : "No repeated domains to highlight yet."
    ];

    $("accountImportResult").innerHTML = formatList(lines);
    $("accountImportResult").classList.remove("hidden");
}

async function analyzeAccountImport() {
    const text = await readFileText("accountCsvInput");
    if (!text.trim()) {
        alert("Import a saved-account CSV or compatible export first.");
        return;
    }

    const entries = parseAccountRows(text);
    if (!entries.length) {
        alert("I could not find account rows in that file.");
        return;
    }

    state.auditData.accountEntries = entries;
    state.auditData.accountSummary = buildAccountSummary(entries, $("emailInput").value.trim());
    renderAccountImport(state.auditData.accountSummary);
    renderAttackSurfaceInsights();
}

function clearAccountImport() {
    $("accountCsvInput").value = "";
    $("accountImportResult").classList.add("hidden");
    $("accountImportResult").innerHTML = "";
    hideMetricStrip("accountImportSummary");
    state.auditData.accountEntries = [];
    state.auditData.accountSummary = null;
    renderAttackSurfaceInsights();
}

function parseHistoryRows(text) {
    const trimmed = String(text || "").trim();
    if (!trimmed) {
        return [];
    }

    try {
        if (trimmed.startsWith("[") || trimmed.startsWith("{")) {
            const parsed = JSON.parse(trimmed);
            const records = Array.isArray(parsed)
                ? parsed
                : Array.isArray(parsed?.items)
                    ? parsed.items
                    : Array.isArray(parsed?.history)
                        ? parsed.history
                        : [];

            return records.map(record => ({
                url: readUrlCandidate(record.url || record.URL || record.link || ""),
                title: String(record.title || record.name || "").trim()
            })).filter(record => record.url);
        }
    } catch (error) {
        void error;
    }

    const rows = parseCsv(trimmed);
    if (rows.length > 1) {
        const headers = rows[0];
        const urlIndex = findColumnIndex(headers, ["url", "link", "website", "address"]);
        const titleIndex = findColumnIndex(headers, ["title", "name", "page"]);
        if (urlIndex >= 0) {
            return rows.slice(1)
                .map(row => ({
                    url: readUrlCandidate(row[urlIndex]),
                    title: String(titleIndex >= 0 ? row[titleIndex] : "").trim()
                }))
                .filter(record => record.url);
        }
    }

    return trimmed
        .split(/\r?\n/)
        .map(line => ({ url: readUrlCandidate(line), title: "" }))
        .filter(record => record.url);
}

function analyzeHistoryRecord(record) {
    const url = new URL(record.url);
    const domain = url.hostname.replace(/^www\./i, "").toLowerCase();
    const raw = record.url.toLowerCase();
    const riskyTlds = [".zip", ".top", ".xyz", ".click", ".country", ".gq", ".cf", ".tk", ".work"];
    const shorteners = ["bit.ly", "tinyurl.com", "t.co", "rb.gy", "cutt.ly", "is.gd", "ow.ly", "buff.ly"];
    const loginWords = /(login|signin|verify|update|secure|auth|password|reset|wallet|bank|invoice|support)/i;
    const reasons = [];
    let score = 0;

    if (url.protocol === "http:") {
        reasons.push("unencrypted http");
        score += 18;
    }
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(domain)) {
        reasons.push("ip-based host");
        score += 30;
    }
    if (domain.startsWith("xn--")) {
        reasons.push("punycode host");
        score += 28;
    }
    if (shorteners.includes(domain)) {
        reasons.push("shortener redirect");
        score += 22;
    }
    if (riskyTlds.some(tld => domain.endsWith(tld))) {
        reasons.push("high-abuse tld");
        score += 18;
    }
    if (loginWords.test(raw)) {
        reasons.push("login-bait keywords");
        score += 16;
    }
    if (/https?:\/\/[^/]*@/i.test(record.url)) {
        reasons.push("embedded credentials pattern");
        score += 18;
    }
    if (domain.split(".").length >= 5) {
        reasons.push("deep subdomain chain");
        score += 10;
    }
    if (url.port && !["80", "443"].includes(url.port)) {
        reasons.push("non-standard port");
        score += 8;
    }

    return {
        ...record,
        domain,
        reasons,
        score,
        severity: score >= 40 ? "high" : score >= 20 ? "medium" : "low"
    };
}

function buildHistorySummary(entries, accountEntries = []) {
    const enriched = entries.map(analyzeHistoryRecord);
    const uniqueDomains = [...new Set(enriched.map(entry => entry.domain))];
    const domainSet = new Set(accountEntries.map(entry => entry.domain).filter(Boolean));
    const overlapping = [...new Set(enriched.map(entry => entry.domain).filter(domain => domainSet.has(domain)))];
    const risky = enriched.filter(entry => entry.score >= 20);
    const highRisk = enriched.filter(entry => entry.score >= 40);
    const mediumRisk = enriched.filter(entry => entry.score >= 20 && entry.score < 40);
    const suspiciousLogins = enriched.filter(entry => entry.reasons.includes("login-bait keywords"));
    const shorteners = enriched.filter(entry => entry.reasons.includes("shortener redirect"));
    const topRiskDomains = Object.entries(groupBy(risky, entry => entry.domain))
        .map(([domain, group]) => ({ domain, count: group.length, score: group.reduce((sum, item) => sum + item.score, 0) }))
        .sort((left, right) => right.score - left.score || right.count - left.count)
        .slice(0, 5);

    return {
        totalEntries: enriched.length,
        uniqueDomains: uniqueDomains.length,
        riskyCount: risky.length,
        highRiskCount: highRisk.length,
        mediumRiskCount: mediumRisk.length,
        suspiciousLogins,
        shorteners,
        overlapping,
        topRiskDomains,
        enriched
    };
}

function renderHistoryImport(summary) {
    renderMetricStrip("historyImportSummary", [
        { value: summary.totalEntries, label: "history rows" },
        { value: summary.uniqueDomains, label: "unique domains" },
        { value: summary.highRiskCount, label: "high risk" },
        { value: summary.overlapping.length, label: "account overlaps" }
    ]);

    const lines = [
        `Parsed ${summary.totalEntries} history entries across ${summary.uniqueDomains} distinct domains.`,
        summary.highRiskCount
            ? `${summary.highRiskCount} entries scored high risk based on phishing-style heuristics.`
            : "No entry reached the high-risk threshold.",
        summary.mediumRiskCount
            ? `${summary.mediumRiskCount} additional entries landed in the medium-risk band.`
            : "No medium-risk entries were flagged.",
        summary.suspiciousLogins.length
            ? `${summary.suspiciousLogins.length} entries used login, verify, reset, or support keywords in the URL.`
            : "No obvious login-bait keywords were found in imported URLs.",
        summary.shorteners.length
            ? `${summary.shorteners.length} entries were hidden behind URL shorteners.`
            : "No URL shortener entries were detected.",
        summary.overlapping.length
            ? `Visited domains overlap with imported account domains on ${summary.overlapping.length} hosts.`
            : "No imported-account overlap was detected yet.",
        summary.topRiskDomains.length
            ? `Top risky domains: ${summary.topRiskDomains.map(item => `${item.domain} (${item.count})`).join(", ")}.`
            : "No risky domains to rank yet."
    ];

    $("historyImportResult").innerHTML = formatList(lines);
    $("historyImportResult").classList.remove("hidden");
}

async function analyzeHistoryImport() {
    const fileText = await readFileText("historyImportInput");
    const pastedText = $("historyPasteInput").value.trim();
    const combined = [fileText, pastedText].filter(Boolean).join("\n");

    if (!combined.trim()) {
        alert("Import history data or paste URLs first.");
        return;
    }

    const entries = parseHistoryRows(combined);
    if (!entries.length) {
        alert("I could not extract any URLs from that history input.");
        return;
    }

    state.auditData.historyEntries = entries;
    state.auditData.historySummary = buildHistorySummary(entries, state.auditData.accountEntries);
    renderHistoryImport(state.auditData.historySummary);
    renderAttackSurfaceInsights();
}

function clearHistoryImport() {
    $("historyImportInput").value = "";
    $("historyPasteInput").value = "";
    $("historyImportResult").classList.add("hidden");
    $("historyImportResult").innerHTML = "";
    hideMetricStrip("historyImportSummary");
    state.auditData.historyEntries = [];
    state.auditData.historySummary = null;
    renderAttackSurfaceInsights();
}

function renderInsightGrid(cards) {
    const target = $("auditInsightGrid");
    target.innerHTML = cards.map(card => `
        <article class="insight-card">
            <h3>${escapeHtml(card.title)}</h3>
            <p>${escapeHtml(card.summary)}</p>
            <ul class="insight-list">
                ${card.items.map(item => `<li>${escapeHtml(item)}</li>`).join("")}
            </ul>
        </article>
    `).join("");
}

function renderAttackSurfaceInsights(primaryEmail = $("emailInput").value.trim().toLowerCase()) {
    const accountSummary = state.auditData.accountSummary;
    const historySummary = state.auditData.historySummary;
    const scamAnalysis = state.auditData.scamAnalysis;
    const attackSurfaceResult = $("attackSurfaceResult");

    if (!accountSummary && !historySummary && !scamAnalysis) {
        $("auditInsightGrid").innerHTML = "";
        attackSurfaceResult.classList.add("hidden");
        attackSurfaceResult.innerHTML = "";
        return;
    }

    const largestReuseCluster = accountSummary?.passwordGroups?.[0]?.length || 0;
    const identityMatches = accountSummary?.primaryMatches || 0;
    const historyOverlap = historySummary?.overlapping?.length || 0;
    const riskyHistory = historySummary?.highRiskCount || 0;
    const riskyLoginBait = historySummary?.suspiciousLogins?.length || 0;

    const cards = [
        ...(scamAnalysis ? [{
            title: "Live scam pressure",
            summary: "What the currently pasted message or caller note is trying to make the user do next.",
            items: [
                `${scamAnalysis.severity.toUpperCase()} risk score from the scam decoder.`,
                `Likely pattern: ${scamAnalysis.scenarioLabel}.`,
                scamAnalysis.actions[0] || "Pause and verify using the official app."
            ]
        }] : []),
        {
            title: "Identity footprint",
            summary: primaryEmail
                ? `How far the main identity spreads across imported account data.`
                : "Import saved accounts and add a primary email to map identity reuse.",
            items: [
                primaryEmail ? `Primary email match count: ${identityMatches}.` : "Primary email not set.",
                accountSummary ? `Imported account inventory size: ${accountSummary.totalAccounts}.` : "No account inventory imported.",
                accountSummary?.domainsByUsername?.[0]
                    ? `A single username repeats across ${accountSummary.domainsByUsername[0].length} accounts.`
                    : "No large username reuse cluster detected."
            ]
        },
        {
            title: "Credential reuse",
            summary: "This is the fastest path an attacker uses after a single credential leak.",
            items: [
                largestReuseCluster ? `Largest reused-password cluster unlocks ${largestReuseCluster} accounts.` : "No password reuse cluster detected in imported data.",
                accountSummary ? `${accountSummary.weakPasswords.length} imported passwords look weak locally.` : "Weak-password analysis unavailable until account import.",
                accountSummary ? `${accountSummary.httpEntries.length} imported records still point at HTTP pages.` : "HTTP login analysis unavailable until account import."
            ]
        },
        {
            title: "Browsing bait",
            summary: "Risky browsing signals often reveal where phishing or credential capture starts.",
            items: [
                historySummary ? `${riskyHistory} high-risk history entries were flagged.` : "No history import analyzed yet.",
                historySummary ? `${riskyLoginBait} login-bait URLs were found.` : "Login-bait scan unavailable until history import.",
                historySummary ? `${historyOverlap} visited domains overlap with imported account domains.` : "No account-history overlap measured yet."
            ]
        }
    ];

    renderInsightGrid(cards);

    const summaryLines = [
        ...(scamAnalysis
            ? [`Scam Decoder currently flags a ${scamAnalysis.severity} risk ${scamAnalysis.scenarioLabel.toLowerCase()} pattern.`]
            : []),
        largestReuseCluster
            ? `If one reused password falls, the biggest blast radius currently touches ${largestReuseCluster} accounts.`
            : "No reused-password cluster has been confirmed from imported account data.",
        identityMatches
            ? `Your main email appears directly inside ${identityMatches} imported account rows.`
            : primaryEmail
                ? "The current primary email did not appear directly in imported usernames."
                : "Set a primary email to measure direct account linkage.",
        riskyHistory
            ? `${riskyHistory} high-risk visited URLs deserve manual review before reusing credentials on similar domains.`
            : "No high-risk browsing pattern has been flagged from the imported history."
    ];

    attackSurfaceResult.innerHTML = formatList(summaryLines);
    attackSurfaceResult.classList.remove("hidden");
}

function buildAuditReportPayload(options = {}) {
    const primaryEmail = $("emailInput").value.trim().toLowerCase();
    const phoneDigits = $("phoneInput").value.replace(/\D/g, "");
    const password = $("passwordInput").value;
    const username = $("usernameInput").value.trim();
    const recoveryProvider = $("recoveryProviderInput").value.trim();
    const contacts = Number($("contactInput").value) || 0;
    const provider = detectEmailProvider(primaryEmail);
    const passwordStrength = calculateStrength(password);
    const accountSummary = state.auditData.accountSummary;
    const historySummary = state.auditData.historySummary;
    const scamAnalysis = state.auditData.scamAnalysis;
    const riskyHistory = historySummary?.highRiskCount || 0;
    const mediumHistory = historySummary?.mediumRiskCount || 0;
    const largestReuseCluster = accountSummary?.passwordGroups?.[0]?.length || 0;
    const attackSummary = [
        ...(scamAnalysis
            ? [`Scam Decoder flagged a ${scamAnalysis.severity} risk ${scamAnalysis.scenarioLabel.toLowerCase()} pattern.`]
            : []),
        largestReuseCluster
            ? `Largest reused-password cluster affects ${largestReuseCluster} saved accounts.`
            : "No reused-password cluster confirmed from imported account data.",
        accountSummary
            ? `${accountSummary.primaryMatches} imported accounts directly match the configured primary email.`
            : "No saved-account inventory was imported.",
        historySummary
            ? `${riskyHistory} high-risk and ${mediumHistory} medium-risk history entries were flagged.`
            : "No history import was analyzed."
    ];

    return {
        exportedAt: new Date().toISOString(),
        reportType: "secure-vault-audit",
        score: options.score ?? null,
        profile: {
            primaryEmail,
            emailProvider: provider.label,
            recoveryProvider,
            phoneDigitsLength: phoneDigits.length,
            username,
            contacts,
            passwordStrength
        },
        importedData: {
            accountEntries: state.auditData.accountEntries.length,
            historyEntries: state.auditData.historyEntries.length
        },
        accountSummary: accountSummary ? {
            totalAccounts: accountSummary.totalAccounts,
            uniqueDomains: accountSummary.uniqueDomains,
            primaryMatches: accountSummary.primaryMatches,
            weakPasswords: accountSummary.weakPasswords.length,
            reuseClusters: accountSummary.passwordGroups.length,
            largestReuseCluster,
            httpEntries: accountSummary.httpEntries.length,
            topDomains: accountSummary.topDomains
        } : null,
        historySummary: historySummary ? {
            totalEntries: historySummary.totalEntries,
            uniqueDomains: historySummary.uniqueDomains,
            highRiskCount: historySummary.highRiskCount,
            mediumRiskCount: historySummary.mediumRiskCount,
            suspiciousLogins: historySummary.suspiciousLogins.length,
            shorteners: historySummary.shorteners.length,
            overlappingDomains: historySummary.overlapping,
            topRiskDomains: historySummary.topRiskDomains
        } : null,
        scamSummary: scamAnalysis ? {
            score: scamAnalysis.score,
            severity: scamAnalysis.severity,
            scenario: scamAnalysis.scenarioLabel,
            reasons: scamAnalysis.reasons,
            actions: scamAnalysis.actions,
            indicators: scamAnalysis.indicators
        } : null,
        awarenessPack: state.auditData.awarenessPack.map(card => ({
            id: card.id,
            channel: card.channel,
            title: card.title
        })),
        attackSummary,
        recommendations: options.recommendations || []
    };
}

function exportAuditReport(format = "json") {
    const report = state.auditData.lastAuditReport || buildAuditReportPayload();
    const hasData = Boolean(
        report.profile.primaryEmail ||
        report.scamSummary ||
        state.auditData.accountEntries.length ||
        state.auditData.historyEntries.length ||
        state.auditData.awarenessPack.length ||
        $("resultText").textContent.trim()
    );

    if (!hasData) {
        alert("Run the audit or import some local data first.");
        return;
    }

    const timestamp = new Date().toISOString().replace(/[:.]/g, "-");

    if (format === "txt") {
        const textReport = [
            "Secure Vault Pro Audit Report",
            `Exported: ${report.exportedAt}`,
            report.score !== null ? `Score: ${report.score}` : "Score: not generated yet",
            "",
            `Primary email: ${report.profile.primaryEmail || "not set"}`,
            `Provider: ${report.profile.emailProvider || "unknown"}`,
            `Recovery provider: ${report.profile.recoveryProvider || "not set"}`,
            `Contacts: ${report.profile.contacts}`,
            `Password strength: ${report.profile.passwordStrength}`,
            report.scamSummary ? `Scam Decoder: ${report.scamSummary.severity} risk ${report.scamSummary.scenario}` : "Scam Decoder: not run",
            "",
            "Attack summary:",
            ...report.attackSummary.map(item => `- ${item}`),
            "",
            "Recommendations:",
            ...(report.recommendations.length ? report.recommendations.map(item => `- ${item}`) : ["- Run the full privacy audit for fuller recommendations."])
        ].join("\n");

        downloadBlob(new Blob([textReport], { type: "text/plain;charset=utf-8" }), `secure-vault-audit-${timestamp}.txt`);
        showBanner("TXT audit report downloaded.", "success");
        return;
    }

    downloadBlob(
        new Blob([JSON.stringify(report, null, 2)], { type: "application/json" }),
        `secure-vault-audit-${timestamp}.json`
    );
    showBanner("JSON audit report downloaded.", "success");
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

function buildPlaybooks(provider, recoveryProvider, passwordBreached, scamAnalysis = state.auditData.scamAnalysis) {
    const cards = [];

    cards.push({
        title: "India rapid response branch",
        description: scamAnalysis
            ? `Treat the current sample as a ${scamAnalysis.scenarioLabel.toLowerCase()} case until official verification proves otherwise.`
            : "Use this branch when a user is scared, rushed, or unsure whether a call or message is real.",
        actions: buildEmergencyChecklist(scamAnalysis).slice(0, 4),
        links: [
            { label: "Call 1930", href: "tel:1930" },
            { label: "Report cybercrime", href: "https://cybercrime.gov.in/" }
        ]
    });

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
    const scamAnalysis = state.auditData.scamAnalysis;

    const provider = detectEmailProvider(email);
    const passwordStrength = calculateStrength(password);
    const passwordBreached = await checkBreach(password);

    if (state.auditData.accountEntries.length) {
        state.auditData.accountSummary = buildAccountSummary(state.auditData.accountEntries, email);
        renderAccountImport(state.auditData.accountSummary);
    }

    if (state.auditData.historyEntries.length) {
        state.auditData.historySummary = buildHistorySummary(state.auditData.historyEntries, state.auditData.accountEntries);
        renderHistoryImport(state.auditData.historySummary);
    }

    const accountImportScore = state.auditData.accountSummary
        ? Math.max(
            10,
            92
                - Math.min(34, state.auditData.accountSummary.weakPasswords.length * 4)
                - Math.min(28, state.auditData.accountSummary.passwordGroups.length * 8)
                - Math.min(20, state.auditData.accountSummary.httpEntries.length * 5)
        )
        : 52;

    const historyImportScore = state.auditData.historySummary
        ? Math.max(
            8,
            90
                - Math.min(40, state.auditData.historySummary.highRiskCount * 12)
                - Math.min(24, state.auditData.historySummary.shorteners.length * 6)
                - Math.min(22, state.auditData.historySummary.suspiciousLogins.length * 4)
        )
        : 54;

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
            label: "Imported account hygiene",
            weight: 12,
            score: accountImportScore,
            summary: state.auditData.accountSummary
                ? `${state.auditData.accountSummary.passwordGroups.length} reuse clusters and ${state.auditData.accountSummary.weakPasswords.length} weak imported passwords.`
                : "No account export imported."
        },
        {
            label: "Browsing risk pressure",
            weight: 10,
            score: historyImportScore,
            summary: state.auditData.historySummary
                ? `${state.auditData.historySummary.highRiskCount} high-risk and ${state.auditData.historySummary.mediumRiskCount} medium-risk history entries.`
                : "No history import analyzed."
        },
        {
            label: "Live scam pressure",
            weight: 14,
            score: scamAnalysis ? Math.max(8, 100 - scamAnalysis.score) : 58,
            summary: scamAnalysis
                ? `${scamAnalysis.severity.toUpperCase()} risk ${scamAnalysis.scenarioLabel.toLowerCase()} pattern detected.`
                : "Scam Decoder has not been run yet."
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
        ...(scamAnalysis
            ? [`Treat the current message as ${scamAnalysis.scenarioLabel.toLowerCase()} until you verify it from an official source.`]
            : []),
        passwordBreached ? "Rotate the tested password before continuing to lower-priority accounts." : "Keep the tested password unique even if it looked healthy.",
        email.includes("+") ? "Keep alias-style addressing for new signups." : "Start using aliases or service-specific addresses for risky signups.",
        contacts > 750 ? "Reduce over-shared address books where possible." : "Keep high-value contacts compartmentalized from public-facing apps.",
        recoveryProvider ? `Review the backup mailbox or provider you listed: ${recoveryProvider}.` : "Add and audit a dedicated recovery channel that is different from the primary inbox."
    ];

    state.auditData.lastAuditReport = buildAuditReportPayload({
        score: totalScore,
        recommendations: nextSteps
    });

    $("resultText").classList.remove("hidden");
    $("resultText").innerHTML = formatList(findings);

    $("adviceText").classList.remove("hidden");
    $("adviceText").innerHTML = `
        <h3>Best next actions</h3>
        ${formatList(nextSteps)}
    `;

    renderPlaybooks(buildPlaybooks(provider, recoveryProvider, passwordBreached, scamAnalysis));
    renderTimeline([
        { title: "Stop the scam flow", detail: scamAnalysis ? (scamAnalysis.actions[0] || "Pause and verify using an official channel.") : "Pause, verify, and do not follow the incoming message path." },
        { title: "Lock the primary account", detail: "Review active sessions, recovery channels, and outstanding alerts first." },
        { title: "Rotate exposed secrets", detail: passwordBreached ? "Reset the tested password everywhere it may be reused." : "Confirm each important account has a unique secret." },
        { title: "Compartmentalize future signups", detail: provider.key === "proton" ? "Use Proton aliases to isolate new services." : "Use aliases and separate recovery paths for risky services." }
    ]);
    renderAttackSurfaceInsights(email);
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
