let chatWarningShown = false;

function showTab(tab) {
    document.getElementById("vault").classList.add("hidden");
    document.getElementById("risk").classList.add("hidden");
    document.getElementById("chat").classList.add("hidden");

    document.getElementById("vaultTab").classList.remove("active");
    document.getElementById("riskTab").classList.remove("active");
    document.getElementById("chatTab").classList.remove("active");

    document.getElementById(tab).classList.remove("hidden");
    document.getElementById(tab + "Tab").classList.add("active");

    if (tab === "chat" && !chatWarningShown) {
        chatWarningShown = true;
        setTimeout(() => {
            appendSystemMessage("⚠️ PRECAUTION: Do not use for illegal activities. While data is transported securely natively, the person on the other end can record their own screen. Use responsibly.");
        }, 100);
    }
}

/* ================= PASSWORD STRENGTH ================= */

function calculateStrength(p) {
    let s = 0;
    if (p.length >= 8) s += 20;
    if (/[A-Z]/.test(p)) s += 20;
    if (/[a-z]/.test(p)) s += 10;
    if (/[0-9]/.test(p)) s += 20;
    if (/[^A-Za-z0-9]/.test(p)) s += 20;
    if (p.length >= 12) s += 10;
    return s;
}

function displayStrength(id, value) {
    let el = document.getElementById(id);
    let score = calculateStrength(value);

    if (!value) { el.innerText = ""; return; }

    if (score < 40) {
        el.innerText = "Weak – Add uppercase, numbers, symbols";
        el.className = "strength weak";
    }
    else if (score < 70) {
        el.innerText = "Medium – Increase length for better security";
        el.className = "strength medium";
    }
    else {
        el.innerText = "Strong – Good security level";
        el.className = "strength strong";
    }
}

function checkTextStrength() {
    displayStrength("textStrength", document.getElementById("textPassword").value);
}

function checkFileStrength() {
    displayStrength("fileStrength", document.getElementById("filePassword").value);
}

function checkRiskStrength() {
    displayStrength("riskStrength", document.getElementById("passwordInput").value);
}

/* ================= TEXT ENCRYPTION ================= */

async function encryptText() {
    let text = document.getElementById("textInput").value;
    let p1 = document.getElementById("textPassword").value;
    let p2 = document.getElementById("textConfirmPassword").value;
    if (!p1 || p1 !== p2) { alert("Password mismatch"); return; }

    let enc = new TextEncoder();
    let keyMaterial = await crypto.subtle.importKey("raw", enc.encode(p1), { name: "PBKDF2" }, false, ["deriveKey"]);
    let key = await crypto.subtle.deriveKey({
        name: "PBKDF2", salt: enc.encode("vault"),
        iterations: 120000, hash: "SHA-256"
    }, keyMaterial, { name: "AES-GCM", length: 256 }, false, ["encrypt"]);

    let iv = crypto.getRandomValues(new Uint8Array(12));
    let encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(text));
    document.getElementById("textOutput").value = btoa(String.fromCharCode(...iv, ...new Uint8Array(encrypted)));
}

async function decryptText() {
    try {
        let data = atob(document.getElementById("textInput").value);
        let password = document.getElementById("textPassword").value;

        let bytes = Uint8Array.from(data, c => c.charCodeAt(0));
        let iv = bytes.slice(0, 12);
        let encrypted = bytes.slice(12);

        let enc = new TextEncoder();
        let keyMaterial = await crypto.subtle.importKey("raw", enc.encode(password), { name: "PBKDF2" }, false, ["deriveKey"]);
        let key = await crypto.subtle.deriveKey({
            name: "PBKDF2", salt: enc.encode("vault"),
            iterations: 120000, hash: "SHA-256"
        }, keyMaterial, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);

        let decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, encrypted);
        document.getElementById("textOutput").value = new TextDecoder().decode(decrypted);
    } catch { alert("Wrong password or invalid data"); }
}

function shareText() {
    let data = document.getElementById("textOutput").value;
    if (!data) { alert("Nothing to share"); return; }
    navigator.clipboard.writeText(data);
    alert("Copied to clipboard");
}

function clearText() {
    document.getElementById("textInput").value = "";
    document.getElementById("textOutput").value = "";
}

/* ================= FILE ENCRYPTION ================= */

let lastEncryptedFileBlob = null;

async function encryptFile() {
    let file = document.getElementById("fileInput").files[0];
    let password = document.getElementById("filePassword").value;
    let confirm = document.getElementById("fileConfirmPassword").value;
    if (!file || password !== confirm) { alert("Check file or password"); return; }

    let buffer = await file.arrayBuffer();
    let enc = new TextEncoder();

    let keyMaterial = await crypto.subtle.importKey("raw", enc.encode(password), { name: "PBKDF2" }, false, ["deriveKey"]);
    let key = await crypto.subtle.deriveKey({
        name: "PBKDF2", salt: enc.encode("vault"),
        iterations: 120000, hash: "SHA-256"
    }, keyMaterial, { name: "AES-GCM", length: 256 }, false, ["encrypt"]);

    let iv = crypto.getRandomValues(new Uint8Array(12));
    let encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, buffer);

    lastEncryptedFileBlob = new Blob([iv, new Uint8Array(encrypted)]);
    let link = document.createElement("a");
    link.href = URL.createObjectURL(lastEncryptedFileBlob);
    link.download = file.name + ".enc";
    link.click();
}

function shareFile() {
    if (!lastEncryptedFileBlob) { alert("No encrypted file yet"); return; }
    navigator.clipboard.writeText("Encrypted file ready. Share downloaded file.");
    alert("File ready to share.");
}

function clearFile() {
    document.getElementById("fileInput").value = "";
}

/* ================= RISK ANALYZER ================= */

async function runScan() {

    let score = 0;
    let findings = [];

    let email = document.getElementById("emailInput").value;
    let username = document.getElementById("usernameInput").value;
    let password = document.getElementById("passwordInput").value;
    let contacts = parseInt(document.getElementById("contactInput").value) || 0;

    // PASSWORD
    let strength = calculateStrength(password);
    score += (100 - strength);
    if (strength < 50) findings.push("Weak password");

    let breached = await checkBreach(password);
    if (breached) { score += 30; findings.push("Password found in breach database"); }

    // EMAIL
    if (email) {
        if (email.length < 8) { score += 10; findings.push("Short email"); }
        if (email.includes("123")) { score += 10; findings.push("Predictable email pattern"); }
    }

    // USERNAME
    if (username) {
        if (username.length < 5) { score += 10; findings.push("Short username"); }
        if (username.includes("123")) { score += 10; }
    }

    // CONTACT SURFACE
    if (contacts > 500) { score += 10; findings.push("Large contact exposure surface"); }
    if (contacts > 1000) { score += 10; }

    if (score > 100) score = 100;

    animateWheel(score, findings);

    document.getElementById("passwordInput").value = "";
}

async function checkBreach(password) {
    if (!password) return false;
    let enc = new TextEncoder();
    let hashBuffer = await crypto.subtle.digest("SHA-1", enc.encode(password));
    let hashArray = Array.from(new Uint8Array(hashBuffer));
    let hashHex = hashArray.map(b => b.toString(16).padStart(2, "0")).join("").toUpperCase();

    let prefix = hashHex.substring(0, 5);
    let suffix = hashHex.substring(5);

    let res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
    let txt = await res.text();
    return txt.includes(suffix);
}

function animateWheel(score, findings) {
    let circle = document.getElementById("progressCircle");
    let radius = 85;
    let circumference = 2 * Math.PI * radius;
    let current = 0;

    let interval = setInterval(() => {
        if (current >= score) { clearInterval(interval); return; }
        current++;
        circle.style.strokeDashoffset = circumference - (current / 100) * circumference;

        if (current > 60) circle.style.stroke = "red";
        else if (current > 30) circle.style.stroke = "orange";
        else circle.style.stroke = "green";

        document.getElementById("scoreText").innerText = current;
    }, 10);

    document.getElementById("resultText").innerText =
        findings.length ? findings.join(" • ") : "No major exposure detected.";
}

/* ================= SECURE CHAT ================= */

let peer = null;
let currentConnection = null;

function initPeer() {
    // Initialize PeerJS to generate our unique ID
    peer = new Peer({
        config: {
            'iceServers': [
                { urls: 'stun:stun.l.google.com:19302' },
                { urls: 'stun:stun1.l.google.com:19302' }
            ]
        }
    });

    peer.on('open', (id) => {
        document.getElementById('myPeerId').value = id;

        // Check for auto-connect invite link
        const urlParams = new URLSearchParams(window.location.search);
        const connectToId = urlParams.get('connect');
        if (connectToId) {
            document.getElementById('connectId').value = connectToId;
            showTab('chat');
            setTimeout(() => connectToPeer(), 500);
        }
    });

    peer.on('connection', (conn) => {
        if (currentConnection) {
            conn.close(); // Only allow one connection at a time
            return;
        }
        setupConnectionStatus(conn);
    });

    peer.on('error', (err) => {
        console.error("PeerJS error:", err);
        appendSystemMessage("Error: " + err.type);
        updateConnectionStatus("Connection Error");
    });

    peer.on('call', (call) => {
        if (currentCall) {
            call.close();
            return;
        }
        answerCall(call);
    });
}

function connectToPeer() {
    let connectId = document.getElementById("connectId").value.trim();
    if (!connectId) {
        alert("Please enter an ID to connect.");
        return;
    }
    if (connectId === document.getElementById('myPeerId').value) {
        alert("Cannot connect to yourself.");
        return;
    }
    if (currentConnection) {
        currentConnection.close();
    }
    updateConnectionStatus("Connecting...");
    let conn = peer.connect(connectId);
    setupConnectionStatus(conn);
}

function setupConnectionStatus(conn) {
    currentConnection = conn;

    const onConnectionOpen = () => {
        updateConnectionStatus("Connected to peer!");
        appendSystemMessage("Secure connection established.");
        document.getElementById("connectId").value = "";
        document.getElementById("callControls").classList.remove('hidden');
    };

    conn.on('open', onConnectionOpen);

    // Fallback for receiver if it's already open
    if (conn.open) {
        onConnectionOpen();
    }

    conn.on('data', (data) => {
        if (typeof data === 'string') {
            appendMessage(data, 'peer');
        } else if (data.type === 'text') {
            appendMessage(data.content, 'peer');
        } else if (data.type === 'media') {
            renderIncomingMedia(data);
        }
    });

    conn.on('close', () => {
        updateConnectionStatus("Connection closed.");
        appendSystemMessage("Peer disconnected.");
        document.getElementById("callControls").classList.add('hidden');
        endCall();
        currentConnection = null;
    });
}

function sendChatMessage() {
    if (!currentConnection || !currentConnection.open) {
        alert("Not connected to a peer. Please connect first.");
        return;
    }
    let input = document.getElementById('chatInput');
    let msg = input.value.trim();
    if (!msg) return;

    currentConnection.send({ type: 'text', content: msg });
    appendMessage(msg, 'self');
    input.value = '';
}

function handleChatKeyPress(event) {
    if (event.key === 'Enter') {
        sendChatMessage();
    }
}

function copyMyId() {
    let myId = document.getElementById('myPeerId').value;
    if (myId) {
        navigator.clipboard.writeText(myId);
        alert("ID copied to clipboard!");
    }
}

function appendMessage(text, type) {
    let msgDiv = document.createElement("div");
    msgDiv.className = "chat-msg " + type;
    msgDiv.innerText = text;

    let chatBox = document.getElementById("chatMessages");
    chatBox.appendChild(msgDiv);
    chatBox.scrollTop = chatBox.scrollHeight;
}

function appendSystemMessage(text) {
    appendMessage(text, 'system');
}

function updateConnectionStatus(msg) {
    let el = document.getElementById("connectionStatus");
    el.innerText = msg;
    if (msg.includes("Connected")) {
        el.classList.add("connected");
    } else {
        el.classList.remove("connected");
    }
}

// Initialize Peer automatically when the script loads
function generateInviteLink() {
    let myId = document.getElementById('myPeerId').value;
    if (!myId) return;
    let url = window.location.origin + window.location.pathname + "?connect=" + myId;
    navigator.clipboard.writeText(url);
    alert("Invite link copied! Send it to your friend to securely connect.");
}

async function sendMediaFile() {
    if (!currentConnection || !currentConnection.open) {
        alert("Not connected to a peer.");
        return;
    }
    let fileInput = document.getElementById('mediaInput');
    let file = fileInput.files[0];
    if (!file) return;

    if (file.size > 50 * 1024 * 1024) {
        alert("File too large. Limit is 50MB.");
        fileInput.value = "";
        return;
    }

    let buffer = await file.arrayBuffer();
    currentConnection.send({
        type: 'media',
        mime: file.type,
        name: file.name,
        buffer: buffer
    });

    appendMessage("📎 Sent media: " + file.name, 'self');
    fileInput.value = "";
}

function renderIncomingMedia(data) {
    let msgDiv = document.createElement("div");
    msgDiv.className = "chat-msg peer media-message-container";
    msgDiv.oncontextmenu = (e) => { e.preventDefault(); return false; };
    msgDiv.ondragstart = (e) => { e.preventDefault(); return false; };

    let blob = new Blob([data.buffer], { type: data.mime });
    let url = URL.createObjectURL(blob);

    let mediaEl;
    if (data.mime.startsWith("image/")) {
        mediaEl = document.createElement("img");
        mediaEl.src = url;
    } else if (data.mime.startsWith("video/")) {
        mediaEl = document.createElement("video");
        mediaEl.src = url;
        mediaEl.loop = true;
    } else if (data.mime.startsWith("audio/")) {
        mediaEl = document.createElement("audio");
        mediaEl.src = url;
    } else {
        appendMessage("📎 Received file: " + data.name + " (Unsupported media type)", "peer");
        return;
    }

    let overlay = document.createElement("div");
    overlay.className = "media-overlay";
    overlay.innerText = "🔒 Hold to View\n(10s max)";

    msgDiv.appendChild(mediaEl);
    msgDiv.appendChild(overlay);

    let chatBox = document.getElementById("chatMessages");
    chatBox.appendChild(msgDiv);
    chatBox.scrollTop = chatBox.scrollHeight;

    let viewTimeout;
    let isRevealed = false;

    const startViewing = (e) => {
        if (e.type !== "touchstart") e.preventDefault();
        if (isRevealed) return;
        isRevealed = true;
        msgDiv.classList.add("revealed");

        if (mediaEl.tagName === 'VIDEO' || mediaEl.tagName === 'AUDIO') {
            mediaEl.play().catch(e => console.log("Autoplay prevented:", e));
        }

        viewTimeout = setTimeout(() => {
            destroyMedia();
        }, 10000); // 10s view max 
    };

    const stopViewing = (e) => {
        if (!isRevealed) return;
        destroyMedia();
    };

    const destroyMedia = () => {
        clearTimeout(viewTimeout);
        URL.revokeObjectURL(url);
        msgDiv.innerHTML = "<span style='color:#ef4444; font-style:italic; font-size:12px;'>Media permanently destroyed</span>";
        msgDiv.classList.remove("media-message-container");
        window.removeEventListener('mouseup', stopViewing);
        window.removeEventListener('touchend', stopViewing);
    };

    overlay.addEventListener('mousedown', startViewing);
    overlay.addEventListener('touchstart', startViewing);
    window.addEventListener('mouseup', stopViewing);
    window.addEventListener('touchend', stopViewing);
}

/* ================= AUDIO / VIDEO CALLS ================= */

let localStream = null;
let currentCall = null;

async function startCall(videoEnabled) {
    if (!currentConnection || !currentConnection.open) {
        alert("Connect to a peer first.");
        return;
    }

    try {
        localStream = await navigator.mediaDevices.getUserMedia({
            video: videoEnabled,
            audio: true
        });

        document.getElementById('localVideo').srcObject = localStream;
        document.getElementById('videoContainer').classList.remove('hidden');

        currentCall = peer.call(currentConnection.peer, localStream);
        setupCallHandlers(currentCall);
        appendSystemMessage((videoEnabled ? "Video" : "Audio") + " call started...");
        document.getElementById("callControls").classList.add('hidden'); // Hide start buttons during active call

    } catch (err) {
        console.error("Failed to get local stream", err);
        alert("Could not access camera/microphone. Check permissions.");
    }
}

async function answerCall(call) {
    try {
        let wantVideo = confirm("Incoming call. Answer with video?");

        localStream = await navigator.mediaDevices.getUserMedia({
            video: wantVideo,
            audio: true
        });

        document.getElementById('localVideo').srcObject = localStream;
        document.getElementById('videoContainer').classList.remove('hidden');

        call.answer(localStream);
        currentCall = call;
        setupCallHandlers(currentCall);
        appendSystemMessage("Call answered.");
        document.getElementById("callControls").classList.add('hidden'); // Hide start buttons during active call

    } catch (err) {
        console.error("Failed to get local stream", err);
        alert("Could not answer call. Check permissions.");
    }
}

function setupCallHandlers(call) {
    call.on('stream', (remoteStream) => {
        document.getElementById('remoteVideo').srcObject = remoteStream;
    });

    call.on('close', () => {
        endCall();
    });
}

function endCall() {
    if (currentCall) {
        currentCall.close();
        currentCall = null;
    }
    if (localStream) {
        localStream.getTracks().forEach(track => track.stop());
        localStream = null;
    }
    document.getElementById('videoContainer').classList.add('hidden');
    document.getElementById('localVideo').srcObject = null;
    document.getElementById('remoteVideo').srcObject = null;
    if (currentConnection && currentConnection.open) {
        document.getElementById("callControls").classList.remove('hidden'); // Bring back buttons 
    }
    appendSystemMessage("Call ended.");
}

// Initialize Peer automatically when the script loads
initPeer();

/* ================= SAFETY & REVIEW CONTROLS ================= */

function checkTerms() {
    if (localStorage.getItem("termsAccepted") !== "true") {
        document.getElementById("termsModal").classList.remove("hidden");
    } else {
        document.getElementById("termsModal").classList.add("hidden");
    }
}

function acceptTerms() {
    localStorage.setItem("termsAccepted", "true");
    document.getElementById("termsModal").classList.add("hidden");
}

// Exit prevention to save users from accidental reload loop
window.addEventListener("beforeunload", function (e) {
    // Set message for older browsers
    const confirmationMessage = "Are you sure you want to exit? Your secure connection and all local chat/vault data will be permanently destroyed.";
    (e || window.event).returnValue = confirmationMessage;
    return confirmationMessage;
});

// Run terms check on load
document.addEventListener('DOMContentLoaded', checkTerms);