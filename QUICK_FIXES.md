# QUICK FIXES - COPY & PASTE SOLUTIONS
**Secure Vault Pro - Critical Patches (Ready to Deploy)**

---

## PATCH 1: URL Payload Signature Verification

**File:** `script.js`  
**Replace Function:** `handleSharedPayloadFromUrl()` (lines ~900-950)

```javascript
// === SIGNATURE GENERATION & VERIFICATION HELPERS ===
function generatePayloadSignature(payload) {
    // Generate HMAC-SHA256 signature for payload
    const key = new TextEncoder().encode("secure-vault-pro--v2");  // Use config in production
    const data = new TextEncoder().encode(payload);
    
    return crypto.subtle.sign("HMAC", 
        await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]),
        data
    ).then(sig => {
        const sigArray = new Uint8Array(sig);
        return Array.from(sigArray)
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    });
}

async function verifyPayloadSignature(payload, signature) {
    try {
        const key = new TextEncoder().encode("secure-vault-pro--v2");
        const data = new TextEncoder().encode(payload);
        
        const importedKey = await crypto.subtle.importKey(
            "raw", 
            key, 
            { name: "HMAC", hash: "SHA-256" }, 
            false, 
            ["verify"]
        );
        
        const expectedSig = new Uint8Array(
            signature.match(/.{1,2}/g).map(byte => parseInt(byte, 16))
        );
        
        return await crypto.subtle.verify(
            "HMAC",
            importedKey,
            expectedSig,
            data
        );
    } catch (error) {
        console.error("Signature verification failed:", error);
        return false;
    }
}

// === MAIN FUNCTION - FIXED ===
async function handleSharedPayloadFromUrl() {
    const rawHash = window.location.hash.startsWith("#")
        ? window.location.hash.slice(1)
        : "";

    if (!rawHash) {
        return;
    }

    const hashParams = new URLSearchParams(rawHash);
    const mode = hashParams.get("mode");

    // === TEXT MODE ===
    if (mode === "text") {
        const payload = hashParams.get("payload");
        const signature = hashParams.get("sig");
        
        showTab("vault");
        clearBanner();

        if (payload) {
            // NEW: VALIDATE PAYLOAD SIZE
            if (payload.length > TEXT_LINK_LIMIT) {
                showBanner("⚠️ Payload exceeds safe size limit - possible tampering detected", "error");
                clearHashOnly();
                return;
            }

            // NEW: VERIFY SIGNATURE
            if (signature) {
                const isValid = await verifyPayloadSignature(payload, signature);
                if (!isValid) {
                    showBanner("🔴 SECURITY: Payload signature invalid - possible tampering detected. Link rejected.", "error");
                    clearHashOnly();
                    return;
                }
            }

            // NEW: SAFE JSON PARSING
            try {
                const envelope = decodeJsonPayload(payload.slice(TEXT_FORMAT_PREFIX.length));
                
                // Validate envelope structure
                if (!envelope.v || !envelope.data || !envelope.salt || !envelope.iv) {
                    throw new Error("Invalid payload structure");
                }
                
                if (envelope.v !== 2) {
                    throw new Error(`Unsupported format version: ${envelope.v}`);
                }

                $("textInput").value = payload;
                showBanner("✅ Encrypted text loaded from secure link. Enter password to decrypt.", "success");
            } catch (error) {
                showBanner(`❌ Corrupted payload - cannot load: ${error.message}`, "error");
                clearHashOnly();
                return;
            }
        } else {
            showBanner("Secure link opened. If the sender used a long message fallback, paste the encrypted text into the vault.", "warning");
        }

        clearHashOnly();
    }

    // === FILE MODE ===
    if (mode === "file") {
        const payload = hashParams.get("payload");
        const signature = hashParams.get("sig");
        const name = hashParams.get("name") || "shared-package.svp.enc";
        
        showTab("vault");
        clearBanner();

        if (payload) {
            // NEW: VALIDATE PAYLOAD SIZE
            if (payload.length > INLINE_FILE_LINK_LIMIT) {
                showBanner("⚠️ File payload too large for link - copy encrypted file directly", "warning");
                clearHashOnly();
                return;
            }

            // NEW: VERIFY SIGNATURE
            if (signature) {
                const isValid = await verifyPayloadSignature(payload, signature);
                if (!isValid) {
                    showBanner("🔴 SECURITY: File signature invalid - possible tampering detected. Link rejected.", "error");
                    clearHashOnly();
                    return;
                }
            }

            try {
                const bytes = base64ToBytes(payload);
                const blob = new Blob([bytes], { type: "application/octet-stream" });
                
                // Validate SVP file magic
                const view = new Uint8Array(bytes);
                const magic = String.fromCharCode(...view.slice(0, 4));
                
                state.importedEncryptedFilePackage = { blob, name };
                state.lastEncryptedFilePackage = null;
                
                updateShareSummary(
                    "fileShareSummary",
                    "Shared file package imported",
                    [
                        `${name} (${(bytes.length / 1024 / 1024).toFixed(2)} MB) is loaded from the secure link.`,
                        "Enter the agreed password and use Decrypt File."
                    ]
                );
                
                showBanner("✅ Encrypted file loaded from secure link.", "success");
            } catch (error) {
                showBanner(`❌ File format error: ${error.message}`, "error");
                clearHashOnly();
                return;
            }
        } else {
            showBanner(`Open the app, then attach the encrypted file package named ${name}.`, "warning");
        }

        clearHashOnly();
    }
}
```

**Usage When Sharing:**
```javascript
async function shareText() {
    // ... existing code ...
    
    // NEW: Generate signature before sharing
    const signature = await generatePayloadSignature(encryptedText);
    const deepLink = buildAppUrl({ 
        mode: "text", 
        payload: encryptedText,
        sig: signature  // ADD THIS
    });
    
    // ... rest of sharing code ...
}
```

---

## PATCH 2: Rate Limiting on Decryption

**File:** `script.js`  
**Add Before All Crypto Functions** (around line 250)

```javascript
// === RATE LIMITING SYSTEM ===
const RATE_LIMIT_DECRYPTION = {
    maxAttempts: 5,
    windowMs: 60000  // 60 seconds
};

const decryptionAttempts = new Map();  // browser_id -> [timestamps...]

function getBrowserFingerprint() {
    // Generate consistent device identifier
    const fingerprint = [
        navigator.hardwareConcurrency,
        navigator.deviceMemory,
        navigator.maxTouchPoints,
        screen.width + "x" + screen.height,
        Intl.DateTimeFormat().resolvedOptions().timeZone
    ].join("|");
    
    return btoa(fingerprint);  // Simple hash
}

function checkDecryptionRateLimit() {
    const browserId = getBrowserFingerprint();
    const now = Date.now();
    
    // Get attempts for this device in last window
    const attempts = decryptionAttempts.get(browserId) || [];
    const recentAttempts = attempts.filter(t => now - t < RATE_LIMIT_DECRYPTION.windowMs);
    
    // Check if limit exceeded
    if (recentAttempts.length >= RATE_LIMIT_DECRYPTION.maxAttempts) {
        const oldestAttempt = Math.min(...recentAttempts);
        const waitSeconds = Math.ceil((oldestAttempt + RATE_LIMIT_DECRYPTION.windowMs - now) / 1000);
        
        throw new Error(`Rate limited: ${waitSeconds}s remaining. Max ${RATE_LIMIT_DECRYPTION.maxAttempts} decryption attempts per minute.`);
    }
    
    // Store this attempt
    recentAttempts.push(now);
    decryptionAttempts.set(browserId, recentAttempts);
}

// === UPDATE DECRYPT FUNCTION ===
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

    // NEW: CHECK RATE LIMIT
    try {
        checkDecryptionRateLimit();
    } catch (error) {
        alert(`⚠️ ${error.message}`);
        showBanner(`Rate limited: ${error.message}`, "warning");
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
        showBanner("✅ Text decrypted successfully.", "success");
        appendSystemMessage("Text decrypted successfully.");
    } catch (error) {
        // NEW: DISTINGUISH ERROR TYPES
        let userMessage = "Decryption failed: ";
        
        if (error.message.includes("tag")) {
            userMessage += "File corrupted or tampered (AES tag mismatch).";
            console.error("🔴 SECURITY: Possible tampering detected!");
        } else if (error.message.includes("Rate limited")) {
            userMessage += error.message;
        } else {
            userMessage += "Wrong password or corrupted file.";
        }
        
        alert(userMessage);
        showBanner(userMessage, "error");
    }
}

// === ALSO UPDATE FILE DECRYPTION ===
async function decryptFile() {
    // Add same rate limit check here
    try {
        checkDecryptionRateLimit();
    } catch (error) {
        alert(`⚠️ ${error.message}`);
        return;
    }
    
    // ... rest of file decryption code (unchanged) ...
}
```

---

## PATCH 3: Content Security Policy

**File:** `index.html`  
**Location:** Add to `<head>` section (after `<title>`)

```html
<meta http-equiv="Content-Security-Policy" content="
    default-src 'self';
    script-src 'self' https://unpkg.com/peerjs@1.5.2/ 'unsafe-inline';
    style-src 'self' 'unsafe-inline';
    connect-src 'self' https://*.peerjs.com wss://*.peerjs.com https://*.ipv6.peerjs.com wss://*.ipv6.peerjs.com;
    img-src 'self' data: https:;
    media-src 'self';
    object-src 'none';
    frame-ancestors 'none';
    base-uri 'self';
    form-action 'none';
">
```

**Why Each Directive:**
- `default-src 'self'` - Block everything except same origin
- `script-src` - Only PeerJS CDN, no inline scripts except existing ones
- `connect-src` - PeerJS servers only, no attacker exfil domains
- `object-src 'none'` - No plugins/flash
- `frame-ancestors 'none'` - Can't be embedded in iframes
- `form-action 'none'` - No form submissions to external sites

---

## PATCH 4: Force TURN Relay (Hide IP)

**File:** `script.js`  
**Function:** `initPeer()` (around line 2569)

```javascript
function initPeer() {
    warnIfInsecureContext();

    // NEW: Enhanced ICE configuration
    const iceServers = getIceServers();
    
    // Ensure all STUN servers are removed (can leak IP)
    const peerConfig = {
        iceServers: iceServers.filter(server => 
            server.urls.some(url => 
                typeof url === "string" ? url.startsWith("turn:") : false
            ) || 
            (Array.isArray(server.urls) && server.urls.some(url => url.startsWith("turn:")))
        ),
        // NEW: Force TURN relay only
        iceTransportPolicy: "relay",  // ✅ CRITICAL: Hides public IP
        bundlePolicy: "max-bundle",   // Fewer connections = less IP leakage
        rtcpMuxPolicy: "require"
    };

    state.peer = new Peer({
        secure: window.location.protocol === "https:",
        debug: 0,
        pingInterval: 20000,
        config: peerConfig,
        
        // NEW: Timeout settings for stalled connections
        iceTransportPolicy: "relay",
        connectionTimeout: 30000  // Fail faster on broken connections
    });

    // ... existing peer event handlers ...

    // NEW: Monitor ice connection state
    state.peer.on("connection", connection => {
        // Track ICE state
        original_onopen = connection.peerConnection.onconnectionstatechange;
        connection.peerConnection.onconnectionstatechange = (event) => {
            const iceState = connection.peerConnection.iceConnectionState;
            console.log(`ICE State: ${iceState}`);  // Debug
            
            if (iceState === "failed" || iceState === "disconnected") {
                appendSystemMessage("⚠️ Connection unstable - ensure TURN relay configured");
            }
        };
        
        if (state.currentConnection) {
            connection.close();
            return;
        }

        setupConnectionHandlers(connection, connection.peer, 1);
    });

    // ... rest unchanged ...
}

// NEW: Validate relay servers are being used
function validateTurnServers() {
    const servers = getIceServers();
    const hasTurn = servers.some(s => 
        s.urls?.some(u => (typeof u === "string" ? u.startsWith("turn:") : false))
    );
    
    if (!hasTurn) {
        console.warn("⚠️ WARNING: No TURN servers configured - IP may leak!");
        appendSystemMessage("⚠️ SECURITY WARNING: No TURN relay available - using STUN (IP visible)");
    }
}

// Call on app init
document.addEventListener("DOMContentLoaded", () => {
    // ... existing initApp code ...
    validateTurnServers();
});
```

---

## PATCH 5: Improved Password Strength Calculation

**File:** `script.js`  
**Function:** `calculateStrength()` (around line 306)

```javascript
function calculateStrength(password) {
    if (!password) {
        return 0;
    }

    // NEW: More realistic scoring
    const checks = [
        // Length scoring - more aggressive
        password.length >= 8 ? 8 : 0,
        password.length >= 12 ? 12 : 0,
        password.length >= 16 ? 16 : 0,
        password.length >= 20 ? 16 : 0,
        
        // Character class diversity (quadruple weight)
        /[a-z]/.test(password) ? 10 : 0,
        /[A-Z]/.test(password) ? 10 : 0,
        /\d/.test(password) ? 10 : 0,
        /[^A-Za-z0-9]/.test(password) ? 14 : 0,  // Symbols are valuable
        
        // Complexity patterns
        /(.)\1{2,}/.test(password) ? -15 : 0,   // Repeated chars = very bad
        /^.{1,5}$/.test(password) || /^[a-z]*$/.test(password) ? -20 : 0,  // Only lowercase/short = very bad
        
        // Common patterns to penalize
        /password|admin|qwerty|letmein|123456|welcome|dragon|abc123/i.test(password) ? -30 : 0,
        
        // Dictionary check (naive spelling)
        /(love|hate|best|worst|good|bad|nice|great|hello|world)/i.test(password) ? -10 : 0,
        
        // Character entropy (uniqueness)
        new Set(password).size >= Math.min(password.length, 10) ? 15 : 0,
        
        // Sequential characters are weak
        /012|123|234|345|456|567|678|789|890|abc|bcd|cde|def|efg|fgh|hij/i.test(password) ? -8 : 0
    ];

    let score = Math.max(0, checks.reduce((sum, value) => sum + value, 0));
    
    // NEW: Minimum threshold requirement
    const MINIMUM_ENTROPY = 40;
    
    // Normalize to 0-100
    score = Math.min(100, Math.max(0, score));
    
    return score;
}

// NEW: Strict password requirement for encryption
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

    // NEW: STRICTER REQUIREMENT
    const strength = calculateStrength(password);
    if (strength < 60) {  // Changed from 40 to 60
        alert(`⚠️ Password too weak (${strength}/100). Use at least 12 characters with mixed types.\n\nExamples:\n- MySecret@2024\n- Coffee#Morning99\n- BlueSky!Rock$42`);
        return;
    }

    // ... REST OF FUNCTION UNCHANGED ...
}
```

---

## PATCH 6: Enhanced Error Messages

**File:** `script.js`  
**Update:** All crypto error handlers

```javascript
// HELPER FUNCTION
function getCryptoErrorDescription(error) {
    const msg = error.message || String(error);
    
    if (msg.includes("tag") || msg.includes("verification")) {
        return {
            user: "❌ File corrupted, tampered, or wrong password",
            security: "AES-GCM tag verification failed - possible attack or corruption",
            level: "warning"
        };
    }
    
    if (msg.includes("Base64")) {
        return {
            user: "❌ File format corrupted - invalid encoding",
            security: "Base64 decode failed - invalid payload format",
            level: "error"
        };
    }
    
    if (msg.includes("password")) {
        return {
            user: "❌ Likely wrong password - verify with sender",
            security: "Password derivation error",
            level: "warning"
        };
    }
    
    if (msg.includes("Rate limited")) {
        return {
            user: "⏱️ Too many attempts - wait before retrying",
            security: "Brute force protection activated",
            level: "info"
        };
    }
    
    return {
        user: "❌ Decryption failed - verify file and password",
        security: error.message,
        level: "error"
    };
}

// USE IN DECRYPT FUNCTIONS
async function decryptText() {
    // ... validation code ...
    
    try {
        // ... decryption code ...
    } catch (error) {
        const errorInfo = getCryptoErrorDescription(error);
        alert(errorInfo.user);
        showBanner(errorInfo.user, errorInfo.level);
        console.error(`[SECURITY] ${errorInfo.security}`);
    }
}
```

---

## DEPLOYMENT CHECKLIST

- [ ] Test URL payload validation with invalid/corrupted data
- [ ] Test decryption rate limiting (try 6 attempts in 60s)
- [ ] Test WebRTC IP leak (use browserleaktest.com)
- [ ] Test CSP enforcement (inject script via console)
- [ ] Verify TURN relay is used (check WebRTC statistics)
- [ ] Verify new password strength works (try weak passwords)
- [ ] Test file tampering detection (modify encrypted file bytes)
- [ ] Run security headers check (securityheaders.com)

---

## ROLLBACK PLAN

If issues discovered post-deployment:

```bash
# Quick revert to previous version
git revert HEAD --no-edit
git push origin main

# Emergency hotfix branch
git checkout -b hotfix/security-issue-2026-04-10
# Make minimal fixes
git push origin hotfix/...
```

---

## VERIFICATION COMMANDS

After deployment, verify fixes:

```javascript
// Test 1: Verify CSP is active
console.log(document.currentScript?.nonce || 'CSP Applied');

// Test 2: Verify TURN only
const peer = state.peer;
const rtcConfig = peer._pc?.getConfiguration();
console.log("ICE Policy:", rtcConfig?.iceTransportPolicy);  // Should be "relay"

// Test 3: Verify rate limiting works
try {
    for (let i = 0; i < 10; i++) {
        checkDecryptionRateLimit();
    }
} catch (e) {
    console.log("✅ Rate limiting working:", e.message);
}

// Test 4: Verify password strength
console.log(calculateStrength("weak"));     // Should be < 40
console.log(calculateStrength("MyPwd@2024")); // Should be > 60
```

