// SECURITY PATCHES - Add these helper functions to script.js after the escapeHtml function

// SECURITY PATCH: Helper functions for rate limiting and error handling
function getBrowserFingerprint() {
    const fingerprint = [
        navigator.hardwareConcurrency,
        navigator.deviceMemory,
        navigator.maxTouchPoints,
        screen.width + "x" + screen.height,
        Intl.DateTimeFormat().resolvedOptions().timeZone
    ].join("|");
    return btoa(fingerprint);
}

function checkDecryptionRateLimit() {
    const browserId = getBrowserFingerprint();
    const now = Date.now();
    const attempts = decryptionAttempts.get(browserId) || [];
    const recentAttempts = attempts.filter(t => now - t < RATE_LIMIT_DECRYPTION.windowMs);
    
    if (recentAttempts.length >= RATE_LIMIT_DECRYPTION.maxAttempts) {
        const oldestAttempt = Math.min(...recentAttempts);
        const waitSeconds = Math.ceil((oldestAttempt + RATE_LIMIT_DECRYPTION.windowMs - now) / 1000);
        throw new Error(`Rate limited: ${waitSeconds}s remaining. Max ${RATE_LIMIT_DECRYPTION.maxAttempts} decryption attempts per minute.`);
    }
    
    recentAttempts.push(now);
    decryptionAttempts.set(browserId, recentAttempts);
}

function getCryptoErrorDescription(error) {
    const msg = error.message || String(error);
    
    if (msg.includes("tag") || msg.includes("verification")) {
        return { 
            user: "File corrupted, tampered, or wrong password", 
            security: "AES-GCM tag verification failed - possible attack or corruption", 
            level: "warning" 
        };
    }
    if (msg.includes("Base64")) {
        return { 
            user: "File format corrupted - invalid encoding", 
            security: "Base64 decode failed - invalid payload format", 
            level: "error" 
        };
    }
    if (msg.includes("Rate limited")) {
        return { 
            user: "Too many attempts - wait before retrying", 
            security: "Brute force protection activated", 
            level: "info" 
        };
    }
    return { 
        user: "Decryption failed - verify file and password", 
        security: error.message, 
        level: "error" 
    };
}
