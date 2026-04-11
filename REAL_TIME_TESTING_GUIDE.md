# REAL-TIME FEATURE TESTING GUIDE
**Deployment:** Live on http://127.0.0.1:8080  
**Date:** April 10, 2026

---

## 🚀 APPLICATION IS NOW LIVE

**Server Status:** ✅ Running on http://127.0.0.1:8080

Open browser to test. The application should load immediately.

---

## 📋 FEATURE-BY-FEATURE TESTING CHECKLIST

### FEATURE 1: File Encryption (Vault Tab)

**Test Case 1.1: Encrypt a File**

Steps:
```
1. Navigate to: http://127.0.0.1:8080
2. Click "Vault" tab (should be active)
3. Click "Choose File" button under "File Encryption" section
4. Select ANY file from your computer (e.g., document.pdf, image.jpg)
5. Enter Password: "MySecret@2024#Secure99" (meets 60+ strength requirement)
6. Confirm Password: "MySecret@2024#Secure99"
7. Click "Encrypt File" button
8. ✅ Expected: 
   - File shows in summary box
   - Download button appears
   - No errors in console
```

**Test Case 1.2: Download Encrypted File**

Steps:
```
1. After encryption, click "Share Package" button
2. ✅ Expected: Encrypted .svp file downloads
3. File name format: secure-vault-TIMESTAMP.svp
4. File size: Larger than original (due to encryption overhead)
```

**Test Case 1.3: Weak Password Prevention**

Steps:
```
1. Try password: "weak"
2. Click "Encrypt File"
3. ✅ Expected: 
   - Alert: "⚠️ Password too weak (X/100)"
   - Suggestions shown
   - Encryption blocked
4. Try password: "MySecret@2024"
5. ✅ Expected: Encryption succeeds
```

---

### FEATURE 2: Text Encryption (Vault Tab)

**Test Case 2.1: Encrypt Text**

Steps:
```
1. Click "Vault" tab > "Text Encryption" section
2. Enter Text: "This is a sensitive message from India Police"
3. Enter Password: "Police@Secure2024!"
4. Confirm Password: "Police@Secure2024!"
5. Click "Encrypt" button
6. ✅ Expected:
   - Encrypted text appears in output box
   - Starts with "SVP-TEXT:2:"
   - Long random string
```

**Test Case 2.2: Decrypt Text**

Steps:
```
1. Copy encrypted text (or leave it in "textOutput")
2. Paste into "textInput" field
3. Enter same password: "Police@Secure2024!"
4. Click "Decrypt" button
5. ✅ Expected:
   - Original text appears
   - No errors
```

**Test Case 2.3: Rate Limiting (NEW SECURITY PATCH)**

Steps:
```
1. Try decrypting 6 times rapidly (wrong password each time)
2. ✅ Expected: After 5th attempt -> "⚠️ Too many attempts. Wait 60 seconds."
3. Wait 60 seconds
4. 6th attempt works
```

**Test Case 2.4: Tamper Detection (NEW SECURITY PATCH)**

Steps:
```
1. Encrypt text with: "MySecret@2024"
2. Copy encrypted output
3. Modify ONE character in the middle
4. Paste modified text to input
5. Enter password: "MySecret@2024"
6. Try to decrypt
7. ✅ Expected: 
   - Error: "File corrupted, tampered, or wrong password"
   - Not just generic decryption error
```

---

### FEATURE 3: Scam Decoder (Safety Lab Tab)

**Test Case 3.1: Detect Digital Arrest Scam**

Steps:
```
1. Click "Safety Lab" tab
2. Find "Scam Decoder" section
3. Paste this sample:
   "This is Cyber Crime Branch. Your Aadhaar linked to illegal activity. 
    Stay on call. Transfer ₹50,000 to safe account or arrest today."
4. Click "Run Scam Decoder"
5. ✅ Expected:
   - Risk Score: 80+ (Critical/High)
   - Pattern: "Digital arrest"
   - Actions suggested
   - Confidence visible
```

**Test Case 3.2: Detect KYC Freeze Scam**

Steps:
```
1. Enter this text:
   "Dear customer, your KYC expired. Download this app now to update 
    or account will be blocked in 30 minutes."
2. Click "Run Scam Decoder"
3. ✅ Expected:
   - Risk Score: 70+ (High)
   - Pattern: "KYC freeze"
```

**Test Case 3.3: False Positive Check**

Steps:
```
1. Enter legitimate business email:
   "Hi, your shipment is delayed. Expected delivery: tomorrow."
2. Click "Run Scam Decoder"
3. ✅ Expected:
   - Low risk score (below 30)
   - Not flagged as scam
```

---

### FEATURE 4: Secure Chat (P2P Connection - TWO TAB TEST)

**IMPORTANT: This is the critical test showing WebRTC + rate limiting works**

#### **SETUP: Open Two Browser Tabs**

**Step 1: Open First Tab (USER A)**
```
1. Tab 1 URL: http://127.0.0.1:8080
2. Wait for page to fully load
3. Look for "P2P Secure Chat" section
4. See "Your Peer ID" field with a random ID
5. Write down this ID or observe it
6. Status should show: "Waiting for connection..."
```

**Step 2: Open Second Tab (USER B)**
```
1. Tab 2 URL: http://127.0.0.1:8080
2. Wait for page to fully load
3. Get the Peer ID from Tab 2
```

**Test Case 4.1: Generate Invite Link**

**In Tab 1 (USER A):**
```
1. Look for "Generate Invite Link" button
2. Click it
3. ✅ Expected:
   - Link appears in modal dialog
   - Link format: http://127.0.0.1:8080#...connect=PEER_ID
   - "Copy Invite Link" button available
```

**Test Case 4.2: Connect Peer-to-Peer**

**In Tab 2 (USER B):**
```
1. Copy the Peer ID from Tab 1 (User A's ID)
2. In Tab 2, find "Connect to Peer" field
3. Paste User A's Peer ID
4. Click "Connect" button
5. ⏳ Wait 2-3 seconds for connection
6. ✅ Expected:
   - Status changes to: "Connected to peer ✅"
   - Control buttons enable
   - System message: "Secure channel established"
```

**Test Case 4.3: Send Text Messages**

**From Tab 2 to Tab 1:**
```
1. In Tab 2, type message: "Hello from Tab 2! This is a secure message."
2. Press Enter or click "Send"
3. ✅ Expected:
   - Tab 2 shows message in blue (self)
   - Message shows timestamp
   - Tab 1 receives message
   - Tab 1 shows message in gray (peer)
```

**From Tab 1 to Tab 2:**
```
1. In Tab 1, type: "Received! Replying from Tab 1 with encryption active."
2. Send message
3. ✅ Expected:
   - Both tabs show conversation
   - Both see timestamp and sender
```

**Test Case 4.4: Self-Destruct Mode**

**In Tab 1:**
```
1. Enable "Auto Self-Destruct" checkbox
2. Set timer to 10 seconds
3. Type message: "This message will self-destruct in 10 seconds"
4. Send to Tab 2
5. ✅ Expected:
   - Message shows countdown: "Self-destructs in 10s"
   - After 10 seconds: Message disappears
   - Tab 2 shows: "Message self-destructed"
```

**Test Case 4.5: File Sharing (Attachment)**

**From Tab 2 to Tab 1:**
```
1. In Tab 2, find "Attach File" button
2. Select a small file (< 50MB)
3. ✅ Expected:
   - File attachment shows in chat
   - Size displayed
   - Can share any type
```

---

### FEATURE 5: Safety Lab - Audit Functions

**Test Case 5.1: Email Breach Check**

Steps:
```
1. Click "Safety Lab" tab
2. Scroll to "Email Identity" section
3. Enter your email: "user@gmail.com"
4. Click "Scan Email"
5. ✅ Expected:
   - Analysis of provider (Gmail)
   - Alias detection check
   - Recovery suggestions
```

**Test Case 5.2: Password Strength Check (with k-anonymity)**

Steps:
```
1. Enter Password: "MyPassword123"
2. Click "Check Password"
3. ✅ Expected:
   - Shows if password is in breach database
   - Uses k-anonymity (privacy-preserving)
   - No actual password sent to server
   - "No pwned-password match found" (or match report)
```

**Test Case 5.3: Account Import & Analysis**

Steps:
```
1. Create a CSV file with sample data:
   website,email,username,password
   gmail.com,user@gmail.com,user123,Pass123!
   facebook.com,user@gmail.com,user123,Pass123!
   
2. Click "Import Accounts"
3. Upload CSV
4. ✅ Expected:
   - Shows duplicate password detection
   - Reuse clusters identified
   - Weak password warnings
```

---

## 🔐 SECURITY PATCHES VERIFICATION

### Verify Patch 1: CSP (XSS Protection)

In browser DevTools (F12):
```javascript
1. Go to Console tab
2. Paste: new Image().src = "https://evil.com/steal";
3. ✅ Expected: 
   - Request blocked
   - Console warning: "Refused to connect (CSP)"
```

### Verify Patch 2: TURN Relay (IP Hiding)

Check WebRTC connection:
```
1. Go to Console (F12)
2. Paste: 
   if (state.peer?._pc?.getConfiguration) {
       let config = state.peer._pc.getConfiguration();
       console.log("ICE Policy:", config.iceTransportPolicy);
   }
3. ✅ Expected: 
   - Output: "ICE Policy: relay"
   - NOT "all" (which leaks IP)
```

### Verify Patch 3: Rate Limiting

Already tested in Test Case 2.3 above.

### Verify Patch 4: Password Strength

Already tested in Test Case 1.3 and 2.1 above.

---

## 🧪 REAL-WORLD SCENARIO TESTS

### Scenario 1: Police Officer Investigation

**Setup:**
```
1. Officer receives suspicious WhatsApp message
2. Text to test:
   "URGENT: Your UPI account blocked due to fraud. 
    Click link: bit.ly/verify-upi or call 1800-XXX-XXXX"
```

**Steps:**
```
1. Open Safety Lab tab
2. Click "Scam Decoder"
3. Paste message
4. Click "Run Scam Decoder"
5. ✅ Should detect:
   - UPI platform
   - URL shortener (bit.ly) - risky
   - Urgency language
   - Score: 70+ (High Risk)
```

### Scenario 2: Secure Evidence Transfer Between Officers

**Setup:**
```
Officer A needs to send sensitive case details to Officer B securely
```

**Steps:**
```
1. Tab 1: Officer A - Generate invite link
2. Tab 2: Officer B - Scan QR or enter Peer ID
3. Connect peers (tested in 4.2)
4. Officer A encrypts message: "Case ID: 2024-FRAUD-001, Suspect: XYZ"
5. Send via secure chat
6. ✅ Expected:
   - Encrypted in transit (WebRTC)
   - No IP leak (TURN relay)
   - Rate limited protection active
```

### Scenario 3: Decrypt Intercepted Scam Message

**Setup:**
```
Police investigates scam, finds encrypted message in suspect's files
```

**Steps:**
```
1. Go to Vault > Text Encryption
2. Decrypt with suspect's password (if known)
3. If brute force attempt needed:
   - Try 6 times with wrong passwords
   - ✅ Should be rate limited after 5
   - Protects against external attacks
```

---

## 📊 TESTING RESULTS TRACKER

Print this table and fill it as you test:

| Feature | Test Case | Status | Notes |
|---------|-----------|--------|-------|
| File Encryption | Encrypt file | ⚪ |  |
| File Encryption | Decrypt file | ⚪ |  |
| File Encryption | Weak password blocked | ⚪ |  |
| Text Encryption | Encrypt/decrypt | ⚪ |  |
| Text Encryption | Rate limiting | ⚪ |  |
| Text Encryption | Tamper detection | ⚪ |  |
| Scam Decoder | Digital arrest detection | ⚪ |  |
| Scam Decoder | KYC scam detection | ⚪ |  |
| Scam Decoder | False positive check | ⚪ |  |
| Secure Chat | Tab 1 connects | ⚪ |  |
| Secure Chat | Tab 2 connects | ⚪ |  |
| Secure Chat | Message delivery | ⚪ |  |
| Secure Chat | Self-destruct works | ⚪ |  |
| Secure Chat | File attachment | ⚪ |  |
| Email Audit | Breach check | ⚪ |  |
| CSP Security | XSS blocked | ⚪ |  |
| TURN Relay | IP hidden | ⚪ |  |

Legend: ⚪ Not tested | 🟡 In progress | ✅ Pass | ❌ Fail

---

## 🆘 TROUBLESHOOTING

### Issue 1: Page Won't Load

**Symptom:** Blank page or "Connection refused"

**Fix:**
```powershell
# Check if server is running
Get-Process | Where-Object {$_.Name -like "*python*"}

# Restart if needed
# Terminal ID: See "Local server running" message
# If not running, restart with: python -m http.server 8080 --bind 127.0.0.1
```

### Issue 2: Peer Connection Failed

**Symptom:** Can't connect between tabs, shows "Peer unavailable"

**Possible Causes:**
```
1. PeerJS signaling server is down (temporary)
2. Firewall blocking WebRTC
3. TURN server unavailable

Fix:
1. Wait 30 seconds and retry
2. Check browser console for errors (F12)
3. Try different browser
4. Check internet connection
```

### Issue 3: CSP Blocking Legitimate Requests

**Symptom:** Browser console shows CSP violations

**Check:**
```
- Is peer.js CDN https://unpkg.com/peerjs@1.5.2/ in whitelist? ✓ (It is)
- Does error mention inline scripts? → Need to allow 'unsafe-inline'
- Check Chrome DevTools Security tab
```

### Issue 4: Password Strength Too Strict

**Symptom:** Can't encrypt with "Fair" password (50-60 range)

**This is Intentional:**
```
- Minimum now 60/100 (was 40/100)
- Examples of valid passwords:
  ✓ MySecret@2024
  ✓ Coffee#Morning99
  ✓ BlueSky!Rock$42
  ✓ India@Police2024!
  
- Examples that won't work:
  ✗ weak
  ✗ password123
  ✗ Abc1234
```

---

## 📝 EXPECTED RESULTS SUMMARY

### All Tests Should Pass ✅

When everything works, you should see:

1. **Encryption:** Files and text encrypt/decrypt smoothly
2. **Rate Limiting:** 6th decryption attempt blocked
3. **Scam Detection:** Real scams flagged 75+, legitimate emails 20-30
4. **P2P Chat:** Two tabs communicate securely with zero latency
5. **Self-Destruct:** Messages disappear after timer
6. **Security:** CSP blocks malicious requests, IP stays hidden

### Performance Notes

- Encryption/decryption: < 2 seconds for typical messages
- Peer connection: 1-3 seconds to establish
- File operations: Depends on file size
- Scam analysis: < 1 second

---

## 🚀 NEXT STEPS AFTER TESTING

If all tests pass:
```
1. ✅ Features work correctly
2. ✅ Security patches active
3. ✅ Ready for production deployment
4. ✅ Safe for police use (except evidence collection - needs HSM)
```

If issues found:
```
1. Document exactly what failed
2. Check browser console (F12) for JavaScript errors
3. Check network tab for failed requests
4. Report specific error messages
```

---

**Server is running. Open http://127.0.0.1:8080 in your browser and start testing!**

Good luck! 🎯

