# 🧪 QUICK P2P TEST - 3 Steps

## Step 1: Clear & Refresh 
```
Press: Ctrl+Shift+Del
  → Check: Cookies and cached files
  → Click: Clear Now

Then: Ctrl+F5 (hard refresh)
```

## Step 2: Test Two-Tab Connection

**Tab 1:**
```
1. Open http://127.0.0.1:8080
2. Wait 2-5 seconds for Secure ID
3. Click "Copy" button
4. ID is now copied
```

**Tab 2:**
```
1. Open http://127.0.0.1:8080 (new tab, same URL)
2. Wait for different Secure ID to appear
3. Paste into "Paste a peer ID" field
4. Click "Connect"
```

## Step 3: Send Message

**Tab 1 → Tab 2:**
```
Type: "Hello from Tab 1"
Send (Enter or Send button)
✅ Message appears in Tab 2 instantly
```

**Tab 2 → Tab 1:**
```
Type: "Hello from Tab 1"
Send
✅ Message appears in Tab 1 instantly
```

---

## ✅ Success Indicators

- [ ] Tab 2 shows "Connected to peer ✅"
- [ ] Messages send without delay
- [ ] Both directions work (Tab 1→2 and 2→1)
- [ ] Timestamps show on messages
- [ ] No error messages in F12 console

---

## ❌ If Still Failing

**Check 1: Browser Console**
```
Press F12
Go to: Console tab
Look for red errors
Report what you see
```

**Check 2: Network Status**
```
In F12: Network tab
Refresh: Ctrl+F5
Look for: peerjs.min.js
Should be: 200 (loaded)
```

**Check 3: Try Different Browser**
```
Chrome  → Test
Firefox → Test
Safari  → Test
```

**Check 4: Peer ID Format**
```
Tab 1 ID: Should be random (e.g., "abc-123-def")
Tab 2 ID: Should be DIFFERENT random
NOT: "offline-..." (that means offline mode)
```

---

## 🔍 What Was Fixed

```
BEFORE: iceTransportPolicy = "relay"  (RELAY-ONLY)
  Result: ❌ P2P connections blocked

AFTER: iceTransportPolicy = "all"    (P2P + RELAY FALLBACK)
  Result: ✅ P2P connections work
```

The fix allows direct peer-to-peer connections with TURN relay as a fallback.

---

## 📞 Quick Reference

| Problem | Solution |
|---------|----------|
| Still "Offline mode" | Clear cache + hard refresh |
| Messages don't send | Check connection status |
| Connection won't establish | Check peer IDs are different |
| Slow messages | Check network/connection type |
| Can't copy ID | Click "Copy" button again |

---

**Ready?** Go to http://127.0.0.1:8080 and test it now!
