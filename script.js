// ===============================
// DOM REFERENCES
// ===============================

const dropArea = document.getElementById("dropArea");
const fileInput = document.getElementById("fileInput");
const preview = document.getElementById("preview");

// ===============================
// PASSWORD VALIDATION
// ===============================

function validatePassword() {
  const p1 = document.getElementById("password").value;
  const p2 = document.getElementById("confirmPassword").value;

  if (!p1 || !p2) {
    alert("Enter and confirm password");
    return false;
  }

  if (p1 !== p2) {
    alert("Passwords do not match");
    return false;
  }

  if (p1.length < 8) {
    alert("Password must be at least 8 characters");
    return false;
  }

  return true;
}

// ===============================
// PASSWORD STRENGTH
// ===============================

document.getElementById("password").addEventListener("input", checkStrength);

function checkStrength() {
  const pwd = document.getElementById("password").value;
  let score = 0;

  if (pwd.length >= 8) score++;
  if (/[A-Z]/.test(pwd)) score++;
  if (/[0-9]/.test(pwd)) score++;
  if (/[^A-Za-z0-9]/.test(pwd)) score++;

  const levels = ["Weak", "Medium", "Strong", "Very Strong"];
  document.getElementById("strength").innerText =
    score > 0 ? "Strength: " + levels[score - 1] : "";
}

// ===============================
// TOGGLE PASSWORD VISIBILITY
// ===============================

function togglePassword() {
  const p1 = document.getElementById("password");
  const p2 = document.getElementById("confirmPassword");

  p1.type = p1.type === "password" ? "text" : "password";
  p2.type = p2.type === "password" ? "text" : "password";
}

// ===============================
// DRAG & DROP
// ===============================

if (dropArea) {
  dropArea.addEventListener("dragover", e => {
    e.preventDefault();
  });

  dropArea.addEventListener("drop", e => {
    e.preventDefault();
    fileInput.files = e.dataTransfer.files;
  });
}

// ===============================
// KEY DERIVATION
// ===============================

async function deriveKey(password, salt) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt,
      iterations: 200000,
      hash: "SHA-256"
    },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

// ===============================
// FILE ENCRYPTION
// ===============================

async function encryptFile() {
  if (!validatePassword()) return;

  const file = fileInput.files[0];
  if (!file) return alert("Select file");

  const password = document.getElementById("password").value;

  const data = await file.arrayBuffer();
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));

  const key = await deriveKey(password, salt);

  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv },
    key,
    data
  );

  const fileNameBytes = new TextEncoder().encode(file.name);
  const nameLength = new Uint8Array([fileNameBytes.length]);

  const combined = new Uint8Array([
    ...salt,
    ...iv,
    ...nameLength,
    ...fileNameBytes,
    ...new Uint8Array(encrypted)
  ]);

  download(combined, file.name + ".vault");
}

// ===============================
// FILE DECRYPTION
// ===============================

async function decryptFile() {
  const file = fileInput.files[0];
  if (!file) return alert("Select vault file");

  const password = document.getElementById("password").value;
  if (!password) return alert("Enter password");

  const data = new Uint8Array(await file.arrayBuffer());

  const salt = data.slice(0, 16);
  const iv = data.slice(16, 28);
  const nameLength = data[28];
  const nameStart = 29;
  const nameEnd = nameStart + nameLength;

  const originalName = new TextDecoder().decode(data.slice(nameStart, nameEnd));
  const encrypted = data.slice(nameEnd);

  const key = await deriveKey(password, salt);

  try {
    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: iv },
      key,
      encrypted
    );

    const blob = new Blob([decrypted]);
    const url = URL.createObjectURL(blob);

    if (originalName.match(/\.(jpg|png|jpeg|gif)$/i)) {
      preview.innerHTML = `<img src="${url}">`;
    } else if (originalName.match(/\.(txt)$/i)) {
      const text = await blob.text();
      preview.innerHTML = `<pre>${text}</pre>`;
    } else {
      download(new Uint8Array(decrypted), originalName);
    }

  } catch {
    alert("Wrong password or corrupted file");
  }
}

// ===============================
// TEXT ENCRYPTION
// ===============================

async function encryptText() {
  if (!validatePassword()) return;

  const text = document.getElementById("textInput").value;
  if (!text) return alert("Enter text");

  const password = document.getElementById("password").value;

  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(password, salt);

  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv },
    key,
    new TextEncoder().encode(text)
  );

  const combined = new Uint8Array([
    ...salt,
    ...iv,
    ...new Uint8Array(encrypted)
  ]);

  document.getElementById("textOutput").value =
    btoa(String.fromCharCode(...combined));
}

// ===============================
// TEXT DECRYPTION
// ===============================

async function decryptText() {
  const base64 = document.getElementById("textInput").value;
  if (!base64) return alert("Enter encrypted text");

  const password = document.getElementById("password").value;
  if (!password) return alert("Enter password");

  const data = Uint8Array.from(atob(base64), c => c.charCodeAt(0));

  const salt = data.slice(0, 16);
  const iv = data.slice(16, 28);
  const encrypted = data.slice(28);

  const key = await deriveKey(password, salt);

  try {
    const decrypted = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: iv },
      key,
      encrypted
    );

    document.getElementById("textOutput").value =
      new TextDecoder().decode(decrypted);

  } catch {
    alert("Wrong password or corrupted text");
  }
}

// ===============================
// DOWNLOAD HELPER
// ===============================

function download(data, filename) {
  const blob = new Blob([data]);
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
}