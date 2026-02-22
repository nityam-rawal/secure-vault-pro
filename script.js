const dropArea = document.getElementById("dropArea");
const fileInput = document.getElementById("fileInput");

dropArea.addEventListener("dragover", e => {
  e.preventDefault();
});

dropArea.addEventListener("drop", e => {
  e.preventDefault();
  fileInput.files = e.dataTransfer.files;
});

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

async function encryptFile() {
  const file = fileInput.files[0];
  const password = document.getElementById("password").value;
  if (!file || !password) return alert("Select file and enter password");

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

async function decryptFile() {
  const file = fileInput.files[0];
  const password = document.getElementById("password").value;
  if (!file || !password) return alert("Select vault file and enter password");

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
      document.getElementById("preview").innerHTML =
        `<img src="${url}">`;
    } else if (originalName.match(/\.(txt)$/i)) {
      const text = await blob.text();
      document.getElementById("preview").innerHTML =
        `<pre>${text}</pre>`;
    } else {
      download(new Uint8Array(decrypted), originalName);
    }

  } catch {
    alert("Wrong password or corrupted file");
  }
}

async function encryptText() {
  const text = document.getElementById("textInput").value;
  const password = document.getElementById("password").value;
  if (!text || !password) return alert("Enter text and password");

  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveKey(password, salt);

  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv },
    key,
    new TextEncoder().encode(text)
  );

  const combined = new Uint8Array([...salt, ...iv, ...new Uint8Array(encrypted)]);
  document.getElementById("textOutput").value =
    btoa(String.fromCharCode(...combined));
}

async function decryptText() {
  const base64 = document.getElementById("textInput").value;
  const password = document.getElementById("password").value;
  if (!base64 || !password) return alert("Enter encrypted text and password");

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

function download(data, filename) {
  const blob = new Blob([data]);
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
}