document.addEventListener("DOMContentLoaded", () => {

  if (!window.crypto || !window.crypto.subtle) {
    document.body.innerHTML =
      "<h2 style='color:white;text-align:center;margin-top:20%'>Secure browser required.</h2>";
    return;
  }

  // Prevent global drag-drop
  window.addEventListener("dragover", e => e.preventDefault());
  window.addEventListener("drop", e => e.preventDefault());

  const fileInput = document.getElementById("fileInput");
  const preview = document.getElementById("preview");

  const filePassword = document.getElementById("filePassword");
  const fileConfirmPassword = document.getElementById("fileConfirmPassword");
  const textPassword = document.getElementById("textPassword");
  const textConfirmPassword = document.getElementById("textConfirmPassword");

  const fileStrength = document.getElementById("fileStrength");
  const textStrength = document.getElementById("textStrength");

  const fileError = document.getElementById("fileError");
  const textError = document.getElementById("textError");

  function strengthCheck(pwd, el) {
    let score = 0;
    if (pwd.length >= 8) score++;
    if (/[A-Z]/.test(pwd)) score++;
    if (/[0-9]/.test(pwd)) score++;
    if (/[^A-Za-z0-9]/.test(pwd)) score++;
    const levels = ["Weak","Medium","Strong","Very Strong"];
    el.textContent = score ? "Strength: " + levels[score-1] : "";
  }

  filePassword.addEventListener("input", e => strengthCheck(e.target.value,fileStrength));
  textPassword.addEventListener("input", e => strengthCheck(e.target.value,textStrength));

  function validate(p1,p2,errorEl){
    errorEl.textContent="";
    if(!p1||!p2) return errorEl.textContent="Enter password",false;
    if(p1!==p2) return errorEl.textContent="Passwords do not match",false;
    if(p1.length<8) return errorEl.textContent="Minimum 8 characters",false;
    return true;
  }

  async function deriveKey(password,salt){
    const enc=new TextEncoder();
    const keyMaterial=await crypto.subtle.importKey("raw",enc.encode(password),"PBKDF2",false,["deriveKey"]);
    return crypto.subtle.deriveKey(
      {name:"PBKDF2",salt,iterations:150000,hash:"SHA-256"},
      keyMaterial,
      {name:"AES-GCM",length:256},
      false,
      ["encrypt","decrypt"]
    );
  }

  function clearFileFields(){
    filePassword.value="";
    fileConfirmPassword.value="";
    fileStrength.textContent="";
    fileError.textContent="";
    preview.innerHTML="";
  }

  function clearTextFields(){
    textPassword.value="";
    textConfirmPassword.value="";
    textStrength.textContent="";
    textError.textContent="";
  }

  document.getElementById("clearFileBtn").onclick=clearFileFields;
  document.getElementById("clearTextBtn").onclick=clearTextFields;

  function download(data,filename){
    const blob=new Blob([data]);
    const url=URL.createObjectURL(blob);
    const a=document.createElement("a");
    a.href=url;
    a.download=filename;
    a.click();
    URL.revokeObjectURL(url);
  }

  // FILE ENCRYPT
  document.getElementById("encryptFileBtn").onclick=async()=>{
    preview.innerHTML="";
    if(!validate(filePassword.value,fileConfirmPassword.value,fileError))return;
    const file=fileInput.files[0];
    if(!file)return fileError.textContent="Select file";

    const data=await file.arrayBuffer();
    const salt=crypto.getRandomValues(new Uint8Array(16));
    const iv=crypto.getRandomValues(new Uint8Array(12));
    const key=await deriveKey(filePassword.value,salt);

    const encrypted=await crypto.subtle.encrypt({name:"AES-GCM",iv},key,data);
    const nameBytes=new TextEncoder().encode(file.name);

    const combined=new Uint8Array([
      ...salt,
      ...iv,
      nameBytes.length,
      ...nameBytes,
      ...new Uint8Array(encrypted)
    ]);

    download(combined,file.name+".vault");
    clearFileFields();
  };

  // FILE DECRYPT
  document.getElementById("decryptFileBtn").onclick=async()=>{
    preview.innerHTML="";
    const file=fileInput.files[0];
    if(!file||!filePassword.value)return fileError.textContent="Select file & password";

    const data=new Uint8Array(await file.arrayBuffer());
    const salt=data.slice(0,16);
    const iv=data.slice(16,28);
    const nameLength=data[28];
    const name=new TextDecoder().decode(data.slice(29,29+nameLength));
    const encrypted=data.slice(29+nameLength);

    const key=await deriveKey(filePassword.value,salt);

    try{
      const decrypted=await crypto.subtle.decrypt({name:"AES-GCM",iv},key,encrypted);
      download(decrypted,name);
      clearFileFields();
    }catch{
      fileError.textContent="Wrong password or corrupted file";
    }
  };

  // TEXT ENCRYPT
  document.getElementById("encryptTextBtn").onclick=async()=>{
    if(!validate(textPassword.value,textConfirmPassword.value,textError))return;
    const text=document.getElementById("textInput").value;
    if(!text)return textError.textContent="Enter text";

    const salt=crypto.getRandomValues(new Uint8Array(16));
    const iv=crypto.getRandomValues(new Uint8Array(12));
    const key=await deriveKey(textPassword.value,salt);

    const encrypted=await crypto.subtle.encrypt(
      {name:"AES-GCM",iv},
      key,
      new TextEncoder().encode(text)
    );

    const combined=new Uint8Array([...salt,...iv,...new Uint8Array(encrypted)]);
    document.getElementById("textOutput").value=
      btoa(String.fromCharCode(...combined));

    clearTextFields();
  };

  // TEXT DECRYPT
  document.getElementById("decryptTextBtn").onclick=async()=>{
    const base64=document.getElementById("textInput").value;
    if(!base64||!textPassword.value)return textError.textContent="Enter encrypted text & password";

    const data=Uint8Array.from(atob(base64),c=>c.charCodeAt(0));
    const salt=data.slice(0,16);
    const iv=data.slice(16,28);
    const encrypted=data.slice(28);

    const key=await deriveKey(textPassword.value,salt);

    try{
      const decrypted=await crypto.subtle.decrypt({name:"AES-GCM",iv},key,encrypted);
      document.getElementById("textOutput").value=
        new TextDecoder().decode(decrypted);
      clearTextFields();
    }catch{
      textError.textContent="Wrong password or corrupted text";
    }
  };

  // AUTO LOCK (5 min)
  let timer;
  function resetTimer(){
    clearTimeout(timer);
    timer=setTimeout(()=>{
      document.body.innerHTML=
        "<h2 style='color:white;text-align:center;margin-top:20%'>Session Locked — Refresh Page</h2>";
    },300000);
  }
  document.addEventListener("mousemove",resetTimer);
  document.addEventListener("keydown",resetTimer);
  resetTimer();

});