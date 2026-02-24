function showTab(tab){
document.getElementById("vault").classList.add("hidden");
document.getElementById("risk").classList.add("hidden");
document.getElementById("vaultTab").classList.remove("active");
document.getElementById("riskTab").classList.remove("active");
document.getElementById(tab).classList.remove("hidden");
document.getElementById(tab+"Tab").classList.add("active");
}

/* ================= PASSWORD STRENGTH ================= */

function calculateStrength(p){
let s=0;
if(p.length>=8)s+=20;
if(/[A-Z]/.test(p))s+=20;
if(/[a-z]/.test(p))s+=10;
if(/[0-9]/.test(p))s+=20;
if(/[^A-Za-z0-9]/.test(p))s+=20;
if(p.length>=12)s+=10;
return s;
}

function displayStrength(id,value){
let el=document.getElementById(id);
let score=calculateStrength(value);

if(!value){ el.innerText=""; return; }

if(score<40){
el.innerText="Weak – Add uppercase, numbers, symbols";
el.className="strength weak";
}
else if(score<70){
el.innerText="Medium – Increase length for better security";
el.className="strength medium";
}
else{
el.innerText="Strong – Good security level";
el.className="strength strong";
}
}

function checkTextStrength(){
displayStrength("textStrength",document.getElementById("textPassword").value);
}

function checkFileStrength(){
displayStrength("fileStrength",document.getElementById("filePassword").value);
}

function checkRiskStrength(){
displayStrength("riskStrength",document.getElementById("passwordInput").value);
}

/* ================= TEXT ENCRYPTION ================= */

async function encryptText(){
let text=document.getElementById("textInput").value;
let p1=document.getElementById("textPassword").value;
let p2=document.getElementById("textConfirmPassword").value;
if(!p1||p1!==p2){alert("Password mismatch");return;}

let enc=new TextEncoder();
let keyMaterial=await crypto.subtle.importKey("raw",enc.encode(p1),{name:"PBKDF2"},false,["deriveKey"]);
let key=await crypto.subtle.deriveKey({
name:"PBKDF2",salt:enc.encode("vault"),
iterations:120000,hash:"SHA-256"
},keyMaterial,{name:"AES-GCM",length:256},false,["encrypt"]);

let iv=crypto.getRandomValues(new Uint8Array(12));
let encrypted=await crypto.subtle.encrypt({name:"AES-GCM",iv},key,enc.encode(text));
document.getElementById("textOutput").value=btoa(String.fromCharCode(...iv,...new Uint8Array(encrypted)));
}

async function decryptText(){
try{
let data=atob(document.getElementById("textInput").value);
let password=document.getElementById("textPassword").value;

let bytes=Uint8Array.from(data,c=>c.charCodeAt(0));
let iv=bytes.slice(0,12);
let encrypted=bytes.slice(12);

let enc=new TextEncoder();
let keyMaterial=await crypto.subtle.importKey("raw",enc.encode(password),{name:"PBKDF2"},false,["deriveKey"]);
let key=await crypto.subtle.deriveKey({
name:"PBKDF2",salt:enc.encode("vault"),
iterations:120000,hash:"SHA-256"
},keyMaterial,{name:"AES-GCM",length:256},false,["decrypt"]);

let decrypted=await crypto.subtle.decrypt({name:"AES-GCM",iv},key,encrypted);
document.getElementById("textOutput").value=new TextDecoder().decode(decrypted);
}catch{alert("Wrong password or invalid data");}
}

function shareText(){
let data=document.getElementById("textOutput").value;
if(!data){alert("Nothing to share");return;}
navigator.clipboard.writeText(data);
alert("Copied to clipboard");
}

function clearText(){
document.getElementById("textInput").value="";
document.getElementById("textOutput").value="";
}

/* ================= FILE ENCRYPTION ================= */

let lastEncryptedFileBlob=null;

async function encryptFile(){
let file=document.getElementById("fileInput").files[0];
let password=document.getElementById("filePassword").value;
let confirm=document.getElementById("fileConfirmPassword").value;
if(!file||password!==confirm){alert("Check file or password");return;}

let buffer=await file.arrayBuffer();
let enc=new TextEncoder();

let keyMaterial=await crypto.subtle.importKey("raw",enc.encode(password),{name:"PBKDF2"},false,["deriveKey"]);
let key=await crypto.subtle.deriveKey({
name:"PBKDF2",salt:enc.encode("vault"),
iterations:120000,hash:"SHA-256"
},keyMaterial,{name:"AES-GCM",length:256},false,["encrypt"]);

let iv=crypto.getRandomValues(new Uint8Array(12));
let encrypted=await crypto.subtle.encrypt({name:"AES-GCM",iv},key,buffer);

lastEncryptedFileBlob=new Blob([iv,new Uint8Array(encrypted)]);
let link=document.createElement("a");
link.href=URL.createObjectURL(lastEncryptedFileBlob);
link.download=file.name+".enc";
link.click();
}

function shareFile(){
if(!lastEncryptedFileBlob){alert("No encrypted file yet");return;}
navigator.clipboard.writeText("Encrypted file ready. Share downloaded file.");
alert("File ready to share.");
}

function clearFile(){
document.getElementById("fileInput").value="";
}

/* ================= RISK ANALYZER ================= */

async function runScan(){

let score=0;
let findings=[];

let email=document.getElementById("emailInput").value;
let username=document.getElementById("usernameInput").value;
let password=document.getElementById("passwordInput").value;
let contacts=parseInt(document.getElementById("contactInput").value)||0;

// PASSWORD
let strength=calculateStrength(password);
score+=(100-strength);
if(strength<50)findings.push("Weak password");

let breached=await checkBreach(password);
if(breached){score+=30;findings.push("Password found in breach database");}

// EMAIL
if(email){
if(email.length<8){score+=10;findings.push("Short email");}
if(email.includes("123")){score+=10;findings.push("Predictable email pattern");}
}

// USERNAME
if(username){
if(username.length<5){score+=10;findings.push("Short username");}
if(username.includes("123")){score+=10;}
}

// CONTACT SURFACE
if(contacts>500){score+=10;findings.push("Large contact exposure surface");}
if(contacts>1000){score+=10;}

if(score>100)score=100;

animateWheel(score,findings);

document.getElementById("passwordInput").value="";
}

async function checkBreach(password){
if(!password)return false;
let enc=new TextEncoder();
let hashBuffer=await crypto.subtle.digest("SHA-1",enc.encode(password));
let hashArray=Array.from(new Uint8Array(hashBuffer));
let hashHex=hashArray.map(b=>b.toString(16).padStart(2,"0")).join("").toUpperCase();

let prefix=hashHex.substring(0,5);
let suffix=hashHex.substring(5);

let res=await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
let txt=await res.text();
return txt.includes(suffix);
}

function animateWheel(score,findings){
let circle=document.getElementById("progressCircle");
let radius=85;
let circumference=2*Math.PI*radius;
let current=0;

let interval=setInterval(()=>{
if(current>=score){clearInterval(interval);return;}
current++;
circle.style.strokeDashoffset=circumference-(current/100)*circumference;

if(current>60)circle.style.stroke="red";
else if(current>30)circle.style.stroke="orange";
else circle.style.stroke="green";

document.getElementById("scoreText").innerText=current;
},10);

document.getElementById("resultText").innerText=
findings.length?findings.join(" • "):"No major exposure detected.";
}