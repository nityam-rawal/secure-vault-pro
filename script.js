// ================= TAB SWITCH =================

function showTab(tab){
document.querySelectorAll(".tab-content").forEach(t=>t.classList.add("hidden"));
document.querySelectorAll(".tabs button").forEach(b=>b.classList.remove("active"));

document.getElementById(tab).classList.remove("hidden");
if(document.getElementById(tab+"Tab"))
document.getElementById(tab+"Tab").classList.add("active");
}

// ================= PASSWORD ENTROPY =================

function calculateEntropy(password){
if(!password) return 0;

let charset=0;
if(/[a-z]/.test(password)) charset+=26;
if(/[A-Z]/.test(password)) charset+=26;
if(/[0-9]/.test(password)) charset+=10;
if(/[^A-Za-z0-9]/.test(password)) charset+=32;

let entropy=password.length * Math.log2(charset || 1);
return Math.round(entropy);
}

function showStrength(elementId,password){
let entropy=calculateEntropy(password);
let el=document.getElementById(elementId);

if(!password){ el.innerText=""; return; }

if(entropy<40){
el.innerText="Weak ("+entropy+" bits)";
el.className="strength weak";
}
else if(entropy<70){
el.innerText="Medium ("+entropy+" bits)";
el.className="strength medium";
}
else{
el.innerText="Strong ("+entropy+" bits)";
el.className="strength strong";
}
}

function checkTextStrength(){
showStrength("textStrength",document.getElementById("textPassword").value);
}
function checkFileStrength(){
showStrength("fileStrength",document.getElementById("filePassword").value);
}
function checkRiskStrength(){
showStrength("riskStrength",document.getElementById("passwordInput").value);
}

// ================= ENCRYPTION CORE =================

async function deriveKey(password,salt){
const enc=new TextEncoder();
const keyMaterial=await crypto.subtle.importKey("raw",enc.encode(password),{name:"PBKDF2"},false,["deriveKey"]);
return await crypto.subtle.deriveKey({
name:"PBKDF2",
salt:salt,
iterations:150000,
hash:"SHA-256"
},keyMaterial,{name:"AES-GCM",length:256},false,["encrypt","decrypt"]);
}

function combineBuffers(...buffers){
let totalLength=buffers.reduce((acc,b)=>acc+b.byteLength,0);
let combined=new Uint8Array(totalLength);
let offset=0;
buffers.forEach(b=>{
combined.set(new Uint8Array(b),offset);
offset+=b.byteLength;
});
return combined;
}

// ================= TEXT ENCRYPT =================

async function encryptText(){
let text=document.getElementById("textInput").value;
let p1=document.getElementById("textPassword").value;
let p2=document.getElementById("textConfirmPassword").value;

if(!p1||p1!==p2){alert("Password mismatch");return;}

let enc=new TextEncoder();
let salt=crypto.getRandomValues(new Uint8Array(16));
let iv=crypto.getRandomValues(new Uint8Array(12));

let key=await deriveKey(p1,salt);
let encrypted=await crypto.subtle.encrypt({name:"AES-GCM",iv},key,enc.encode(text));

let header=new TextEncoder().encode("SVP1");
let finalData=combineBuffers(header,salt,iv,encrypted);

document.getElementById("textOutput").value=btoa(String.fromCharCode(...finalData));
document.getElementById("integrityMsg").innerText="Encrypted with integrity protection (AES-GCM).";

document.getElementById("textPassword").value="";
document.getElementById("textConfirmPassword").value="";
}

async function decryptText(){
try{
let data=Uint8Array.from(atob(document.getElementById("textInput").value),c=>c.charCodeAt(0));

let header=new TextDecoder().decode(data.slice(0,4));
if(header!=="SVP1"){alert("Invalid format");return;}

let salt=data.slice(4,20);
let iv=data.slice(20,32);
let ciphertext=data.slice(32);

let password=document.getElementById("textPassword").value;
let key=await deriveKey(password,salt);

let decrypted=await crypto.subtle.decrypt({name:"AES-GCM",iv},key,ciphertext);
document.getElementById("textOutput").value=new TextDecoder().decode(decrypted);
document.getElementById("integrityMsg").innerText="Integrity verified ✔";

document.getElementById("textPassword").value="";
}catch{
alert("Wrong password or corrupted data");
}
}

function clearText(){
document.getElementById("textInput").value="";
document.getElementById("textOutput").value="";
document.getElementById("integrityMsg").innerText="";
}

function shareText(){
let data=document.getElementById("textOutput").value;
if(!data){alert("Nothing to share");return;}
navigator.clipboard.writeText(data);
alert("Copied to clipboard");
}

// ================= FILE ENCRYPT =================

async function encryptFile(){
let file=document.getElementById("fileInput").files[0];
let password=document.getElementById("filePassword").value;
let confirm=document.getElementById("fileConfirmPassword").value;

if(!file||password!==confirm){alert("Check file or password");return;}

let buffer=await file.arrayBuffer();
let salt=crypto.getRandomValues(new Uint8Array(16));
let iv=crypto.getRandomValues(new Uint8Array(12));
let key=await deriveKey(password,salt);

let encrypted=await crypto.subtle.encrypt({name:"AES-GCM",iv},key,buffer);
let header=new TextEncoder().encode("SVP1");

let finalData=combineBuffers(header,salt,iv,encrypted);

let blob=new Blob([finalData]);
let link=document.createElement("a");
link.href=URL.createObjectURL(blob);
link.download=file.name+".enc";
link.click();

document.getElementById("filePassword").value="";
document.getElementById("fileConfirmPassword").value="";
}

async function decryptFile(){
let file=document.getElementById("fileInput").files[0];
let password=document.getElementById("filePassword").value;
if(!file){alert("Select encrypted file");return;}

let buffer=new Uint8Array(await file.arrayBuffer());

let header=new TextDecoder().decode(buffer.slice(0,4));
if(header!=="SVP1"){alert("Invalid encrypted file");return;}

let salt=buffer.slice(4,20);
let iv=buffer.slice(20,32);
let ciphertext=buffer.slice(32);

let key=await deriveKey(password,salt);
let decrypted=await crypto.subtle.decrypt({name:"AES-GCM",iv},key,ciphertext);

let blob=new Blob([decrypted]);
let link=document.createElement("a");
link.href=URL.createObjectURL(blob);
link.download="decrypted_file";
link.click();

document.getElementById("filePassword").value="";
}

// ================= BREACH CHECK =================

async function checkBreach(password){
if(!password) return 0;

let enc=new TextEncoder();
let hashBuffer=await crypto.subtle.digest("SHA-1",enc.encode(password));
let hashArray=Array.from(new Uint8Array(hashBuffer));
let hashHex=hashArray.map(b=>b.toString(16).padStart(2,"0")).join("").toUpperCase();

let prefix=hashHex.substring(0,5);
let suffix=hashHex.substring(5);

let res=await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
let txt=await res.text();

let lines=txt.split("\n");
for(let line of lines){
let parts=line.split(":");
if(parts[0]===suffix){
return parseInt(parts[1]);
}
}
return 0;
}

// ================= RISK ANALYZER =================

async function runScan(){

document.getElementById("loading").innerText="Scanning...";
document.getElementById("scanBtn").disabled=true;

let score=0;
let breakdown=[];

let email=document.getElementById("emailInput").value;
let username=document.getElementById("usernameInput").value;
let password=document.getElementById("passwordInput").value;
let contacts=parseInt(document.getElementById("contactInput").value)||0;

let entropy=calculateEntropy(password);
let passwordRisk=Math.max(0,80-entropy);
score+=passwordRisk;
breakdown.push("Password risk: "+passwordRisk);

let breachCount=await checkBreach(password);
if(breachCount>0){
score+=30;
breakdown.push("Breached "+breachCount+" times");
}

if(email.length<8){score+=10;breakdown.push("Short email");}
if(username.length<5){score+=10;breakdown.push("Short username");}
if(contacts>500){score+=10;breakdown.push("Large contact surface");}

if(score>100)score=100;

animateWheel(score);

let category="";
if(score<=30) category="Low";
else if(score<=60) category="Medium";
else if(score<=80) category="High";
else category="Critical";

document.getElementById("category").innerText="Risk Level: "+category;
document.getElementById("breakdown").innerText=breakdown.join(" • ");

document.getElementById("loading").innerText="";
document.getElementById("scanBtn").disabled=false;
document.getElementById("passwordInput").value="";
}

// ================= ANIMATED WHEEL =================

function animateWheel(score){
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
},8);
}