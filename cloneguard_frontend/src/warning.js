const params=new URLSearchParams(location.search);
const domain=params.get("domain")||"Unknown domain";
const reason=params.get("reason")||"Suspicious URL pattern detected";
const safe=params.get("safe")||"";
document.getElementById("detectedDomain").textContent=domain;
document.getElementById("reason").textContent=reason;
const button=document.getElementById("visitOfficial");
const safeEl=document.getElementById("safeDomain");
const allowed=["google.com","facebook.com","paypal.com","amazon.com","microsoft.com","instagram.com"];
try{
  const u=new URL(safe);
  if(u.protocol==="https:"&&allowed.includes(u.hostname)){
    safeEl.textContent=u.hostname;button.disabled=false;
    button.addEventListener("click",()=>location.assign(u.href));
  }
}catch{}
document.getElementById("goBack").addEventListener("click",()=>history.length>1?history.back():location.assign("https://www.google.com/"));