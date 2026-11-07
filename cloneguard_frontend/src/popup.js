const OFFICIAL = {
  "google.com": "https://www.google.com",
  "facebook.com": "https://www.facebook.com",
  "paypal.com": "https://www.paypal.com",
  "amazon.com": "https://www.amazon.com",
  "microsoft.com": "https://www.microsoft.com",
  "instagram.com": "https://www.instagram.com"
};

const $ = id => document.getElementById(id);
const rootDomain = host => {
  const parts = host.toLowerCase().split(".");
  return parts.length > 2 ? parts.slice(-2).join(".") : host.toLowerCase();
};

function inspect(rawUrl) {
  const url = new URL(rawUrl);
  const host = url.hostname.toLowerCase();
  const root = rootDomain(host);
  const known = OFFICIAL[root];
  const lookalike = known && host !== root && !host.endsWith("." + root);
  const suspiciousTerms = ["login-verify", "secure-account", "account-update", "verify-user"];
  const suspiciousPath = suspiciousTerms.some(term => (host + url.pathname).includes(term));
  const mixedScript = /[а-яё]/i.test(host); // Simple visual-spoofing signal, not a full IDN detector.
  const suspicious = Boolean(lookalike || suspiciousPath || mixedScript);
  return {url,host,root,known,suspicious,reason:lookalike?"Unexpected subdomain":suspiciousPath?"Suspicious URL wording":mixedScript?"Potential lookalike characters":"No basic warning signals"};
}

async function init() {
  const saved = await chrome.storage.local.get({protectionEnabled:true,scannedCount:0,blockedCount:0,history:[]});
  $("protectionToggle").checked = saved.protectionEnabled;
  $("scannedCount").textContent = saved.scannedCount;
  $("blockedCount").textContent = saved.blockedCount;
  updateToggleLabel(saved.protectionEnabled);
  renderHistory(saved.history);

  const [tab] = await chrome.tabs.query({active:true,currentWindow:true});
  if (!tab?.url || !/^https?:/.test(tab.url)) {
    $("domain").textContent = "Browser page";
    $("protocol").textContent = "This page cannot be checked";
    setResult("warning","Not a regular website","Not assessed",0,"Chrome internal pages are excluded.");
    return;
  }

  try {
    const result = inspect(tab.url);
    $("domain").textContent = result.host;
    $("protocol").textContent = result.url.protocol === "https:" ? "HTTPS connection" : "HTTP connection";
    if (!saved.protectionEnabled) {
      setResult("warning","Protection is paused","Paused",0,"Turn protection on to run the local demo checks.");
      return;
    }

    const nextCount = saved.scannedCount + 1;
    const entry = {host:result.host,status:result.suspicious?"Warning":"Checked",time:new Date().toLocaleTimeString()};
    const history = [entry,...saved.history].slice(0,5);
    await chrome.storage.local.set({scannedCount:nextCount,history});
    $("scannedCount").textContent = nextCount;
    renderHistory(history);

    if (result.suspicious) {
      setResult("danger","Potentially suspicious","Elevated risk",88,`Signal: ${result.reason}. This prototype cannot confirm fraud.`);
      if (result.known) {
        $("explanation").textContent = "A known brand domain matched. The suggested official destination is shown on the warning page only after verification.";
      }
    } else {
      setResult("safe","No basic warning signals","Not verified",22,"This is not a reputation check. A site can still be fraudulent without these signals.");
    }
  } catch {
    $("domain").textContent = "Unable to analyze tab";
    setResult("warning","Check unavailable","Not assessed",0,"The current tab URL could not be parsed.");
  }
}

function setResult(kind,message,label,width,detail) {
  const banner = $("resultBanner");
  banner.className = "result-banner" + (kind==="safe"?"":` ${kind}`);
  $("resultIcon").textContent = kind==="safe"?"✓":kind==="danger"?"!":"i";
  $("resultText").textContent = message;
  $("riskLabel").textContent = label;
  $("riskMeter").style.width = width+"%";
  $("riskMeter").style.background = kind==="danger"?"#ff657c":kind==="warning"?"#f4b65c":"#25d5a3";
  $("explanation").textContent = detail;
}
function updateToggleLabel(enabled) {
  $("protectionTitle").textContent = enabled?"Protection active":"Protection paused";
  $("protectionDescription").textContent = enabled?"Local demo checks are enabled":"Website checks are disabled";
  $("protectionSymbol").textContent = enabled?"✓":"Ⅱ";
}
function renderHistory(items) {
  $("history").innerHTML = "";
  if (!items.length) { $("history").innerHTML='<p class="muted">No recent checks yet.</p>'; return; }
  items.forEach(item => {
    const row=document.createElement("div"); row.className="history-item";
    const name=document.createElement("strong"); name.textContent=item.host;
    const status=document.createElement("span"); status.textContent=item.status+" · "+item.time;
    row.append(name,status); $("history").append(row);
  });
}
$("protectionToggle").addEventListener("change",async e=>{
  await chrome.storage.local.set({protectionEnabled:e.target.checked});
  updateToggleLabel(e.target.checked);
});
$("settingsBtn").addEventListener("click",()=>chrome.runtime.openOptionsPage());
$("clearHistory").addEventListener("click",async()=>{
  await chrome.storage.local.set({history:[]}); renderHistory([]);
});
init();