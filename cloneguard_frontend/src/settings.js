const state=document.getElementById("state");
let enabled=true;async function load(){const s=await chrome.storage.local.get({protectionEnabled:true});
enabled=s.protectionEnabled;render()}
function render(){state.textContent=enabled?"Protection is active":"Protection is paused"}document.getElementById("toggle").addEventListener("click",async()=>{enabled=!enabled;await chrome.storage.local.set({protectionEnabled:enabled});render()});load();