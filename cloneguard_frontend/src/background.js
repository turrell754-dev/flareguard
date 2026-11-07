chrome.runtime.onInstalled.addListener(async()=>{
  const defaults={protectionEnabled:true,scannedCount:0,blockedCount:0,history:[]};
  const current=await chrome.storage.local.get(Object.keys(defaults));
  const missing={};
  for(const [key,value] of Object.entries(defaults)){
    if(current[key]===undefined) missing[key]=value;
  }
  await chrome.storage.local.set(missing);
});