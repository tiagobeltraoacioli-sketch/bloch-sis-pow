export function setupPwa({canReload=()=>!document.querySelector('dialog[open]'),notify=()=>{}}={}){
  const install=document.querySelector('#install'),notice=document.querySelector('#update-notice'),button=document.querySelector('#update-app');let prompt,registration,activeUpdate=false;
  window.addEventListener('beforeinstallprompt',event=>{event.preventDefault();prompt=event;if(install)install.hidden=false;});
  install?.addEventListener('click',async()=>{if(!prompt)return;await prompt.prompt();prompt=null;install.hidden=true;});
  const show=()=>{if(notice)notice.hidden=false;};
  button?.addEventListener('click',()=>{if(!canReload())return notify('Finish or close your form and save or reset the current draft before updating.');if(activeUpdate)location.reload();else registration?.waiting?.postMessage({type:'ACTIVATE'});});
  if(!('serviceWorker'in navigator))return;
  navigator.serviceWorker.register('./sw.js',{scope:'./',updateViaCache:'none'}).then(reg=>{registration=reg;const check=()=>{if(reg.waiting&&navigator.serviceWorker.controller)show();};check();reg.addEventListener('updatefound',()=>{const worker=reg.installing;worker?.addEventListener('statechange',check);});}).catch(()=>notify('Offline installation is unavailable in this browser.'));
  navigator.serviceWorker.addEventListener('controllerchange',()=>{if(canReload())location.reload();else{activeUpdate=true;show();const copy=document.querySelector('#update-copy');if(copy)copy.textContent='New version ready. Finish your changes before reloading.';if(button)button.textContent='Reload app';}});
}
