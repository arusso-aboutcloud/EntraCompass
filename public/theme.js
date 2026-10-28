// Applies the saved theme before first paint. External file because the CSP
// forbids inline scripts. sessionStorage only, per the privacy contract.
try {
  var t = sessionStorage.getItem('entracompass_theme');
  if (t) document.documentElement.dataset.theme = JSON.parse(t);
} catch (e) { /* storage blocked: follow the OS theme */ }
