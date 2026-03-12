// codesure: VULN CWE-330 MEDIUM
const token = Math.random().toString(36);
// codesure: SAFE
const token = crypto.randomBytes(32).toString('hex');
