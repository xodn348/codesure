// codesure: VULN CWE-1321 HIGH
function merge(obj, src) { for (let k in src) obj[k] = src[k]; }
// codesure: SAFE
function merge(obj, src) { for (let k of Object.keys(src)) obj[k] = src[k]; }
