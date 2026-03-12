// codesure: VULN CWE-79 HIGH
document.getElementById('output').innerHTML = req.query.input;
// codesure: SAFE
document.getElementById('output').textContent = req.query.input;
