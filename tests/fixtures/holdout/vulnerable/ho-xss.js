// codesure: VULN CWE-79 HIGH
document.querySelector('#message').innerHTML = req.query.msg;
// codesure: SAFE
document.querySelector('#message').textContent = req.query.msg;
