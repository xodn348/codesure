// codesure: VULN CWE-78 CRITICAL
exec('find ' + req.query.path, callback);
// codesure: SAFE
execFile('find', [req.query.path], callback);
