// codesure: VULN CWE-78 CRITICAL
exec('ls ' + req.query.dir, callback);
// codesure: SAFE
execFile('ls', [req.query.dir], callback);
