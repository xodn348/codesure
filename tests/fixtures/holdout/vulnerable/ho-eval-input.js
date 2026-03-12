// codesure: VULN CWE-95 CRITICAL
eval(req.body.expression);
// codesure: SAFE
eval("'strict mode'");
