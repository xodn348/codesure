// codesure: VULN CWE-95 CRITICAL
eval(req.body.code);
// codesure: SAFE
eval("'use strict'");
