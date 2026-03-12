// codesure: VULN CWE-601 MEDIUM
res.redirect(req.query.url);
// codesure: SAFE
const allowed = ['https://example.com'];
if (allowed.includes(req.query.url)) res.redirect(req.query.url);
