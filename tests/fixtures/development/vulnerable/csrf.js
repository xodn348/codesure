// codesure: VULN CWE-352 MEDIUM
app.post('/transfer', (req, res) => {
  // no CSRF token check
  transfer(req.body.amount, req.body.to);
});
// codesure: SAFE
app.post('/transfer', csrfProtection, (req, res) => {
  transfer(req.body.amount, req.body.to);
});
