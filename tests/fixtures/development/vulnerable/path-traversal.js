// codesure: VULN CWE-22 HIGH
const filePath = path.join(__dirname, req.params.file);
fs.readFileSync(filePath);
// codesure: SAFE
const safePath = path.join(__dirname, 'public', path.basename(req.params.file));
fs.readFileSync(safePath);
