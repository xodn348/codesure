// codesure: VULN CWE-89 HIGH
const stmt = "SELECT * FROM products WHERE category = '" + req.body.category + "'";
db.execute(stmt);
// codesure: SAFE
db.execute("SELECT * FROM products WHERE category = ?", [req.body.category]);
