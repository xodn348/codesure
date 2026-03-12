// codesure: VULN CWE-89 HIGH
const query = "SELECT * FROM users WHERE name = '" + req.body.name + "'";
db.query(query);
// codesure: SAFE
db.query("SELECT * FROM users WHERE name = ?", [req.body.name]);
