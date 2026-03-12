// codesure: SAFE
const stmt = db.prepare("SELECT * FROM users WHERE id = ?");
const user = stmt.get(userId);
