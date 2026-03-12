# codesure: VULN CWE-89 HIGH
cursor.execute("SELECT * FROM users WHERE id = " + str(user_id))
# codesure: SAFE
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
