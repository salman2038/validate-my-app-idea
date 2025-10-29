import sqlite3
from werkzeug.security import generate_password_hash

DB_NAME = "datarector.db"

conn = sqlite3.connect(DB_NAME)
c = conn.cursor()

# Fetch all users
c.execute("SELECT id, password FROM users")
rows = c.fetchall()

for user_id, password in rows:
    if not password:
        print(f"⚠️ Skipping user ID {user_id} (no password found)")
        continue

    if not password.startswith("pbkdf2:sha256:"):
        new_hashed = generate_password_hash(password)
        c.execute("UPDATE users SET password=? WHERE id=?", (new_hashed, user_id))
        print(f"✅ Rehashed password for user ID {user_id}")

conn.commit()
conn.close()
print("🎉 All passwords updated successfully!")