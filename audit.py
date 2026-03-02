import sqlite3
db = sqlite3.connect('C:/Users/user/mnemosyne/mnemosyne.db')
c = db.cursor()
print("--- SCHEMA ---")
for row in c.execute("SELECT sql FROM sqlite_master WHERE type='table'"):
    print(row[0])
print("\n--- FK CHECK ---")
print(c.execute("PRAGMA foreign_key_check").fetchall())
