import sqlite3

from flask import Flask, request

app = Flask(__name__)


@app.route("/user")
def get_user():
    uid = request.args.get("id")
    con = sqlite3.connect("app.db")
    # VULN (planted): SQL injection — f-string interpolation into the query.
    # Category: injection. OWASP A03:2025.
    row = con.execute(f"SELECT * FROM users WHERE id = {uid}").fetchone()
    return {"user": row}
