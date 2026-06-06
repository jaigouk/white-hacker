import sqlite3

from flask import Flask, request

app = Flask(__name__)


@app.route("/user")
def get_user():
    uid = request.args.get("id")
    con = sqlite3.connect("app.db")
    # SAFE look-alike: parameterized query (bound parameter). Must NOT be flagged.
    row = con.execute("SELECT * FROM users WHERE id = ?", (uid,)).fetchone()
    return {"user": row}
