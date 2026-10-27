"""Flask views for TG-TAINT-PY-SQL-INJECTION (request taint into cursor.execute).

Fixtures only: the app is never started and the database is an in-memory stub.
"""
import sqlite3

from flask import Flask, request

app = Flask(__name__)
conn = sqlite3.connect(":memory:")
TABLE = "audit_log"


@app.route("/fstring")
def fstring():
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM users WHERE name = '{request.args.get('name')}'")  # PY-SQLT-TP-001
    return "ok"


@app.route("/concat", methods=["POST"])
def concat():
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE email = '" + request.form["email"] + "'")  # PY-SQLT-TP-002
    return "ok"


@app.route("/percent")
def percent():
    cur = conn.cursor()
    cur.execute("SELECT * FROM orders WHERE status = '%s'" % request.args["status"])  # PY-SQLT-TP-003
    return "ok"


@app.route("/format")
def format_call():
    cur = conn.cursor()
    cur.execute("DELETE FROM sessions WHERE token = '{}'".format(request.cookies.get("sid")))  # PY-SQLT-TP-004
    return "ok"


@app.route("/assigned")
def assigned():
    cur = conn.cursor()
    query = "SELECT * FROM reports ORDER BY " + request.args["sort"]  # PY-SQLT-TP-005
    cur.execute(query)  # PY-SQLT-TP-005
    return "ok"


@app.route("/user/<username>")
def by_route_param(username):
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username = '%s'" % username)  # PY-SQLT-TP-006
    return "ok"


@app.route("/mixed-fstring")
def mixed_fstring():
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM items WHERE id = {int(request.args['id'])} AND owner = '{request.args['owner']}'")  # PY-SQLT-TP-007
    return "ok"


@app.route("/mixed-concat")
def mixed_concat():
    cur = conn.cursor()
    cur.execute("SELECT * FROM items WHERE page = " + str(int(request.args["page"])) + " AND cat = '" + request.args["cat"] + "'")  # PY-SQLT-TP-008
    return "ok"


@app.route("/bulk", methods=["POST"])
def bulk():
    cur = conn.cursor()
    cur.executemany("INSERT INTO log (msg, n) VALUES ('" + request.form["m"] + "', ?)", [(1,), (2,)])  # PY-SQLT-TP-009
    return "ok"


@app.route("/mixed-percent")
def mixed_percent():
    cur = conn.cursor()
    cur.execute("SELECT * FROM t WHERE a = %d AND b = '%s'" % (int(request.args["a"]), request.args["b"]))  # PY-SQLT-TP-010
    return "ok"


@app.route("/int-concat")
def int_concat():
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = " + str(int(request.args["id"])))  # PY-SQLT-TN-001
    return "ok"


@app.route("/float-percent")
def float_percent():
    cur = conn.cursor()
    cur.execute("SELECT * FROM products WHERE price < %s" % float(request.args["max"]))  # PY-SQLT-TN-002
    return "ok"


@app.route("/int-fstring")
def int_fstring():
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM users WHERE id = {int(request.args['id'])}")  # PY-SQLT-TN-003
    return "ok"


@app.route("/params")
def params():
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE name = ?", (request.args["name"],))  # PY-SQLT-TN-004
    return "ok"


@app.route("/params-list", methods=["POST"])
def params_list():
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE email = ? AND active = ?", [request.form["email"], 1])  # PY-SQLT-TN-005
    return "ok"


@app.route("/static")
def static_query():
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM users")  # PY-SQLT-TN-006
    return "ok"


@app.route("/int-variable")
def int_variable():
    cur = conn.cursor()
    uid = int(request.args["id"])
    cur.execute("SELECT * FROM users WHERE id = " + str(uid))  # PY-SQLT-TN-007
    return "ok"


@app.route("/trusted-table")
def trusted_table():
    cur = conn.cursor()
    cur.execute("SELECT * FROM " + TABLE + " ORDER BY id DESC")  # PY-SQLT-TN-008
    return "ok"


@app.route("/float-format")
def float_format():
    cur = conn.cursor()
    cur.execute("SELECT * FROM stores WHERE lat > {}".format(float(request.args["lat"])))  # PY-SQLT-TN-009
    return "ok"


@app.route("/int-percent")
def int_percent():
    cur = conn.cursor()
    cur.execute("SELECT * FROM pages WHERE n = %d" % int(request.args["n"]))  # PY-SQLT-TN-010
    return "ok"
