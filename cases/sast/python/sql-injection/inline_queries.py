"""Inline SQL construction cases for TG-SQL-INJECTION-PY-INLINE.

The rule is source-agnostic: it fires on SQL text built by concatenation, %, .format() or an
f-string unless every joined value is written as int(...) / float(...). Values here are plain
function parameters, as in data-access helpers.
"""


def by_name_fstring(cursor, name):
    cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")  # PY-SQLI-TP-001


def by_name_concat(cursor, name):
    cursor.execute("SELECT * FROM users WHERE name = '" + name + "'")  # PY-SQLI-TP-002


def by_name_format(cursor, name):
    cursor.execute("SELECT * FROM users WHERE name = '{}'".format(name))  # PY-SQLI-TP-003


def by_name_percent(cursor, name):
    cursor.execute("SELECT * FROM users WHERE name = '%s'" % name)  # PY-SQLI-TP-004


def mixed_fstring(cursor, uid, name):
    cursor.execute(f"SELECT * FROM users WHERE id = {int(uid)} AND name = '{name}'")  # PY-SQLI-TP-005


def mixed_concat(cursor, uid, name):
    cursor.execute("SELECT * FROM users WHERE id = " + str(int(uid)) + " AND name = '" + name + "'")  # PY-SQLI-TP-006


def raw_concat(db, tag):
    return db.raw("SELECT * FROM posts WHERE tag = '" + tag + "'")  # PY-SQLI-TP-007


def many_fstring(cursor, table, rows):
    cursor.executemany(f"INSERT INTO {table} (a, b) VALUES (?, ?)", rows)  # PY-SQLI-TP-008


def assigned_fstring(cursor, key):
    query = f"DELETE FROM cache WHERE k = '{key}'"  # PY-SQLI-TP-009
    cursor.execute(query)  # PY-SQLI-TP-009


def mixed_float_unsafe(cursor, price, category):
    cursor.execute("SELECT * FROM items WHERE price < " + str(float(price)) + " AND cat = '" + category + "'")  # PY-SQLI-TP-010

