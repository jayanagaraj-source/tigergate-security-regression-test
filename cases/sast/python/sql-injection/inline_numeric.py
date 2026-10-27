"""Numeric and parameterized SQL that TG-SQL-INJECTION-PY-INLINE must not report."""


def by_id_fstring(cursor, uid):
    cursor.execute(f"SELECT * FROM users WHERE id = {int(uid)}")  # PY-SQLI-TN-001


def by_price_fstring(cursor, price):
    cursor.execute(f"SELECT * FROM items WHERE price < {float(price)}")  # PY-SQLI-TN-002


def by_id_concat(cursor, uid):
    cursor.execute("SELECT * FROM users WHERE id = " + str(int(uid)))  # PY-SQLI-TN-003


def by_price_concat(cursor, price):
    cursor.execute("SELECT * FROM items WHERE price < " + str(float(price)) + " ORDER BY price")  # PY-SQLI-TN-004


def by_id_percent(cursor, uid):
    cursor.execute("SELECT * FROM users WHERE id = %d" % int(uid))  # PY-SQLI-TN-005


def by_price_format(cursor, price):
    cursor.execute("SELECT * FROM items WHERE price < {}".format(float(price)))  # PY-SQLI-TN-006


def page_fstring(cursor, limit, offset):
    cursor.execute(f"SELECT * FROM items LIMIT {int(limit)} OFFSET {int(offset)}")  # PY-SQLI-TN-007


def numeric_variable(cursor, raw):
    n = int(raw)
    cursor.execute(f"SELECT * FROM users WHERE id = {n}")  # PY-SQLI-TN-008


def parameterized(cursor, name):
    cursor.execute("SELECT * FROM users WHERE name = %s", (name,))  # PY-SQLI-TN-009


def static(cursor):
    cursor.execute("SELECT 1")  # PY-SQLI-TN-010


def numeric_variables_multi(cursor, raw_limit, raw_offset):
    limit = int(raw_limit)
    offset = int(raw_offset)
    cursor.execute(f"SELECT * FROM items LIMIT {limit} OFFSET {offset}")  # PY-SQLI-GAP-002


def to_id(value):
    return int(value)


def helper_numeric(cursor, raw):
    cursor.execute(f"SELECT * FROM users WHERE id = {to_id(raw)}")  # PY-SQLI-GAP-003

