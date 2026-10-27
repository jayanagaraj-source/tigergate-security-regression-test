"""Shadowed int() / float(): the names look numeric but return their input unchanged.

TG-SQL-INJECTION-PY-INLINE trusts the call text int(...) / float(...), so these are expected
analyzer limitations (false negatives), kept in their own module so the shadowing does not
change the meaning of the other fixtures.
"""


def int(value):  # deliberately shadows the builtin
    return value


def float(value):  # deliberately shadows the builtin
    return value


def shadowed_int(cursor, name):
    cursor.execute(f"SELECT * FROM users WHERE id = {int(name)}")  # PY-SQLI-GAP-001


def shadowed_float(cursor, name):
    cursor.execute("SELECT * FROM items WHERE price < " + str(float(name)))  # PY-SQLI-GAP-004
