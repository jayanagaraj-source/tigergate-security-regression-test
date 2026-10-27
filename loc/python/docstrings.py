"""Module docstring for the LOC fixture.

Second paragraph of the module docstring.
"""

import os

# A line comment.
GREETING = """not a docstring: an assigned string
spanning two lines"""


class Greeter:
    """One-line class docstring."""

    def greet(self, name):
        '''Single-quoted triple docstring.
        It continues on this line.
        '''
        return f"{GREETING} {name}"  # trailing comment keeps the line as code


def build(
    prefix: str,
    suffix: str = os.sep,
) -> str:
    r"""Raw docstring after a multi-line signature."""
    value = prefix + suffix
    return value


async def fetch():
    """Async function docstring."""
    return None
