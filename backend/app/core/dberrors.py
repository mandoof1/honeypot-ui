"""Telling "the database rejected this value" from "the database is unwell".

The distinction matters on ingest. A value the database will never accept (a
string longer than its column, a character the encoding cannot hold) is the
payload's fault: answering 500 made the engine keep the session in its spool
and resend it for ever. Answered with 422, the engine files the payload under
``failed/`` and moves on. A dropped connection or a deadlock is not the
payload's fault and must stay a 5xx so the engine does retry.
"""

from __future__ import annotations

from sqlalchemy.exc import DataError, DBAPIError

#: SQLSTATE class 22 is "data exception": string_data_right_truncation
#: (22001), numeric_value_out_of_range (22003), character_not_in_repertoire
#: (22021), untranslatable_character (22P05), invalid_text_representation
#: (22P02) and their siblings.
_DATA_EXCEPTION_CLASS = "22"


def _chain(exc: BaseException):
    """``exc`` and everything it wraps, without looping on a cycle."""
    seen = set()
    current = exc
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        yield current
        current = (
            getattr(current, "orig", None)
            or current.__cause__
            or current.__context__
        )


def is_data_error(exc: BaseException) -> bool:
    """Whether ``exc`` means a value was unacceptable to the database."""
    if isinstance(exc, DataError):
        return True
    if not isinstance(exc, DBAPIError):
        return False
    for inner in _chain(exc):
        code = getattr(inner, "sqlstate", None) or getattr(inner, "pgcode", None)
        if isinstance(code, str) and code.startswith(_DATA_EXCEPTION_CLASS):
            return True
        # asyncpg refuses some values before sending them (a str where an
        # int is bound, text it cannot encode) with its client-side DataError,
        # which carries no SQLSTATE.
        if type(inner).__name__ == "DataError":
            return True
    return False
