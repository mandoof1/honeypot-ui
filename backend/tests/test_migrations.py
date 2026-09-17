"""Migration tests.

The rest of the suite runs against SQLite via ``Base.metadata.create_all``,
which never executes the Alembic scripts and has no concept of a PostgreSQL
ENUM type or a VARCHAR length limit. That combination hid a migration which
could not apply to a real PostgreSQL database at all: the backend built fine,
then exited during startup with

    (psycopg.errors.DuplicateObject) type "userrole" already exists

These tests render the migrations to PostgreSQL DDL offline - no server and no
connection - and assert on the emitted SQL.
"""

import importlib.util
import io
import os
import re

import pytest
from alembic.operations import Operations
from alembic.runtime.migration import MigrationContext

VERSIONS_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "alembic",
    "versions",
)

#: Every enum type the schema is responsible for creating.
ENUM_TYPES = [
    "userrole",
    "honeypotmode",
    "sessionstatus",
    "attackseverity",
    "attackcategory",
    "attackerprofile",
    "alertstatus",
]

_CONSTRAINT_KEYWORDS = {"primary", "foreign", "unique", "constraint", "check"}


def _load_migrations():
    """Every migration module, ordered by revision.

    Rendering only the initial migration would misreport any column a later
    revision adds as missing.
    """
    modules = []
    for filename in sorted(os.listdir(VERSIONS_DIR)):
        if not filename.endswith(".py") or filename.startswith("__"):
            continue
        path = os.path.join(VERSIONS_DIR, filename)
        spec = importlib.util.spec_from_file_location(f"mig_{filename[:-3]}", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        modules.append(module)

    by_revision = {m.revision: m for m in modules}
    ordered, revision = [], None
    while True:
        nxt = next(
            (m for m in modules if m.down_revision == revision and m not in ordered),
            None,
        )
        if nxt is None:
            break
        ordered.append(nxt)
        revision = nxt.revision
    assert len(ordered) == len(by_revision), "migration chain is broken or branched"
    return ordered


def _render(direction: str) -> str:
    """Render the full chain to PostgreSQL DDL without connecting anywhere."""
    modules = _load_migrations()
    if direction == "downgrade":
        modules = list(reversed(modules))
    buffer = io.StringIO()
    context = MigrationContext.configure(
        dialect_name="postgresql",
        opts={"as_sql": True, "output_buffer": buffer},
    )
    with Operations.context(context):
        for module in modules:
            getattr(module, direction)()
    return buffer.getvalue()


@pytest.fixture(scope="module")
def upgrade_sql() -> str:
    return _render("upgrade")


def _schema_from_sql(sql: str) -> dict:
    """{table: {column: rendered type}} after applying every migration."""
    tables = {}
    for block in re.finditer(r"CREATE TABLE (\w+) \((.*?)\n\);", sql, re.S):
        columns = {}
        for line in block.group(2).split("\n"):
            line = line.strip().rstrip(",")
            match = re.match(r"^(\w+)\s+(\S+)", line)
            if match and match.group(1).lower() not in _CONSTRAINT_KEYWORDS:
                columns[match.group(1)] = match.group(2)
        tables[block.group(1)] = columns

    for add in re.finditer(r"ALTER TABLE (\w+) ADD COLUMN (\w+) (\S+)", sql):
        tables.setdefault(add.group(1), {})[add.group(2)] = add.group(3)
    for alter in re.finditer(r"ALTER TABLE (\w+) ALTER COLUMN (\w+) TYPE (\S+)", sql):
        tables.setdefault(alter.group(1), {})[alter.group(2)] = alter.group(3)
    for drop in re.finditer(r"ALTER TABLE (\w+) DROP COLUMN (\w+)", sql):
        tables.get(drop.group(1), {}).pop(drop.group(2), None)
    return tables


def _orm_schema() -> dict:
    from sqlalchemy.dialects import postgresql

    from app.core.database import Base
    import app.models  # noqa: F401

    dialect = postgresql.dialect()
    return {
        table.name: {
            column.name: str(column.type.compile(dialect))
            for column in table.columns
        }
        for table in Base.metadata.tables.values()
    }


@pytest.mark.parametrize("enum_name", ENUM_TYPES)
def test_enum_type_is_created_exactly_once(upgrade_sql, enum_name):
    """Each ENUM must be created once, by the guarded _create_enum block.

    ``sa.Enum(..., name='userrole')`` emits its own ``CREATE TYPE`` when the
    owning table is built - ``op.create_table`` does not pass ``checkfirst``,
    unlike ``metadata.create_all``. With the type already created by
    ``_create_enum`` PostgreSQL raised ``DuplicateObject``, and because DDL is
    transactional the whole migration rolled back, leaving an empty database.
    The columns therefore use ``postgresql.ENUM(..., create_type=False)``.
    """
    assert upgrade_sql.count(f"CREATE TYPE {enum_name} ") == 1


def test_every_enum_creation_is_guarded(upgrade_sql):
    """Re-running against a database that already has the types must be safe."""
    for enum_name in ENUM_TYPES:
        guard = f"SELECT 1 FROM pg_type WHERE typname = '{enum_name}'"
        assert guard in upgrade_sql, f"{enum_name} is created without a guard"


def test_expected_tables_are_created(upgrade_sql):
    for table in (
        "users",
        "honeypot_nodes",
        "honeypot_sessions",
        "alerts",
        "indicators_of_compromise",
        "audit_logs",
        "otp_verifications",
        "alert_thresholds",
        "payload_samples",
        "session_artifacts",
    ):
        assert f"CREATE TABLE {table} " in upgrade_sql


def test_migration_defines_every_orm_column(upgrade_sql):
    """The migrations are the only thing that builds the production schema.

    Every other test uses ``create_all`` on SQLite, which is generated from the
    ORM and so cannot disagree with it. The Alembic chain can.
    """
    migration, orm = _schema_from_sql(upgrade_sql), _orm_schema()
    missing = {
        table: sorted(set(columns) - set(migration.get(table, {})))
        for table, columns in orm.items()
        if set(columns) - set(migration.get(table, {}))
    }
    assert not missing, f"columns in the ORM but not in the migrations: {missing}"


def test_migrations_define_no_unknown_column(upgrade_sql):
    migration, orm = _schema_from_sql(upgrade_sql), _orm_schema()
    extra = {
        table: sorted(set(columns) - set(orm.get(table, {})))
        for table, columns in migration.items()
        if set(columns) - set(orm.get(table, {}))
    }
    assert not extra, f"columns in the migrations but not in the ORM: {extra}"


def test_string_column_widths_match_the_orm(upgrade_sql):
    """A too-narrow VARCHAR only fails on PostgreSQL.

    otp_verifications.otp_code holds an HMAC-SHA256 hex digest (64 chars); 001
    created it as VARCHAR(6) and 002 widens it. SQLite ignores length limits
    entirely, so nothing else in the suite would notice a regression here.
    """
    migration, orm = _schema_from_sql(upgrade_sql), _orm_schema()
    mismatches = []
    for table, columns in orm.items():
        for column, rendered in columns.items():
            if not rendered.startswith("VARCHAR("):
                continue
            actual = migration.get(table, {}).get(column)
            if actual is None:
                continue  # reported by test_migration_defines_every_orm_column
            found = re.search(r"\((\d+)\)", actual)
            expected = re.search(r"\((\d+)\)", rendered).group(1)
            if found and found.group(1) != expected:
                mismatches.append(
                    f"{table}.{column}: ORM {expected}, migrations {found.group(1)}"
                )
    assert not mismatches, f"VARCHAR width mismatches: {mismatches}"


def test_downgrade_renders():
    """A downgrade that cannot even render is a downgrade nobody can run."""
    sql = _render("downgrade")
    assert "DROP TABLE users" in sql
    for enum_name in ENUM_TYPES:
        assert f"DROP TYPE {enum_name}" in sql or f"DROP TYPE IF EXISTS {enum_name}" in sql
