"""The tools. Every one runs as the verified caller; Ranger decides what that caller may see.

The read-only check is a guard against accidents, not the security boundary: Ranger authorizes every statement
Impala runs, whatever this module lets through.
"""
import re

from . import __version__
from .auth import current_user

READ_ONLY = ("select", "show", "describe", "desc", "with", "explain")
IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
WITH_STATEMENT = re.compile(r"\b(select|insert|update|delete|upsert|merge|create|alter|drop|truncate|load|refresh|invalidate|compute)\b", re.IGNORECASE)


def _with_body_keyword(statement):
    """Return the first top-level statement keyword after a WITH clause.

    Impala permits a WITH clause before INSERT, so checking only the first
    keyword is insufficient for a read-only guard. This is intentionally a
    small lexical scan, not a SQL parser: it tracks parentheses, quoted
    strings, and comments so keywords inside CTEs do not count.
    """
    depth = 0
    index = 4  # len("with")
    length = len(statement)
    while index < length:
        char = statement[index]
        if char in "'\"`":
            quote = char
            index += 1
            while index < length:
                if statement[index] == quote:
                    if index + 1 < length and statement[index + 1] == quote:
                        index += 2
                        continue
                    index += 1
                    break
                index += 1
            continue
        if char == "-" and index + 1 < length and statement[index + 1] == "-":
            newline = statement.find("\n", index + 2)
            index = length if newline < 0 else newline + 1
            continue
        if char == "/" and index + 1 < length and statement[index + 1] == "*":
            end = statement.find("*/", index + 2)
            index = length if end < 0 else end + 2
            continue
        if char == "(":
            depth += 1
            index += 1
            continue
        if char == ")":
            depth = max(0, depth - 1)
            index += 1
            continue
        match = WITH_STATEMENT.match(statement, index) if depth == 0 else None
        if match:
            return match.group(1).lower()
        index += 1
    return None


def read_only(sql):
    statement = sql.strip().rstrip(";").strip()
    if not statement:
        raise ValueError("The query is empty")
    if ";" in statement:
        raise ValueError("One statement per call")
    first = statement.split(None, 1)[0].lower()
    if first not in READ_ONLY:
        raise ValueError("Only read-only statements are allowed: " + ", ".join(k.upper() for k in READ_ONLY))
    if first == "with" and _with_body_keyword(statement) != "select":
        raise ValueError("WITH statements must contain a top-level SELECT")
    return statement


def identifier(value, what):
    if not IDENTIFIER.match(value or ""):
        raise ValueError(f"{what} must be a plain identifier (letters, digits and underscores)")
    return value


def register(mcp, impala, settings):
    def clamp(limit):
        return max(1, min(limit or settings.default_limit, settings.max_limit))

    @mcp.tool()
    def whoami() -> dict:
        """Report which account this server acts for on the current request, and how. Use it to confirm that
        queries run as you and that Ranger applies your policies."""
        return {"user": current_user.get(), "auth_mode": settings.auth_mode,
            "impersonation": f"doAs={current_user.get()} via {settings.impala_auth} proxy {settings.principal or settings.impala_user}" if settings.impersonate
                else f"none: queries run as the service account {settings.impala_user or settings.principal}",
            "warehouse": f"{settings.impala_host}:{settings.impala_port}", "server_version": __version__}

    @mcp.tool()
    def execute_query(query: str, limit: int = 0) -> dict:
        """Run a read-only SQL statement (SELECT, WITH, SHOW, DESCRIBE, EXPLAIN) on the Iceberg tables in Impala and
        return the columns and rows. The query runs as you, so Ranger row and column policies apply. `limit` caps
        the rows returned (default and maximum are set by the server); `truncated` tells you when more exist."""
        return impala.run(current_user.get(), read_only(query), clamp(limit))

    @mcp.tool()
    def list_databases() -> dict:
        """List the databases visible to you in this Impala warehouse."""
        result = impala.run(current_user.get(), "SHOW DATABASES", settings.max_limit)
        return {"databases": [row[0] for row in result["rows"]]}

    @mcp.tool()
    def get_schema(database: str = "") -> dict:
        """List the tables in a database (the server's default database when none is given)."""
        database = identifier(database, "database") if database else settings.impala_database
        result = impala.run(current_user.get(), f"SHOW TABLES IN {database}", settings.max_limit)
        return {"database": database, "tables": [row[0] for row in result["rows"]]}

    @mcp.tool()
    def describe_table(table: str, database: str = "") -> dict:
        """Describe a table's columns and types. Give the table name and, optionally, its database; the server's
        default database is used otherwise."""
        database = identifier(database, "database") if database else settings.impala_database
        table = identifier(table, "table")
        result = impala.run(current_user.get(), f"DESCRIBE {database}.{table}", settings.max_limit)
        columns = [dict(zip(("name", "type", "comment"), (list(row) + ["", "", ""])[:3])) for row in result["rows"]]
        return {"database": database, "table": table, "columns": columns}

    return [whoami, execute_query, list_databases, get_schema, describe_table]
