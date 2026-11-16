"""SQL AST security analyzer, mutation blocker, and LIMIT rewriter using sqlglot.

Enforces zero mutation, single statement, and bounded row limits.
"""

import sqlglot
import sqlglot.expressions as exp
from sqlglot.errors import SqlglotError

from app.errors import SecurityViolationError

# Expressions that mutate state or alter database configuration
FORBIDDEN_EXPRESSION_TYPES: tuple[type[exp.Expression], ...] = (
    exp.Insert,
    exp.Update,
    exp.Delete,
    exp.Drop,
    exp.Alter,
    exp.Create,
    exp.Command,
    exp.Pragma,
)

# SQLite functions that allow code execution or out-of-band I/O
BANNED_FUNCTIONS: frozenset[str] = frozenset(
    {
        "load_extension",
        "writefile",
        "readfile",
        "edit",
        "fts3_tokenizer",
    }
)


def validate_and_sanitize_sql(
    sql: str,
    *,
    max_rows: int = 100,
    dialect: str = "sqlite",
) -> str:
    """Parse SQL query, verify read-only invariants, clamp LIMIT, and transpile.

    1. Enforces single statement only (rejects SQL injection chaining).
    2. Enforces root expression is Select or Union.
    3. Walks AST to reject any nested mutation expressions.
    4. Scans for banned function invocations (e.g. load_extension).
    5. Injects or clamps LIMIT clause to max_rows.

    Raises:
        SecurityViolationError: If the SQL contains mutations, multi-statements,
                                banned functions, or invalid syntax.
    """
    cleaned_sql = sql.strip()
    if not cleaned_sql:
        raise SecurityViolationError("SQL query cannot be empty")

    try:
        statements = sqlglot.parse(cleaned_sql, read=dialect)
    except SqlglotError as err:
        raise SecurityViolationError(f"SQL parse error: {err}") from err

    # Filter out None statements from whitespace/comment-only parses
    valid_statements = [s for s in statements if s is not None]
    if not valid_statements:
        raise SecurityViolationError(
            "SQL query contains no valid executable statements"
        )

    if len(valid_statements) > 1:
        raise SecurityViolationError(
            f"Multi-statement queries are forbidden (found {len(valid_statements)} statements)"
        )

    stmt = valid_statements[0]

    # Verify root statement is SELECT or UNION
    if not isinstance(stmt, (exp.Select, exp.Union)):
        raise SecurityViolationError(
            f"Forbidden statement type '{type(stmt).__name__}'. Only SELECT queries are permitted."
        )

    # Walk entire AST to reject any nested mutation expressions (e.g. in CTEs or subqueries)
    for node in stmt.walk():
        if isinstance(node, FORBIDDEN_EXPRESSION_TYPES):
            raise SecurityViolationError(
                f"Forbidden nested statement '{type(node).__name__}' detected"
            )

    # Reject dangerous function calls
    for func in stmt.find_all(exp.Anonymous, exp.Func):
        if func.name:
            fn_name_lower = func.name.lower()
            if fn_name_lower in BANNED_FUNCTIONS:
                raise SecurityViolationError(
                    f"Forbidden function call '{func.name}' detected"
                )

    # Enforce and clamp LIMIT clause
    existing_limit = stmt.find(exp.Limit)
    if existing_limit is not None:
        clamped = False
        for lit in existing_limit.find_all(exp.Literal):
            if lit.is_number:
                val = int(lit.this)
                if val > max_rows:
                    lit.set("this", str(max_rows))
                clamped = True
                break
        if not clamped:
            stmt.set("limit", exp.Limit(expression=exp.Literal.number(max_rows)))
    else:
        stmt.set("limit", exp.Limit(expression=exp.Literal.number(max_rows)))

    return stmt.sql(dialect=dialect)
