#!/usr/bin/env python3
"""Print the API's routes as a Markdown table, read from the source.

    python3 scripts/list_routes.py            # table for docs/TECHNICAL_REFERENCE.md
    python3 scripts/list_routes.py --count    # just the number of routes

The route table in the technical reference used to be kept by hand and fell
behind (45 of 67 routes at one point). This reads backend/app/api/*.py with
the standard library's ast module, so it needs neither the backend's
dependencies nor a running API, and CI can check that the documented count
still matches the code.

Auth is inferred from each handler's dependencies: `require_role("x")`,
`get_current_user` (any signed-in user), `verify_honeypot_token` and friends
(the engine's token), or none. A dependency this script does not recognise is
printed by name rather than guessed at.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
API_DIR = ROOT / "backend" / "app" / "api"
MAIN = ROOT / "backend" / "app" / "main.py"
API_PREFIX = "/api/v1"
METHODS = {"get", "post", "put", "patch", "delete"}

#: Dependency name -> what the table says. Anything else is shown verbatim.
KNOWN_AUTH = {
    "get_current_user": "any",
    "feed_auth": "any or feed token",
    "verify_honeypot_token": "engine token",
    "verify_node_token": "engine token",
    "verify_control_token": "control token",
}
#: Dependencies that are not authentication.
NOT_AUTH = {"get_db", "session_filters"}


def _depends_target(node: ast.AST) -> str | None:
    """`Depends(x)` or `Depends(require_role("admin"))` -> a label, else None."""
    if not (isinstance(node, ast.Call) and getattr(node.func, "id", None) == "Depends" and node.args):
        return None
    inner = node.args[0]
    if isinstance(inner, ast.Call) and getattr(inner.func, "id", None) == "require_role" and inner.args:
        role = inner.args[0]
        return role.value if isinstance(role, ast.Constant) else "role"
    name = getattr(inner, "id", None) or getattr(inner, "attr", None)
    if name is None or name in NOT_AUTH:
        return None
    return KNOWN_AUTH.get(name, name)


def _auth(func: ast.AsyncFunctionDef | ast.FunctionDef, decorator: ast.Call) -> str:
    found: list[str] = []
    args = func.args
    for default in [*args.defaults, *args.kw_defaults]:
        label = _depends_target(default) if default is not None else None
        if label:
            found.append(label)
    for keyword in decorator.keywords:
        if keyword.arg == "dependencies" and isinstance(keyword.value, ast.List):
            for element in keyword.value.elts:
                label = _depends_target(element)
                if label:
                    found.append(label)
    return ", ".join(dict.fromkeys(found)) or "none"


def _summary(func: ast.AsyncFunctionDef | ast.FunctionDef) -> str:
    doc = ast.get_docstring(func) or ""
    first = doc.strip().split("\n\n")[0].replace("\n", " ").strip()
    if not first:
        first = func.name.replace("_", " ").capitalize()
    return first.rstrip(".").replace("|", "\\|")


def _routes_in(path: Path, router_name: str, prefix: str):
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in ast.walk(tree):
        if not isinstance(node, (ast.AsyncFunctionDef, ast.FunctionDef)):
            continue
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call):
                continue
            target = decorator.func
            if not (isinstance(target, ast.Attribute) and target.attr in METHODS):
                continue
            if getattr(target.value, "id", None) != router_name:
                continue
            route = ""
            if decorator.args and isinstance(decorator.args[0], ast.Constant):
                route = str(decorator.args[0].value)
            yield target.attr.upper(), prefix + route, _auth(node, decorator), _summary(node)


def _prefixes() -> dict[str, str]:
    """module name -> mount prefix, from app/api/__init__.py."""
    tree = ast.parse((API_DIR / "__init__.py").read_text(encoding="utf-8"))
    found: dict[str, str] = {}
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and getattr(node.func, "attr", None) == "include_router"):
            continue
        if not node.args:
            continue
        module = getattr(getattr(node.args[0], "value", None), "id", None)
        prefix = next(
            (k.value.value for k in node.keywords if k.arg == "prefix" and isinstance(k.value, ast.Constant)),
            "",
        )
        if module:
            found[module] = prefix
    return found


def collect() -> list[tuple[str, str, str, str]]:
    rows = list(_routes_in(MAIN, "app", ""))
    for module, prefix in _prefixes().items():
        source = API_DIR / f"{module}.py"
        if source.exists():
            rows.extend(_routes_in(source, "router", API_PREFIX + prefix))
    order = {method: index for index, method in enumerate(["GET", "POST", "PUT", "PATCH", "DELETE"])}
    return sorted(rows, key=lambda row: (row[1].split("/")[3:4], row[1], order[row[0]]))


def main() -> int:
    rows = collect()
    if "--count" in sys.argv[1:]:
        print(len(rows))
        return 0
    print("| Method | Path | Auth | Description |")
    print("|---|---|---|---|")
    for method, route, auth, summary in rows:
        print(f"| {method} | `{route}` | {auth} | {summary} |")
    print(f"\n{len(rows)} routes.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
