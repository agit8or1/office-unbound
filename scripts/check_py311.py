#!/usr/bin/env python3
"""Static check that the Python trees still parse on Python 3.11 (Debian 12's interpreter, a supported platform).

Running under 3.11 it simply byte-compiles. Running under 3.12+ (the dev host has no 3.11) it rejects every 3.12-only syntax form:
  * PEP 701 f-strings: an f-string nested inside another f-string's replacement field that reuses the SAME quote, a backslash or a comment inside
    a replacement field, a single-quoted f-string whose replacement field spans lines;
  * PEP 695: `type X = ...`, `def f[T]()`, `class C[T]:`.
`ast.parse(feature_version=(3, 11))` does not gate any of these, hence the token-level check. Usage: check_py311.py DIR...  (exit 1 on any hit)"""
import ast
import io
import os
import sys
import tokenize

SKIP = {".git", "node_modules", ".venv", "__pycache__", "static"}


def py_files(roots):
    for root in roots:
        for d, dirs, files in os.walk(root):
            dirs[:] = [x for x in dirs if x not in SKIP]
            for f in files:
                if f.endswith(".py"):
                    yield os.path.join(d, f)


def fstring_hits(src: str):
    """Yields (line, why) for 3.12-only f-string usage."""
    if not hasattr(tokenize, "FSTRING_START"):
        return
    stack = []   # [quote, triple, depth_of_braces]
    for t in tokenize.generate_tokens(io.StringIO(src).readline):
        if t.type == tokenize.FSTRING_START:
            q = t.string.lstrip("rRfFbBuU")
            if any(s["q"] == q[0] and s["in_expr"] and not (s["triple"] and len(q) == 1) for s in stack):
                yield t.start[0], f"f-string nested in an f-string expression reuses the quote {q[0]}"
            elif stack and stack[-1]["in_expr"] and "\\" in t.string:
                yield t.start[0], "backslash in f-string expression"
            stack.append({"q": q[0], "triple": len(q) == 3, "in_expr": False, "depth": 0, "line": t.start[0]})
        elif t.type == tokenize.FSTRING_END:
            stack.pop()
        elif stack:
            s = stack[-1]
            if t.type == tokenize.OP and t.string == "{" and not s["in_expr"]:
                s["in_expr"], s["depth"] = True, 1
            elif s["in_expr"]:
                if t.type == tokenize.OP and t.string == "{":
                    s["depth"] += 1
                elif t.type == tokenize.OP and t.string == "}":
                    s["depth"] -= 1
                    if s["depth"] == 0:
                        s["in_expr"] = False
                elif t.type == tokenize.COMMENT:
                    yield t.start[0], "comment inside an f-string expression"
                elif t.type == tokenize.STRING:
                    body = t.string.lstrip("rRbBuU")
                    if "\\" in t.string:
                        yield t.start[0], "backslash in a string inside an f-string expression"
                    if body[0] == s["q"] and (not s["triple"] or body[:3] == s["q"] * 3):
                        yield t.start[0], f"string inside an f-string expression reuses the f-string's quote {s['q']}"
                elif t.type in (tokenize.NL, tokenize.NEWLINE) and not s["triple"]:
                    yield t.start[0], "single-quoted f-string expression spans lines"
        # a nested f-string's own braces are tracked by its own stack entry; the parent stays "in_expr"


def syntax_hits(src: str):
    tree = ast.parse(src, feature_version=(3, 11))
    for n in ast.walk(tree):
        if type(n).__name__ == "TypeAlias":
            yield n.lineno, "`type X = ...` statement (3.12)"
        elif getattr(n, "type_params", None):
            yield n.lineno, "generic type parameters (PEP 695, 3.12)"


def main(argv):
    roots = argv[1:] or ["ics/ics", "ics/agent", "ics/migrations", "ics/tests", "portal", "migration", "scripts", "blueprints"]
    roots = [r for r in roots if os.path.isdir(r)]
    bad = 0
    n = 0
    for p in sorted(py_files(roots)):
        n += 1
        try:
            src = open(p, encoding="utf-8").read()
        except (OSError, UnicodeDecodeError) as e:
            print(f"{p}: unreadable: {e}")
            bad += 1
            continue
        if sys.version_info < (3, 12):
            try:
                compile(src, p, "exec")
            except SyntaxError as e:
                print(f"{p}:{e.lineno}: {e.msg}")
                bad += 1
            continue
        try:
            hits = list(syntax_hits(src)) + list(fstring_hits(src))
        except SyntaxError as e:
            print(f"{p}:{e.lineno}: {e.msg}")
            bad += 1
            continue
        for line, why in hits:
            print(f"{p}:{line}: {why}")
            bad += 1
    print(f"checked {n} Python files for Python 3.11 compatibility, {bad} problem(s) (interpreter {sys.version.split()[0]})")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
