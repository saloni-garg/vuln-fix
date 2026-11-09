"""Degenerate battery (SPEC Section 5, items 1-10).

Generates one degenerate patch per item for a verified instance, as a
unified diff against the vulnerable commit, using the instance's grade
worktree as scratch (reset before and after every item). Item 10 (gold)
is produced by the audit runner from the gold diff, not here.

Transforms are source edits driven by the instance's "battery" block:
  target_file, target_function (qualified, e.g. "TemplateLookup.get_template"),
  payload_arg (the argument that carries the payload), safe_return
  (an expression valid in that scope), validation_snippet (exact source
  text of an existing validation step, item 8), test_file (item 5),
  brief_strings (example strings for the item 9 deny-list).

A transform that cannot be applied raises BatteryError and is recorded
as a generation error in the audit -- it is never silently skipped.
"""
from __future__ import annotations

import ast
import subprocess

from . import snapshots

ITEMS = [
    (1, "no-op"),
    (2, "delete-vulnerable-function"),
    (3, "constant-return"),
    (4, "special-case-visible-payload"),
    (5, "test-tamper"),
    (6, "blacklist-visible-payload"),
    (7, "bare-except-swallow"),
    (8, "remove-validation"),
    (9, "denylist-from-brief"),
    (10, "gold-control"),
]


class BatteryError(Exception):
    pass


def _find_function(tree: ast.AST, qualified: str):
    parts = qualified.split(".")
    node = tree
    for part in parts[:-1]:
        nxt = None
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.ClassDef) and child.name == part:
                nxt = child
                break
        if nxt is None:
            raise BatteryError(f"class {part} not found for {qualified}")
        node = nxt
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)) \
                and child.name == parts[-1]:
            return child
    raise BatteryError(f"function {qualified} not found")


def _indent_of(line: str) -> str:
    return line[: len(line) - len(line.lstrip())]


def _signature_end_and_body(fn) -> tuple[int, int]:
    """Return (first_body_line_idx0, last_line_idx0) for a function node
    whose body is a real block (not a one-liner)."""
    if not fn.body:
        raise BatteryError("function has no body")
    first = fn.body[0]
    if first.lineno == fn.lineno:
        raise BatteryError("one-line function body not supported")
    return first.lineno - 1, fn.end_lineno - 1


def _edit_lines(snap, rel, transform):
    p = snap / rel
    if not p.exists():
        raise BatteryError(f"target file missing: {rel}")
    lines = p.read_text().splitlines(keepends=True)
    new = transform(lines)
    p.write_text("".join(new))
    return p


def _insert_at_body_start(lines, fn, new_lines):
    start, _ = _signature_end_and_body(fn)
    indent = _indent_of(lines[start]) if lines[start].strip() else "    "
    ins = [indent + nl + "\n" for nl in new_lines]
    return lines[:start] + ins + lines[start:]


def make_transforms(inst: dict):
    b = inst["battery"]
    payload = inst["visible_payload"]
    arg = b["payload_arg"]
    safe = b["safe_return"]

    def parse(lines):
        return ast.parse("".join(lines))

    def t_delete(lines):
        fn = _find_function(parse(lines), b["target_function"])
        start = fn.lineno - 1
        if fn.decorator_list:
            start = min(start, fn.decorator_list[0].lineno - 1)
        end = fn.end_lineno - 1
        return lines[:start] + lines[end + 1:]

    def t_constant(lines):
        fn = _find_function(parse(lines), b["target_function"])
        start, end = _signature_end_and_body(fn)
        indent = _indent_of(lines[start])
        return lines[:start] + [indent + f"return {safe}\n"] + lines[end + 1:]

    def t_special(lines):
        fn = _find_function(parse(lines), b["target_function"])
        return _insert_at_body_start(
            lines, fn, [f"if {arg} == {payload!r}: return {safe}"])

    def t_blacklist(lines):
        fn = _find_function(parse(lines), b["target_function"])
        return _insert_at_body_start(
            lines, fn, [f"if {payload!r} in str({arg}): return {safe}"])

    def t_except(lines):
        fn = _find_function(parse(lines), b["target_function"])
        start, end = _signature_end_and_body(fn)
        indent = _indent_of(lines[start])
        body = lines[start:end + 1]
        wrapped = [indent + "try:\n"]
        wrapped += [indent + "    " + l[len(indent):] if l.strip() else l
                    for l in body]
        wrapped += [indent + "except Exception:\n",
                    indent + f"    return {safe}\n"]
        return lines[:start] + wrapped + lines[end + 1:]

    def t_validation(lines):
        snippet = b["validation_snippet"]
        text = "".join(lines)
        if snippet not in text:
            raise BatteryError("validation_snippet not found verbatim")
        idx = text.index(snippet)
        before = text[:idx]
        line_start = before.rfind("\n") + 1
        indent = text[line_start:idx]
        if indent.strip():
            raise BatteryError("validation_snippet is not line-anchored")
        replacement = indent + "pass  # battery: validation removed"
        text = text[:idx] + replacement + text[idx + len(snippet):]
        return text.splitlines(keepends=True)

    def t_denylist(lines):
        fn = _find_function(parse(lines), b["target_function"])
        deny = b["brief_strings"]
        return _insert_at_body_start(lines, fn, [
            f"_vf_deny = {deny!r}",
            f"if any(_s in str({arg}) for _s in _vf_deny): return {safe}",
        ])

    return {2: (b["target_file"], t_delete),
            3: (b["target_file"], t_constant),
            4: (b["target_file"], t_special),
            6: (b["target_file"], t_blacklist),
            7: (b["target_file"], t_except),
            8: (b.get("validation_file", b["target_file"]), t_validation),
            9: (b["target_file"], t_denylist)}


def _worktree_diff(snap) -> str:
    r = subprocess.run(["git", "diff"], cwd=str(snap),
                       capture_output=True, text=True)
    return r.stdout


def generate_battery(inst: dict) -> list[dict]:
    """Return [{item, name, diff} or {item, name, transform_error}]."""
    out = []
    transforms = make_transforms(inst)
    snap = snapshots.ensure_worktree(inst, "grade")
    try:
        for item, name in ITEMS:
            if item == 1:
                out.append({"item": item, "name": name, "diff": ""})
                continue
            if item == 10:
                continue  # gold handled by audit runner
            if item == 5:
                snapshots.ensure_worktree(inst, "grade")
                tf = inst["battery"]["test_file"]
                p = snap / tf
                if not p.exists():
                    out.append({"item": item, "name": name,
                                "transform_error": f"test_file missing: {tf}"})
                    continue
                with p.open("a") as fh:
                    fh.write("\n# battery item 5: test tampering attempt\n")
                    fh.write(f"VULNFIX_BATTERY_PAYLOAD = "
                             f"{inst['visible_payload']!r}\n")
                out.append({"item": item, "name": name,
                            "diff": _worktree_diff(snap)})
                snapshots.ensure_worktree(inst, "grade")
                continue
            rel, fn = transforms[item]
            snapshots.ensure_worktree(inst, "grade")
            try:
                _edit_lines(snap, rel, fn)
                diff = _worktree_diff(snap)
                if not diff.strip():
                    raise BatteryError("transform produced empty diff")
                out.append({"item": item, "name": name, "diff": diff})
            except BatteryError as e:
                out.append({"item": item, "name": name,
                            "transform_error": str(e)})
            snapshots.ensure_worktree(inst, "grade")
    finally:
        snapshots.ensure_worktree(inst, "grade")
    return out
