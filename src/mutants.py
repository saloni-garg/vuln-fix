"""Mutant PoC generation (SPEC Section 5).

A mutant is a payload string for the instance's own PoC harness: same
vulnerability class, different surface. Mutators are fixed code, frozen
with the dataset at the Phase 1 freeze; the funnel validates every
mutant (must succeed on the vulnerable commit and fail on the gold
commit) and the surviving list is written into the instance package, so
later mutator edits cannot change a frozen instance.
"""
from __future__ import annotations

import urllib.parse


def traversal_transforms(visible: str, params: dict) -> list[str]:
    """Path-traversal surface variants of the visible payload."""
    out = []
    out.append(urllib.parse.quote(visible, safe=""))          # %2e%2e%2f..
    out.append(visible.replace("/", "//"))                    # double slash
    out.append("./" + visible)                                # dot prefix
    out.append(visible.replace("/", "%2f"))                   # encoded slash
    out.append(visible.replace("../", "....//"))              # nested dots
    out.append(visible.replace("/", "\\"))                    # backslash
    if params.get("absolute"):
        out.append(params["absolute"])
    return _dedup(out, visible)


def sql_fragment_variants(visible: str, params: dict) -> list[str]:
    """Boolean-tautology surface variants. `visible` is the full payload;
    params carry prefix/fragment so variants keep the injection grammar
    of the instance (connector, alias, key transform) while changing the
    boolean surface: casing, spacing, comment separation, equivalent
    comparisons."""
    prefix = params["prefix"]
    frag = params.get("fragment", "1=1")
    variants = [
        prefix.lower() + frag,
        prefix + frag.replace("=", " = "),
        prefix + "/**/" + frag,
        prefix + frag.replace("1=1", "'x'='x'"),
        prefix + frag.replace("1=1", "2>1"),
        prefix + "\t" + frag,
    ]
    return _dedup(variants, visible)


def explicit(visible: str, params: dict) -> list[str]:
    """Instance-declared variants (still code-generated, still validated
    by the funnel, still frozen into the package)."""
    return _dedup(list(params["payloads"]), visible)


def _dedup(items, visible):
    seen, out = set(), []
    for x in items:
        if x != visible and x not in seen:
            seen.add(x)
            out.append(x)
    return out


MUTATORS = {
    "traversal_transforms": traversal_transforms,
    "sql_fragment_variants": sql_fragment_variants,
    "explicit": explicit,
}


def generate(inst: dict) -> list[str]:
    spec = inst["mutator"]
    fn = MUTATORS[spec["name"]]
    return fn(inst["visible_payload"], spec.get("params", {}))
