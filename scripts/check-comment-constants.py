#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Fail when a comment asserts a value for a constant that the constant does not have.

The rot this guard exists to stop
---------------------------------
The most expensive defect in this repository is not a wrong constant. It is a
comment sitting one line above a constant, in the present tense, stating a value
that constant does not hold. A reviewer reads the comment and the code as one
statement instead of two claims, so the lie is invisible at review and survives
into consensus. Several instances were found by accident within two days, most
of them in `bloch-pos-committee`:

  * `TRANSFER_WITNESS_DEDUP_ACTIVATION_EPOCH` — doc said "`u64::MAX` means
    INERT"; the constant was `800` and had been live for ~950 epochs.
  * `BLOCK_BYTES_V2_ACTIVATION_EPOCH` — doc said "`u64::MAX` until the founder
    sets it"; the constant was `800`.
  * `EUVM_ACTIVATION_HEIGHT` — doc said "pinned at `u64::MAX` (an inert
    sentinel)" in three separate places; the constant was `4320`.

Every one of those is the same machine-checkable shape: **prose naming a value,
next to a constant holding a different one.** That shape is what this checks.

What it checks (the honest scope)
---------------------------------
Three passes over `//`, `///` and `//!` comments in workspace Rust sources.

  Pass A — ATTACHED. For each `const`/`static` whose initialiser is a resolvable
  literal, take the contiguous comment block immediately above it and look for a
  value assertion with no explicit subject ("pinned at `u64::MAX`", "set to
  `4320`", "`u64::MAX` means INERT"). The subject of such a sentence is the item
  the block documents, so the asserted value must be that item's value.

  Pass B — NAMED. Anywhere in the workspace, a comment that names a constant
  identifier and asserts a value for it in the same clause ("Because
  `EUVM_ACTIVATION_HEIGHT` is `u64::MAX`, this is `false`"). The name is resolved
  against a workspace-wide table; a name declared twice with different values is
  skipped as ambiguous rather than guessed at.

  Pass C — BOUND (opt-in). A bare number in prose has nothing to compare against
  unless an author binds it to a constant by hand:

      /// Measured on Genesis-3 at height 39,918 (452,726 UTXOs, 16 addresses).
      /// prose-guard: bind height=CARRYOVER_MEASURED_HEIGHT,
      ///   UTXOs=CARRYOVER_MEASURED_UTXOS

  Each `label=CONST` pins every `<label> <number>` / `<number> <label>` phrase in
  the PARAGRAPH the directive closes — the run of comment lines back to the last
  blank one — so a bind on one sentence does not also claim a history table three
  paragraphs below. A bind naming an unresolvable constant, or matching no
  phrase, is itself a failure — a dead binding is a guard that silently stopped
  guarding. Unbound prose numbers are NOT checked; this pass finds nothing on its
  own, and that limit is the point of stating it here.

A "value" is an integer literal (`4320`, `10_000`, `0x20d0`), a
`<int-type>::MAX` / `::MIN` sentinel, or `true` / `false`. A constant whose
initialiser is an expression, an array, a call, or a reference to another
constant is UNRESOLVED: it is counted and reported, never guessed at.

What it CANNOT catch — read this before trusting it
---------------------------------------------------
This is a narrow guard and pretending otherwise is how a guard gets disabled.
It does not and cannot check:

  * Any claim that is not a constant-and-value pair. "Genesis-4 blocks carry EVM
    transactions", "Deposit and Delegate bond existing coins", "a transaction
    carries no id", "`ask` is never on the wire" — all real instances of the same
    defect class, all invisible here. Claims of presence, of absence, of
    reachability, and of a type's shape are outside the subset.
  * Any prose number the author has not bound with `prose-guard: bind`. The
    carryover doc that said "height 43,172 (448,337 UTXOs, 15 addresses)" beside
    constants reading 39,918 / 452,726 / 16 named none of them, so nothing tied
    the prose to the code until a human tied it.
  * A constant that is right and prose that is right while the *mechanism* is
    wrong — a correctly-documented flag day that nothing reads.
  * Values reached by arithmetic, `cfg`, feature flags, or build scripts.
  * Prose in `docs/`, in commit messages, or in any non-Rust file.
  * Units. "`800` epochs" against `const X: u64 = 800` passes whether the
    constant counts epochs, slots or seconds.

Suppression
-----------
A legitimate mention that trips a pattern is silenced with

    prose-guard: allow(this names the value the constant would have if inert)

on any line of the comment block. Every suppression is counted and printed on
every run, so a growing suppression list is visible rather than quiet.

Exit status 0 = every checkable claim matches the constant it describes.
"""

from __future__ import annotations

import argparse
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

SKIP_DIRS = {".git", "target", "node_modules", ".claude", "vendor"}

# ── value literals ────────────────────────────────────────────────────────────

INT_TYPES = "u8|u16|u32|u64|u128|usize|i8|i16|i32|i64|i128|isize"
MAXMIN = re.compile(rf"\b(?P<ty>{INT_TYPES})::(?P<ext>MAX|MIN)\b")

SENTINEL_NUM: dict[tuple[str, str], int] = {
    ("u8", "MAX"): 255,
    ("u16", "MAX"): 65535,
    ("u32", "MAX"): 4294967295,
    ("u64", "MAX"): 18446744073709551615,
    ("u128", "MAX"): 340282366920938463463374607431768211455,
    ("usize", "MAX"): 18446744073709551615,
    ("i8", "MAX"): 127,
    ("i16", "MAX"): 32767,
    ("i32", "MAX"): 2147483647,
    ("i64", "MAX"): 9223372036854775807,
    ("i128", "MAX"): 170141183460469231731687303715884105727,
    ("isize", "MAX"): 9223372036854775807,
}
for _t in ("u8", "u16", "u32", "u64", "u128", "usize"):
    SENTINEL_NUM[(_t, "MIN")] = 0
for _t, _bits in (("i8", 8), ("i16", 16), ("i32", 32),
                  ("i64", 64), ("i128", 128), ("isize", 64)):
    SENTINEL_NUM[(_t, "MIN")] = -(2 ** (_bits - 1))


class Val:
    """A resolved value: an integer, a MAX/MIN sentinel, or a bool."""

    __slots__ = ("kind", "num", "text")

    def __init__(self, kind: str, num: int | None, text: str):
        self.kind = kind  # "int" | "sentinel" | "bool"
        self.num = num
        self.text = text

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Val):
            return NotImplemented
        if self.kind == "bool" or other.kind == "bool":
            return self.kind == other.kind and self.text == other.text
        # A sentinel and an integer compare by number, so a comment that spells
        # out 18446744073709551615 is checked against `u64::MAX` correctly.
        return self.num == other.num

    def __repr__(self) -> str:
        return self.text


def parse_int(text: str) -> int | None:
    t = text.replace("_", "").replace(",", "")
    try:
        return int(t, 16) if t[:2].lower() == "0x" else int(t)
    except ValueError:
        return None


def resolve_literal(expr: str) -> Val | None:
    """Resolve a constant initialiser, but only when it is unambiguously a literal.

    Anything with an operator, a call, a path, an array or another identifier is
    left UNRESOLVED on purpose. A guard that guesses at a value is worse than a
    guard that reports how much it could not read.
    """
    e = expr.strip().rstrip(";").strip()
    if e in ("true", "false"):
        return Val("bool", None, e)
    m = MAXMIN.fullmatch(e)
    if m:
        return Val("sentinel", SENTINEL_NUM[(m.group("ty"), m.group("ext"))], e)
    m = re.fullmatch(r"(0[xX][0-9a-fA-F_]+|[0-9][0-9_]*)(?:" + INT_TYPES + r")?", e)
    if m:
        n = parse_int(m.group(1))
        return Val("int", n, e) if n is not None else None
    return None


# ── source scanning ───────────────────────────────────────────────────────────

CONST_DECL = re.compile(
    r"^\s*(?:pub(?:\s*\([^)]*\))?\s+)?(?:const|static)\s+(?:mut\s+)?"
    r"(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*:\s*[^=]+?=\s*(?P<val>.+?);\s*$"
)
COMMENT_LINE = re.compile(r"^\s*(?:///|//!|//)(?P<body>.*)$")
ATTR_LINE = re.compile(r"^\s*#\[")
ALLOW = re.compile(r"prose-guard:\s*allow\(", re.IGNORECASE)
BIND = re.compile(r"prose-guard:\s*bind\b(?P<binds>.*)", re.IGNORECASE | re.DOTALL)


def rust_sources(roots: list[str]) -> list[str]:
    out: list[str] = []
    for root in roots:
        base = os.path.join(REPO, root)
        if os.path.isfile(base):
            out.append(os.path.relpath(base, REPO))
            continue
        for dirpath, dirs, files in os.walk(base):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".")]
            for f in files:
                if f.endswith(".rs"):
                    out.append(os.path.relpath(os.path.join(dirpath, f), REPO))
    return sorted(out)


def comment_block_above(lines: list[str], idx: int) -> tuple[int, int]:
    """[start, end) line indices of the contiguous comment/attribute run above `idx`."""
    i = idx - 1
    while i >= 0 and (COMMENT_LINE.match(lines[i]) or ATTR_LINE.match(lines[i])):
        i -= 1
    return i + 1, idx


def strip_markers(line: str) -> str:
    m = COMMENT_LINE.match(line)
    return m.group("body") if m else ""


# ── claim patterns ────────────────────────────────────────────────────────────

# A value as it appears in prose: `u64::MAX`, u64::MAX, `4320`, **800**, 0x20d0
VALUE_TOK = (
    r"[`*]*(?:(?:" + INT_TYPES + r")::(?:MAX|MIN)"
    r"|0[xX][0-9a-fA-F_]+|[0-9][0-9_]*)[`*]*"
)

# Pass A: a value assertion whose subject is elided — the subject is therefore the
# item the doc block is attached to. Each verb below reads as a statement about
# *this* item, in the present tense.
SUBJECTLESS = re.compile(
    r"(?<![A-Za-z0-9_])"
    r"(?:[Pp]inned (?:at|to)|[Hh]eld (?:at|to)|[Ss]et to|[Ss]tays(?: at)?"
    r"|[Rr]emains(?: at)?|[Ss]its at|[Dd]efaults? to|[Ii]nitiali[sz](?:ed|es) to"
    r"|[Cc]urrently|[Ii]s currently|[Ii]ts value is)"
    r"\s+(?P<val>" + VALUE_TOK + r")"
)

# "`u64::MAX` means INERT" / "`u64::MAX` until the founder sets it" — the sentinel
# as grammatical subject, asserting the documented item's present state. This is
# exactly the shape both `params.rs` instances took.
SENTINEL_SUBJECT = re.compile(
    r"(?P<val>[`*]*(?:" + INT_TYPES + r")::(?:MAX|MIN)[`*]*)"
    r"\s+(?:means|until|is the|denotes|marks|signals|keeps|=)\b"
)

# Pass B: "<NAME> is <value>", "<NAME> = <value>", "<NAME> is pinned at <value>".
# `mid` may not cross a sentence end, so the name and the value stay in one clause.
NAMED = re.compile(
    r"[`\[]{0,2}(?P<name>[A-Z][A-Z0-9_]{3,})[`\]]{0,2}"
    r"(?P<mid>(?:[^.;!?\n`]|`[^`\n]*`){0,60}?)"
    r"\b(?:is|are|was|were|remains|stays|equals|reads|holds"
    r"|pinned at|held at|set to|=)\s+(?P<val>" + VALUE_TOK + r")"
)

# Hypothetical or historical framing. Kept deliberately small: every extra word
# here is a real contradiction this guard will wave through.
HYPOTHETICAL = re.compile(
    r"\b(?:not|never|no longer|isn't|wasn't|weren't|aren't|doesn't|don't"
    r"|would|could|might|used to|formerly|previously"
    r"|if|unless|were|was|had been|once"
    r"|should be|must be|will be|shall be|to be|becomes|become"
    r"|instead of|rather than|as opposed to|other than"
    r"|e\.g\.|for example)\b",
    re.IGNORECASE,
)

# Where a claim's framing lives: the clause it sits in, not the paragraph.
#
# Scoping this wrongly loses findings in BOTH directions, and both mistakes were
# made while writing this script. Scoped to the whole sentence, the word
# "lowered" elsewhere in a flag-day paragraph silenced a real contradiction.
# Scoped to a fixed 48 characters, the phrase "not scarce at all." ending the
# PREVIOUS sentence silenced another. So the window is the text from the last
# clause boundary to the claim: what a reader would say the claim is qualified by.
CLAUSE_BOUNDARY = re.compile(r"[.!?;:]\s|\n\s*\n|^\s*[-*]\s", re.MULTILINE)


def clause_prefix(block: str, start: int) -> str:
    last = 0
    for b in CLAUSE_BOUNDARY.finditer(block, 0, start):
        last = b.end()
    return block[last:start]


def hypothetical(block: str, start: int) -> bool:
    """Is this claim framed as counterfactual or historical rather than asserted?"""
    return bool(HYPOTHETICAL.search(clause_prefix(block, start)))


def prose_value(tok: str) -> Val | None:
    t = tok.strip("`*")
    m = MAXMIN.fullmatch(t)
    if m:
        return Val("sentinel", SENTINEL_NUM[(m.group("ty"), m.group("ext"))], t)
    n = parse_int(t)
    return Val("int", n, t) if n is not None else None


# ── findings ──────────────────────────────────────────────────────────────────

class Finding:
    def __init__(self, path: str, line: int, claim: str, actual: str,
                 const: str, why: str):
        self.path, self.line, self.claim = path, line, claim
        self.actual, self.const, self.why = actual, const, why

    def render(self) -> str:
        return (
            f"  FAIL {self.path}:{self.line}\n"
            f"        the comment says  {self.const} is {self.claim}\n"
            f"        the code says     {self.const} = {self.actual}\n"
            f"        {self.why}"
        )


def build_const_table(files: list[str], bodies: dict[str, list[str]]):
    """name -> (Val, 'path:line') for every workspace const with a literal initialiser.

    A name declared more than once with DIFFERENT values is dropped: Pass B has no
    import graph, so resolving it would be a guess, and a guessing guard is how
    you get a red CI nobody trusts.
    """
    table: dict[str, tuple[Val, str]] = {}
    ambiguous: set[str] = set()
    unresolved = 0
    for path in files:
        for i, line in enumerate(bodies[path]):
            m = CONST_DECL.match(line)
            if not m:
                continue
            val = resolve_literal(m.group("val"))
            if val is None:
                unresolved += 1
                continue
            name = m.group("name")
            prev = table.get(name)
            if prev is not None and not (prev[0] == val):
                ambiguous.add(name)
            table.setdefault(name, (val, f"{path}:{i + 1}"))
    for n in ambiguous:
        table.pop(n, None)
    return table, ambiguous, unresolved


def check_file(path: str, lines: list[str], table, findings: list[Finding],
               stats: dict) -> None:
    n = len(lines)

    # ── Pass A: value assertions in the block attached to a constant ──────────
    for i, line in enumerate(lines):
        m = CONST_DECL.match(line)
        if not m:
            continue
        actual = resolve_literal(m.group("val"))
        if actual is None:
            continue
        name = m.group("name")
        start, end = comment_block_above(lines, i)
        if start == end:
            continue
        if any(ALLOW.search(l) for l in lines[start:end]):
            stats["suppressed"] += 1
            continue
        block = "\n".join(strip_markers(l) for l in lines[start:end])
        for pat in (SUBJECTLESS, SENTINEL_SUBJECT):
            for mm in pat.finditer(block):
                stats["checked_a"] += 1
                claimed = prose_value(mm.group("val"))
                if claimed is None or claimed == actual:
                    continue
                if hypothetical(block, mm.start()):
                    stats["negated"] += 1
                    continue
                off = block[: mm.start()].count("\n")
                findings.append(Finding(
                    path, start + off + 1, mm.group("val").strip("`*"),
                    actual.text, name,
                    f"declared at {path}:{i + 1}; the claim is in the doc block "
                    f"attached to that declaration",
                ))

    # ── Passes B and C: over every contiguous comment block in the file ───────
    i = 0
    while i < n:
        if not COMMENT_LINE.match(lines[i]):
            i += 1
            continue
        j = i
        while j < n and COMMENT_LINE.match(lines[j]):
            j += 1
        if any(ALLOW.search(l) for l in lines[i:j]):
            stats["suppressed"] += 1
            i = j
            continue
        block = "\n".join(strip_markers(l) for l in lines[i:j])

        for mm in NAMED.finditer(block):
            entry = table.get(mm.group("name"))
            if entry is None:
                continue
            stats["checked_b"] += 1
            actual, where = entry
            claimed = prose_value(mm.group("val"))
            if claimed is None or claimed == actual:
                continue
            if hypothetical(block, mm.start()) or HYPOTHETICAL.search(mm.group("mid")):
                stats["negated"] += 1
                continue
            off = block[: mm.start()].count("\n")
            findings.append(Finding(
                path, i + off + 1, mm.group("val").strip("`*"),
                actual.text, mm.group("name"), f"declared at {where}",
            ))

        check_binds(path, i, [strip_markers(l) for l in lines[i:j]],
                    table, findings, stats)
        i = j


def check_binds(path: str, block_start: int, body: list[str], table,
                findings: list[Finding], stats: dict) -> None:
    """Pass C: a bind pins the PARAGRAPH it closes, and must actually pin something.

    Scope matters here and the first version got it wrong. Binding the whole
    contiguous comment block made a bind on one sentence also cover a deliberate
    history table of superseded measurements three paragraphs below — reporting
    every past value as a contradiction. So the scope is the paragraph the
    directive closes: the run of comment lines back to the last blank one. Write
    the sentence, then bind it on the line underneath.

    A binding that names an unresolvable constant, or that matches no phrase, is
    itself a failure. A guard whose bindings have quietly stopped matching
    anything is green because it is looking at nothing.
    """
    for k, line in enumerate(body):
        bm = BIND.search(line)
        if bm is None:
            continue
        # The directive may wrap; keep taking lines while they are only pairs.
        binds_text = bm.group("binds")
        m = k + 1
        while m < len(body) and re.fullmatch(r"[\s,]*(?:[A-Za-z][\w -]*=[A-Z][A-Z0-9_]+[\s,]*)+",
                                             body[m]):
            binds_text += " " + body[m]
            m += 1
        # The paragraph this directive closes.
        start = k
        while start > 0 and body[start - 1].strip():
            start -= 1
        para = "\n".join(body[start:k])
        para_line = block_start + start + 1

        pairs = re.findall(r"([A-Za-z][A-Za-z0-9 _-]*?)\s*=\s*([A-Z][A-Z0-9_]{3,})", binds_text)
        if not pairs:
            findings.append(Finding(
                path, block_start + k + 1, "(bind)", "?", "-",
                "`prose-guard: bind` with no `label=CONSTANT` pairs after it",
            ))
            continue
        if not para.strip():
            findings.append(Finding(
                path, block_start + k + 1, "(bind)", "?", "-",
                "`prose-guard: bind` closes an empty paragraph — put it directly "
                "under the prose it pins",
            ))
            continue
        for label, cname in pairs:
            label = label.strip()
            entry = table.get(cname)
            if entry is None:
                findings.append(Finding(
                    path, block_start + k + 1, "(bind)", "?", cname,
                    f"`prose-guard: bind {label}={cname}` names something that is "
                    f"not a resolvable workspace constant",
                ))
                continue
            actual, where = entry
            # `[ \t]` not `\s`: a label must not pair with a number on another
            # line, or a markdown table header binds to the row beneath it.
            pat = re.compile(
                rf"(?:{re.escape(label)}[ \t]+(?P<a>\d[\d,_]*)"
                rf"|(?P<b>\d[\d,_]*)[ \t]+{re.escape(label)})",
                re.IGNORECASE,
            )
            hits = list(pat.finditer(para))
            if not hits:
                findings.append(Finding(
                    path, para_line, "(bind)", actual.text, cname,
                    f"`prose-guard: bind {label}={cname}` matches no "
                    f"'{label} <number>' phrase in the paragraph above it — "
                    f"a dead binding guards nothing",
                ))
                continue
            for h in hits:
                stats["checked_c"] += 1
                raw = parse_int(h.group("a") or h.group("b"))
                if raw is None or actual.num is None or raw != actual.num:
                    off = para[: h.start()].count("\n")
                    findings.append(Finding(
                        path, para_line + off, h.group(0).strip(), actual.text,
                        cname,
                        f"bound by `prose-guard: bind {label}={cname}`; "
                        f"declared at {where}",
                    ))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("roots", nargs="*", default=["."],
                    help="repo-relative directories or files (default: the whole "
                         "repository). Prefer the default: a hard-coded list of "
                         "directories is a static reference, and static references "
                         "rot silently — a crate added later would simply not be "
                         "checked, and nothing would say so.")
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="also list ambiguous constant names")
    args = ap.parse_args()
    roots = args.roots or ["."]

    files = rust_sources(roots)
    if not files:
        print(f"FATAL: no Rust sources under {', '.join(roots)}", file=sys.stderr)
        return 2
    bodies: dict[str, list[str]] = {}
    for p in files:
        with open(os.path.join(REPO, p), encoding="utf-8", errors="replace") as fh:
            bodies[p] = fh.read().splitlines()

    table, ambiguous, unresolved = build_const_table(files, bodies)
    stats = {"checked_a": 0, "checked_b": 0, "checked_c": 0,
             "suppressed": 0, "negated": 0}
    findings: list[Finding] = []
    for p in files:
        check_file(p, bodies[p], table, findings, stats)

    total = stats["checked_a"] + stats["checked_b"] + stats["checked_c"]
    print(
        f"\ncheck-comment-constants: {len(files)} files, "
        f"{len(table)} resolvable constants "
        f"({unresolved} non-literal, {len(ambiguous)} ambiguous — both skipped)\n"
        f"  value claims checked: {total} "
        f"(A/attached {stats['checked_a']}, B/named {stats['checked_b']}, "
        f"C/bound {stats['checked_c']})\n"
        f"  {stats['negated']} skipped as hypothetical or historical, "
        f"{stats['suppressed']} comment blocks suppressed\n"
        f"  {len(findings)} contradictions"
    )
    if args.verbose and ambiguous:
        print(f"  ambiguous names (skipped): {', '.join(sorted(ambiguous))}")
    for f in sorted(findings, key=lambda f: (f.path, f.line)):
        print(f.render())
    if findings:
        print(
            "\nA comment that states a constant's value must state the value the\n"
            "constant has. Fix the prose — the constant wins unless the founder says\n"
            "otherwise. If the mention is legitimate, add `prose-guard: allow(reason)`\n"
            "to the comment block; suppressions are counted on every run."
        )
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
