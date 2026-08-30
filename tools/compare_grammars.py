#!/usr/bin/env python3
"""Differentially compare two EXI grammar derivations.

Reads two dumps in the canonical flat-graph format that `iso15118-codegen
--dump` emits and compares them state by state and production by production.

The two implementations number their states differently, so the comparison is a
*lockstep walk*: the grammars of each global element are paired, and from every
paired pair of states the productions are matched by event code. Two grammars
agree when every reachable pair has the same productions in the same order.
This detects any real disagreement while ignoring how the states happen to be
numbered or grouped.

    usage: compare_grammars.py <reference.txt> <ours.txt>

Exits non-zero and prints the first difference per element if they disagree.
"""

from __future__ import annotations

import re
import sys
from collections import deque


def parse(path: str) -> tuple[dict[str, str], dict[str, list[tuple]]]:
    """Returns (element name -> start node, node -> list of productions).

    A production is a tuple whose first item is the event kind, so productions
    compare equal exactly when they mean the same thing.
    """
    elements: dict[str, str] = {}
    nodes: dict[str, list[tuple]] = {}
    current: str | None = None

    with open(path, encoding="utf-8") as handle:
        for line in handle:
            line = line.rstrip("\n")
            if not line.strip():
                continue
            if line.startswith("#element "):
                _, name, node = line.split()
                elements[name] = node
                continue
            if line.startswith("G"):
                current = line.split()[0]
                nodes[current] = []
                continue
            if current is None:
                continue
            parts = line.split()
            kind = parts[1]
            if kind == "SE":
                # code SE {ns}name body=Gx -> Gy
                name = parts[2]
                body = parts[3].removeprefix("body=")
                nxt = parts[5]
                nodes[current].append(("SE", name, body, nxt))
            elif kind == "AT":
                nodes[current].append(("AT", parts[2], parts[4]))
            elif kind == "CH":
                nodes[current].append(("CH", parts[3]))
            elif kind == "SEGEN":
                nodes[current].append(("SEGEN", parts[3]))
            elif kind == "EE":
                nodes[current].append(("EE",))
            else:
                nodes[current].append((kind,))
    return elements, nodes


def compare_element(
    name: str,
    a_start: str,
    a_nodes: dict[str, list[tuple]],
    b_start: str,
    b_nodes: dict[str, list[tuple]],
) -> list[str]:
    """Lockstep-walks one element's grammar in both dumps."""
    problems: list[str] = []
    seen: set[tuple[str, str]] = set()
    queue: deque[tuple[str, str, str]] = deque([(a_start, b_start, name)])

    while queue:
        a_node, b_node, path = queue.popleft()
        if (a_node, b_node) in seen:
            continue
        seen.add((a_node, b_node))

        a_prods = a_nodes.get(a_node, [])
        b_prods = b_nodes.get(b_node, [])

        if len(a_prods) != len(b_prods):
            problems.append(
                f"{path}: production count {len(a_prods)} vs {len(b_prods)}\n"
                f"    reference: {a_prods}\n"
                f"    ours:      {b_prods}"
            )
            continue

        for code, (a_p, b_p) in enumerate(zip(a_prods, b_prods)):
            if a_p[0] != b_p[0]:
                problems.append(f"{path} code {code}: event {a_p[0]} vs {b_p[0]}")
                continue
            if a_p[0] in ("SE", "AT") and a_p[1] != b_p[1]:
                problems.append(f"{path} code {code}: name {a_p[1]} vs {b_p[1]}")
                continue
            if a_p[0] == "SE":
                queue.append((a_p[2], b_p[2], f"{path}/{a_p[1].split('}')[-1]}"))
                queue.append((a_p[3], b_p[3], path))
            elif a_p[0] in ("AT", "CH", "SEGEN"):
                queue.append((a_p[-1], b_p[-1], path))
        if problems and len(problems) > 3:
            break
    return problems


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 2

    ref_elements, ref_nodes = parse(sys.argv[1])
    our_elements, our_nodes = parse(sys.argv[2])

    only_ref = sorted(set(ref_elements) - set(our_elements))
    only_ours = sorted(set(our_elements) - set(ref_elements))
    if only_ref or only_ours:
        print(f"element sets differ:")
        for name in only_ref[:10]:
            print(f"  only in reference: {name}")
        for name in only_ours[:10]:
            print(f"  only in ours:      {name}")
        return 1

    failed = 0
    for name in sorted(ref_elements):
        problems = compare_element(
            name, ref_elements[name], ref_nodes, our_elements[name], our_nodes
        )
        if problems:
            failed += 1
            print(f"MISMATCH {name}")
            for problem in problems[:4]:
                print(f"  {problem}")

    total = len(ref_elements)
    if failed:
        print(f"\n{failed} of {total} element grammars disagree")
        return 1
    print(f"all {total} element grammars agree with the reference")
    return 0


if __name__ == "__main__":
    sys.exit(main())
