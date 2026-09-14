"""Command line interface."""
from __future__ import annotations

import argparse
import os
import random
import sys
from datetime import datetime, timedelta
from typing import List, Optional, Sequence

from . import library
from .grade import Grade, grade, summarise
from .model import FALSE_POSITIVE, TRUE_POSITIVE, Response, Scenario
from .render import SOURCE_HELP, render_alert, render_evidence

_BOLD, _DIM, _RESET = "\033[1m", "\033[2m", "\033[0m"
_RED, _GREEN, _YELLOW = "\033[31m", "\033[32m", "\033[33m"


def _colour(stream) -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    return hasattr(stream, "isatty") and stream.isatty()


class Style:
    def __init__(self, on: bool) -> None:
        self.on = on

    def __call__(self, text: str, code: str) -> str:
        return "{}{}{}".format(code, text, _RESET) if self.on else text


def _anchor(seed: int) -> datetime:
    rng = random.Random(seed)
    base = datetime(2026, 9, 15, 2, 0, 0)
    return base + timedelta(minutes=rng.randrange(0, 60 * 18))


def _pick(scenarios: Sequence[Scenario], count: int, seed: int) -> List[Scenario]:
    """Choose scenarios without ever taking both halves of a pair.

    Seeing a scenario and then its twin turns the exercise into spot-the-diff,
    which is a different and much easier task than triage.
    """
    rng = random.Random(seed)
    pool = list(scenarios)
    rng.shuffle(pool)
    chosen: List[Scenario] = []
    used_pairs = set()
    for s in pool:
        key = tuple(sorted([s.id, s.twin or s.id]))
        if key in used_pairs:
            continue
        used_pairs.add(key)
        chosen.append(s)
        if len(chosen) >= count:
            break
    return chosen


def _ask_verdict(st: Style) -> Optional[str]:
    while True:
        try:
            raw = input(st("  verdict [t]rue-positive / [f]alse-positive / [q]uit: ",
                           _BOLD)).strip().lower()
        except EOFError:
            return None
        if raw in ("t", "tp", "true", "true-positive"):
            return TRUE_POSITIVE
        if raw in ("f", "fp", "false", "false-positive"):
            return FALSE_POSITIVE
        if raw in ("q", "quit", "exit"):
            return None
        print(st("  answer t, f or q", _DIM))


def _ask_evidence(st: Style, n: int) -> List[int]:
    print(st("\n  Which events settle it? Numbers only, comma separated.", _BOLD))
    print(st("  Cite what you actually relied on, not everything that looked odd.", _DIM))
    while True:
        try:
            raw = input("  evidence: ").strip()
        except EOFError:
            return []
        if not raw:
            return []
        try:
            idx = [int(p) for p in raw.replace(" ", "").split(",") if p != ""]
        except ValueError:
            print(st("  numbers only, e.g. 2,3,5", _DIM))
            continue
        bad = [i for i in idx if not 0 <= i < n]
        if bad:
            print(st("  no such event: {}".format(bad), _DIM))
            continue
        return idx


def _report(st: Style, scenario: Scenario, g: Grade) -> None:
    ok = g.diagnosis in ("sound", "right-via-distractor")
    colour = _GREEN if ok else (_YELLOW if g.verdict_correct else _RED)
    print()
    print(st("  " + g.headline, colour + _BOLD))
    print()
    print("  actual verdict   {}".format(scenario.truth.verdict))
    if g.decisive_found:
        print("  you cited        {} of the {} decisive events".format(
            len(g.decisive_found), len(g.decisive_found) + len(g.decisive_missed)))
    if g.decisive_missed:
        print(st("  you missed       {}".format(
            ", ".join(str(i) for i in g.decisive_missed)), _YELLOW))
    if g.distractors_cited:
        print(st("  misled by        {}".format(
            ", ".join(str(i) for i in g.distractors_cited)), _YELLOW))
    print()
    print(st("  Why:", _BOLD))
    for line in _wrap(scenario.truth.rationale, 92, "    "):
        print(line)
    if scenario.truth.common_error and not ok:
        print()
        print(st("  The mistake this one is built to provoke:", _BOLD))
        for line in _wrap(scenario.truth.common_error, 92, "    "):
            print(line)
    if scenario.truth.next_action:
        print()
        print(st("  Next action:", _BOLD))
        for line in _wrap(scenario.truth.next_action, 92, "    "):
            print(line)


def _wrap(text: str, width: int, indent: str) -> List[str]:
    words, lines, cur = text.split(), [], ""
    for w in words:
        cand = w if not cur else cur + " " + w
        if len(cand) + len(indent) > width:
            lines.append(indent + cur)
            cur = w
        else:
            cur = cand
    if cur:
        lines.append(indent + cur)
    return lines


def cmd_drill(args: argparse.Namespace) -> int:
    st = Style(_colour(sys.stdout))
    pool = library.tagged(args.tag) if args.tag else library.ALL
    if not pool:
        print("no scenarios tagged {}".format(args.tag), file=sys.stderr)
        return 2
    seed = args.seed if args.seed is not None else random.randrange(1 << 30)
    scenarios = _pick(pool, args.count, seed)
    anchor = _anchor(seed)

    print(st("\nnoisefloor — triage drill", _BOLD))
    print(st("seed {} · {} scenario(s) · reproduce with --seed {}".format(
        seed, len(scenarios), seed), _DIM))
    print(st("You are grading your own reasoning, not just your verdict.", _DIM))

    grades: List[Grade] = []
    for n, scenario in enumerate(scenarios, start=1):
        print()
        print(st("─" * 92, _DIM))
        print(st("  ALERT {} of {}".format(n, len(scenarios)), _BOLD))
        print()
        print(render_alert(scenario, anchor))
        print()
        print(st("  EVIDENCE", _BOLD))
        sources = sorted({e.source for e in scenario.events})
        print(st("  sources: {}".format(", ".join(
            "{} ({})".format(s, SOURCE_HELP.get(s, "")) for s in sources)), _DIM))
        print()
        for line in render_evidence(scenario, anchor):
            print("  " + line)
        print()
        verdict = _ask_verdict(st)
        if verdict is None:
            print(st("\n  stopped\n", _DIM))
            break
        cited = _ask_evidence(st, len(scenario.events))
        g = grade(scenario, Response(verdict=verdict, cited=cited))
        grades.append(g)
        _report(st, scenario, g)

    print()
    print(st("─" * 92, _DIM))
    print(summarise(grades))
    print()
    return 0 if all(g.passed for g in grades) else 1


def cmd_list(args: argparse.Namespace) -> int:
    width = max(len(s.id) for s in library.ALL)
    for s in library.ALL:
        line = "{}  {}".format(s.id.ljust(width), s.title)
        if args.verbose:
            line += "\n{}  {} · {}".format(" " * width, s.truth.verdict, ", ".join(s.tags))
        print(line)
    return 0


def cmd_show(args: argparse.Namespace) -> int:
    scenario = library.get(args.scenario_id)
    if scenario is None:
        print("no such scenario: {}".format(args.scenario_id), file=sys.stderr)
        return 2
    anchor = _anchor(args.seed if args.seed is not None else 1)
    st = Style(_colour(sys.stdout))
    print()
    print(render_alert(scenario, anchor))
    print()
    for line in render_evidence(scenario, anchor):
        print("  " + line)
    if args.answer:
        print()
        print(st("  verdict: {}".format(scenario.truth.verdict), _BOLD))
        print("  decisive: {}".format(", ".join(str(i) for i in scenario.truth.decisive)))
        if scenario.truth.distractors:
            print("  distractors: {}".format(
                ", ".join(str(i) for i in scenario.truth.distractors)))
        print()
        for line in _wrap(scenario.truth.rationale, 92, "  "):
            print(line)
    print()
    return 0


def build_parser() -> argparse.ArgumentParser:
    from . import __version__

    p = argparse.ArgumentParser(
        prog="noisefloor",
        description="A SOC triage drill that grades your reasoning, not just your verdict.")
    p.add_argument("--version", action="version", version="noisefloor " + __version__)
    sub = p.add_subparsers(dest="command")

    d = sub.add_parser("drill", help="work through scenarios interactively")
    d.add_argument("-n", "--count", type=int, default=3, help="how many (default: 3)")
    d.add_argument("--tag", help="restrict to one tag, e.g. cloud, host, identity")
    d.add_argument("--seed", type=int, help="reproduce an exact drill")

    l = sub.add_parser("list", help="list the scenario library")
    l.add_argument("-v", "--verbose", action="store_true")

    s = sub.add_parser("show", help="print one scenario without grading")
    s.add_argument("scenario_id")
    s.add_argument("--answer", action="store_true", help="include the ground truth")
    s.add_argument("--seed", type=int)
    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command is None:
        build_parser().print_help()
        return 2
    return {"drill": cmd_drill, "list": cmd_list, "show": cmd_show}[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
