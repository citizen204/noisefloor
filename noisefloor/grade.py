"""Grading.

The verdict is one bit and it is not the interesting one.  Half the analysts
who call a scenario correctly do it from something that happens to correlate,
and they will call the next one wrong.  So grading compares the evidence an
analyst cited against the evidence that actually settles the question, and says
which of five things happened.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Sequence, Set

from .model import Response, Scenario

# Diagnoses, worst to best.
WRONG_AND_BLIND = "wrong-and-blind"
WRONG_DESPITE_EVIDENCE = "wrong-despite-evidence"
RIGHT_BY_ACCIDENT = "right-by-accident"
RIGHT_VIA_DISTRACTOR = "right-via-distractor"
SOUND = "sound"

_HEADLINE = {
    WRONG_AND_BLIND: "Wrong verdict, and the evidence that settles it was not cited.",
    WRONG_DESPITE_EVIDENCE: "Wrong verdict, from the right evidence read backwards.",
    RIGHT_BY_ACCIDENT: "Right verdict, but not from the evidence that settles it.",
    RIGHT_VIA_DISTRACTOR: "Right verdict, reached partly through evidence that misleads.",
    SOUND: "Right verdict, from the evidence that settles it.",
}


@dataclass
class Grade:
    scenario_id: str
    verdict_correct: bool
    diagnosis: str
    decisive_found: List[int] = field(default_factory=list)
    decisive_missed: List[int] = field(default_factory=list)
    distractors_cited: List[int] = field(default_factory=list)
    unrelated_cited: List[int] = field(default_factory=list)

    @property
    def headline(self) -> str:
        return _HEADLINE[self.diagnosis]

    @property
    def recall(self) -> float:
        total = len(self.decisive_found) + len(self.decisive_missed)
        return len(self.decisive_found) / total if total else 1.0

    @property
    def passed(self) -> bool:
        """A pass means the verdict *and* the reasoning held up.

        Deliberately strict: this tool exists because a correct verdict from
        the wrong evidence is not a pass in a real SOC either.
        """
        return self.diagnosis in (SOUND, RIGHT_VIA_DISTRACTOR) and self.recall >= 0.5


def _diagnose(correct: bool, recall: float, distractors: Sequence[int]) -> str:
    if not correct:
        return WRONG_DESPITE_EVIDENCE if recall >= 0.5 else WRONG_AND_BLIND
    if recall < 0.5:
        return RIGHT_BY_ACCIDENT
    if distractors:
        return RIGHT_VIA_DISTRACTOR
    return SOUND


def grade(scenario: Scenario, response: Response) -> Grade:
    cited: Set[int] = {i for i in response.cited if 0 <= i < len(scenario.events)}
    decisive: Set[int] = set(scenario.truth.decisive)
    distractors: Set[int] = set(scenario.truth.distractors)

    found = sorted(cited & decisive)
    missed = sorted(decisive - cited)
    fooled = sorted(cited & distractors)
    unrelated = sorted(cited - decisive - distractors)

    correct = response.verdict == scenario.truth.verdict
    recall = len(found) / len(decisive) if decisive else 1.0

    return Grade(
        scenario_id=scenario.id,
        verdict_correct=correct,
        diagnosis=_diagnose(correct, recall, fooled),
        decisive_found=found,
        decisive_missed=missed,
        distractors_cited=fooled,
        unrelated_cited=unrelated,
    )


def summarise(grades: Sequence[Grade]) -> str:
    if not grades:
        return "No scenarios attempted."
    n = len(grades)
    verdicts = sum(1 for g in grades if g.verdict_correct)
    passes = sum(1 for g in grades if g.passed)
    accidents = sum(1 for g in grades if g.diagnosis == RIGHT_BY_ACCIDENT)
    lines = [
        "Verdict correct   {}/{}".format(verdicts, n),
        "Reasoning held up {}/{}".format(passes, n),
    ]
    if accidents:
        lines.append(
            "Right for the wrong reason on {} of {} — the gap between those first two "
            "numbers is the thing to work on.".format(accidents, n))
    return "\n".join(lines)
