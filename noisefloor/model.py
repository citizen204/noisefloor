"""The data model.

A scenario is an alert, the events an analyst can see around it, and a ground
truth that says which of those events actually settle the question.

The last part is the point of this tool.  Most training material grades the
verdict: real or not real.  Real triage is not scored that way -- an analyst
who calls it correctly for the wrong reason will call the next one wrong, and
the one after that.  So a scenario records *which* events are decisive, and
which merely look damning, and grading checks both.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Sequence

TRUE_POSITIVE = "true-positive"
FALSE_POSITIVE = "false-positive"
VERDICTS = (TRUE_POSITIVE, FALSE_POSITIVE)

#: Severity as a SOC queue would show it.
SEVERITIES = ("informational", "low", "medium", "high", "critical")


@dataclass(frozen=True)
class Event:
    """One line of telemetry, as it would arrive from a log source."""

    offset: timedelta          # relative to the scenario's anchor time
    source: str                # okta | sysmon | zeek | cloudtrail | auth | edr
    action: str                # short verb, e.g. "user.session.start"
    fields: Dict[str, Any] = field(default_factory=dict)

    def at(self, anchor: datetime) -> datetime:
        return anchor + self.offset


@dataclass(frozen=True)
class Alert:
    """What lands in the queue.  Deliberately thin: an alert is a claim, not
    evidence, and an analyst who triages from the alert text alone is the
    failure mode this tool is built to train out."""

    rule: str
    severity: str
    summary: str
    technique: str             # MITRE ATT&CK id, e.g. "T1078.004"
    technique_name: str

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError("unknown severity: {}".format(self.severity))


@dataclass(frozen=True)
class GroundTruth:
    verdict: str
    #: Why, in the words an analyst should be able to write in the ticket.
    rationale: str
    #: Indices into Scenario.events that actually settle the question. An
    #: analyst who reaches the right verdict without these got lucky.
    decisive: Sequence[int]
    #: Events that point the other way and have an innocent explanation, or a
    #: guilty-looking one that does not hold up. Naming these is most of the
    #: skill.
    distractors: Sequence[int] = ()
    #: The mistake this scenario exists to provoke.
    common_error: str = ""
    #: What the analyst should do next, if anything.
    next_action: str = ""

    def __post_init__(self) -> None:
        if self.verdict not in VERDICTS:
            raise ValueError("unknown verdict: {}".format(self.verdict))


@dataclass(frozen=True)
class Scenario:
    id: str
    title: str
    alert: Alert
    events: List[Event]
    truth: GroundTruth
    #: Scenarios come in pairs: same alert, opposite verdict. The id of the
    #: twin, so a session can avoid showing both back to back.
    twin: Optional[str] = None
    tags: Sequence[str] = ()

    def __post_init__(self) -> None:
        n = len(self.events)
        for label, idxs in (("decisive", self.truth.decisive),
                            ("distractors", self.truth.distractors)):
            for i in idxs:
                if not 0 <= i < n:
                    raise ValueError(
                        "{} index {} out of range in scenario {}".format(label, i, self.id))
        overlap = set(self.truth.decisive) & set(self.truth.distractors)
        if overlap:
            raise ValueError(
                "scenario {}: event(s) {} are both decisive and distractor".format(
                    self.id, sorted(overlap)))

    def ordered(self) -> List[int]:
        """Event indices in timestamp order."""
        return sorted(range(len(self.events)), key=lambda i: self.events[i].offset)


@dataclass
class Response:
    """What the analyst submitted."""

    verdict: str
    cited: Sequence[int] = ()
    note: str = ""
