"""The scenario library.

Scenarios are paired: each has a twin that fires the same rule with the
opposite verdict.  A session never shows both halves of a pair back to back,
because recognising the format is not the skill being trained.
"""
from __future__ import annotations

from typing import Dict, List, Optional

from ..model import Scenario
from . import cloud, execution, identity

_MODULES = (identity, execution, cloud)

ALL: List[Scenario] = [s for m in _MODULES for s in m.SCENARIOS]
BY_ID: Dict[str, Scenario] = {s.id: s for s in ALL}


def _validate() -> None:
    for s in ALL:
        if s.twin is None:
            continue
        twin = BY_ID.get(s.twin)
        if twin is None:
            raise ValueError("{} names a twin {} that does not exist".format(s.id, s.twin))
        if twin.twin != s.id:
            raise ValueError("{} and {} do not agree that they are twins".format(s.id, s.twin))
        if twin.truth.verdict == s.truth.verdict:
            raise ValueError(
                "{} and its twin {} share a verdict; a pair exists to contrast".format(
                    s.id, s.twin))


_validate()


def get(scenario_id: str) -> Optional[Scenario]:
    return BY_ID.get(scenario_id)


def tagged(tag: str) -> List[Scenario]:
    return [s for s in ALL if tag in s.tags]
