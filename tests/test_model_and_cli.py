import json

import pytest

from noisefloor import library
from noisefloor.cli import _pick, main
from noisefloor.model import Alert, Event, GroundTruth, Scenario
from noisefloor.render import render_evidence
from datetime import datetime, timedelta

ANCHOR = datetime(2026, 9, 15, 2, 0, 0)


def _alert():
    return Alert(rule="R", severity="high", summary="s", technique="T1059",
                 technique_name="n")


def _events(n=3):
    return [Event(timedelta(minutes=i), "auth", "x", {"message": "m%d" % i})
            for i in range(n)]


def test_decisive_index_out_of_range_is_rejected():
    with pytest.raises(ValueError, match="out of range"):
        Scenario(id="x", title="t", alert=_alert(), events=_events(3),
                 truth=GroundTruth(verdict="true-positive", rationale="r", decisive=[7]))


def test_an_event_cannot_be_both_decisive_and_a_distractor():
    with pytest.raises(ValueError, match="both decisive and distractor"):
        Scenario(id="x", title="t", alert=_alert(), events=_events(3),
                 truth=GroundTruth(verdict="true-positive", rationale="r",
                                   decisive=[1], distractors=[1]))


def test_unknown_verdict_is_rejected():
    with pytest.raises(ValueError, match="unknown verdict"):
        GroundTruth(verdict="maybe", rationale="r", decisive=[0])


def test_unknown_severity_is_rejected():
    with pytest.raises(ValueError, match="unknown severity"):
        Alert(rule="R", severity="spicy", summary="s", technique="T1059", technique_name="n")


def test_evidence_indices_are_scenario_indices_not_display_positions():
    """Events are shown in time order, but the numbers an analyst cites must
    mean the same thing regardless of that ordering."""
    scenario = library.get("identity-travel-tp")
    lines = render_evidence(scenario, ANCHOR)
    shown = [int(l.split("]")[0].strip("[ ")) for l in lines]
    assert sorted(shown) == list(range(len(scenario.events)))
    # The historical event is last in the list but not last in display order.
    assert shown != list(range(len(scenario.events)))


def test_a_drill_never_contains_both_halves_of_a_pair():
    for seed in range(40):
        picked = _pick(library.ALL, count=len(library.ALL), seed=seed)
        ids = {s.id for s in picked}
        for s in picked:
            assert s.twin not in ids, (seed, s.id)


def test_pick_is_reproducible_from_a_seed():
    a = [s.id for s in _pick(library.ALL, 3, seed=99)]
    b = [s.id for s in _pick(library.ALL, 3, seed=99)]
    assert a == b


def test_list_and_show_exit_clean(capsys):
    assert main(["list"]) == 0
    assert "identity-travel-tp" in capsys.readouterr().out
    assert main(["show", "cloud-keyuse-fp", "--answer"]) == 0
    out = capsys.readouterr().out
    assert "false-positive" in out and "decisive:" in out


def test_unknown_scenario_is_a_usage_error(capsys):
    assert main(["show", "nope"]) == 2


def test_no_subcommand_prints_help(capsys):
    assert main([]) == 2
