"""The library is content, so the tests are mostly consistency checks. Content
errors in security training material teach the wrong lesson confidently, which
is worse than no material."""
import base64
import re

import pytest

from noisefloor import library
from noisefloor.model import FALSE_POSITIVE, SEVERITIES, TRUE_POSITIVE


def test_library_is_not_empty():
    assert len(library.ALL) >= 6


def test_ids_are_unique():
    ids = [s.id for s in library.ALL]
    assert len(ids) == len(set(ids))


@pytest.mark.parametrize("scenario", library.ALL, ids=lambda s: s.id)
def test_twins_agree_and_disagree(scenario):
    """Each pair must point at each other and reach opposite verdicts."""
    twin = library.get(scenario.twin)
    assert twin is not None, scenario.id
    assert twin.twin == scenario.id
    assert twin.truth.verdict != scenario.truth.verdict


@pytest.mark.parametrize("scenario", library.ALL, ids=lambda s: s.id)
def test_every_scenario_has_decisive_evidence(scenario):
    """A scenario with nothing decisive cannot be graded on reasoning, which is
    the only thing this tool grades."""
    assert scenario.truth.decisive, scenario.id
    assert scenario.truth.rationale.strip()
    assert scenario.alert.severity in SEVERITIES
    assert re.fullmatch(r"T\d{4}(\.\d{3})?", scenario.alert.technique), scenario.alert.technique


@pytest.mark.parametrize("scenario", library.ALL, ids=lambda s: s.id)
def test_false_positives_carry_a_common_error(scenario):
    """The value of a false-positive scenario is naming the trap."""
    if scenario.truth.verdict == FALSE_POSITIVE:
        assert scenario.truth.common_error.strip(), scenario.id


def test_both_verdicts_are_represented():
    verdicts = {s.truth.verdict for s in library.ALL}
    assert verdicts == {TRUE_POSITIVE, FALSE_POSITIVE}


def test_encoded_powershell_base64_really_decodes():
    """The payloads are real, so an analyst can decode them the way they would
    at work. A fake blob would teach the motion without the habit."""
    for sid, expected in (("execution-encodedps-tp", "DownloadString"),
                          ("execution-encodedps-fp", "Win32_QuickFixEngineering")):
        scenario = library.get(sid)
        blobs = [e.fields["command_line"].split("-enc ")[1]
                 for e in scenario.events
                 if "command_line" in e.fields and "-enc " in e.fields["command_line"]]
        assert blobs, sid
        decoded = base64.b64decode(blobs[0]).decode("utf-16-le")
        assert expected in decoded, decoded
