import pytest

from noisefloor import grade as G
from noisefloor import library
from noisefloor.model import FALSE_POSITIVE, TRUE_POSITIVE, Response

SCENARIO = library.get("identity-travel-fp")          # decisive [2,3,5,6], distractor [4]


def _grade(verdict, cited):
    return G.grade(SCENARIO, Response(verdict=verdict, cited=cited))


def test_sound_reasoning():
    g = _grade(FALSE_POSITIVE, [2, 3, 5, 6])
    assert g.diagnosis == G.SOUND and g.passed and g.recall == 1.0


def test_right_verdict_wrong_reasoning_does_not_pass():
    """The case this whole tool exists for: a correct call that would not
    survive the next, slightly different, alert."""
    g = _grade(FALSE_POSITIVE, [0])
    assert g.verdict_correct
    assert g.diagnosis == G.RIGHT_BY_ACCIDENT
    assert not g.passed


def test_right_verdict_via_a_distractor_is_flagged():
    g = _grade(FALSE_POSITIVE, [2, 3, 4])
    assert g.diagnosis == G.RIGHT_VIA_DISTRACTOR
    assert g.distractors_cited == [4]


def test_wrong_verdict_from_the_right_evidence():
    g = _grade(TRUE_POSITIVE, [2, 3, 5, 6])
    assert g.diagnosis == G.WRONG_DESPITE_EVIDENCE
    assert not g.passed


def test_wrong_and_blind():
    g = _grade(TRUE_POSITIVE, [0, 1])
    assert g.diagnosis == G.WRONG_AND_BLIND


def test_no_citations_is_never_a_pass():
    assert not _grade(FALSE_POSITIVE, []).passed


def test_out_of_range_citations_are_ignored_not_crashed():
    g = _grade(FALSE_POSITIVE, [2, 3, 5, 6, 999, -1])
    assert g.diagnosis == G.SOUND


def test_unrelated_citations_are_reported_separately():
    g = _grade(FALSE_POSITIVE, [2, 3, 5, 6, 0])
    assert g.unrelated_cited == [0]
    assert g.diagnosis == G.SOUND        # citing extra is untidy, not wrong


def test_summary_names_the_gap():
    grades = [_grade(FALSE_POSITIVE, [0]), _grade(FALSE_POSITIVE, [2, 3, 5, 6])]
    text = G.summarise(grades)
    assert "Verdict correct   2/2" in text
    assert "Reasoning held up 1/2" in text
    assert "wrong reason" in text
