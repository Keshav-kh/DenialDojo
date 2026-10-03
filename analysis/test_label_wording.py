"""The Checkpoint 10 preregistered analysis, on synthetic per-label counts."""

from __future__ import annotations

import pytest

from analysis.label_wording import AD, NP, PF, RF, RU, analyse, holm, paired_shares, sign_test
from denialdojo.checkpoint10 import LabelArm


def _arm(label: str, pd: int, nf: int, invalid: int = 0, no_send: int = 0) -> LabelArm:
    records = pd + nf + invalid + no_send
    return LabelArm(
        label=label, records=records, provider_filtered=0, runtime_errors=0, denial_observed=records,
        delivered=records, pd_code=pd, nf_code=nf, invalid=invalid, no_send=no_send, paired=0, paired_eligible=0,
    )


def _models(
    count: int, ad: tuple, np_: tuple, ru: tuple, rf: tuple, pf: tuple = (40, 0)
) -> dict[str, dict[str, LabelArm]]:
    return {
        f"model-{index}": {
            AD: _arm(AD, *ad), NP: _arm(NP, *np_), RU: _arm(RU, *ru), RF: _arm(RF, *rf), PF: _arm(PF, *pf),
        }
        for index in range(count)
    }


def test_sign_test_over_six_unanimous_models_is_one_in_sixty_four() -> None:
    result = sign_test([(1.0, 0.1)] * 6)
    assert (result.favourable, result.compared, result.ties) == (6, 6, 0)
    assert result.p_value == pytest.approx(1 / 64)
    assert result.rejected


def test_sign_test_drops_ties_and_five_of_five_still_rejects() -> None:
    result = sign_test([(1.0, 0.2)] * 5 + [(1.0, 1.0)])
    assert (result.favourable, result.compared, result.ties) == (5, 5, 1)
    assert result.p_value == pytest.approx(1 / 32)
    assert result.rejected


def test_four_of_four_does_not_reject() -> None:
    assert not sign_test([(1.0, 0.0)] * 4).rejected


def test_all_ties_compare_nothing_and_never_reject() -> None:
    result = sign_test([(1.0, 1.0)] * 6)
    assert result.compared == 0 and result.p_value == 1.0 and not result.rejected


def test_holm_adjustment() -> None:
    assert holm([0.01, 0.04, 0.03]) == pytest.approx([0.03, 0.06, 0.06])


def test_a_non_interpretable_arm_removes_its_model_from_the_comparison() -> None:
    models = _models(2, (40, 0), (40, 0), (5, 3, 0, 32), (20, 20))
    models["model-0"][RU] = _arm(RU, 0, 40)
    pairs = paired_shares(models, {"model-0": 40, "model-1": 40}, AD, RU)
    assert pairs == [(1.0, 0.0)]


def test_a_label_flip_rejects_h10_2_and_then_tests_h10_3() -> None:
    models = _models(6, (40, 0), (39, 1), (2, 38), (20, 20))
    lines = "\n".join(analyse(models, dict.fromkeys(models, 40)))
    assert "H10.2 (primary) RESOURCE_UNAVAILABLE below ACCESS_DENIED in 6 of 6" in lines
    assert "REJECT H0" in lines.split("H10.2")[1].split("\n")[0]
    assert "H10.3 (fixed sequence) NOT_PERMITTED above RESOURCE_UNAVAILABLE in 6 of 6" in lines
    assert "H10.1 (descriptive) ACCESS_DENIED pooled PD-code share 240/240" in lines


def test_no_shift_leaves_h10_3_untested() -> None:
    models = _models(6, (40, 0), (40, 0), (40, 0), (40, 0))
    lines = "\n".join(analyse(models, dict.fromkeys(models, 40)))
    assert "0 of 0 models (6 tied, dropped)" in lines
    assert "H10.3 (fixed sequence) not tested" in lines


def test_a_position_effect_rejects_h10_4_independently_of_h10_2() -> None:
    models = _models(6, (40, 0), (40, 0), (40, 0), (40, 0), pf=(3, 37))
    lines = "\n".join(analyse(models, dict.fromkeys(models, 40)))
    assert "H10.3 (fixed sequence) not tested" in lines
    assert "H10.4 (separate question) PERMISSION_DENIED-first below NOT_FOUND-first in 6 of 6" in lines
    assert "REJECT H0: codebook position contributes" in lines
    assert "reordered arm pooled PD-code share 18/240" in lines


def test_no_position_effect_leaves_h10_4_unrejected() -> None:
    models = _models(6, (40, 0), (40, 0), (2, 38), (20, 20))
    lines = "\n".join(analyse(models, dict.fromkeys(models, 40)))
    assert "H10.4 (separate question) PERMISSION_DENIED-first below NOT_FOUND-first in 0 of 0 models" in lines
    assert "expected >= 0.90: met" in lines
