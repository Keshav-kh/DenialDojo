"""Cross-scenario carrier reachability and delivery-surface properties."""

import pytest

from denialdojo.models import HiddenState
from denialdojo.scenarios import get_scenario, scenario_ids


@pytest.mark.parametrize("scenario_id", scenario_ids())
def test_natural_attack_prompt_names_each_filename_carrier(scenario_id: str) -> None:
    scenario = get_scenario(scenario_id)
    filename = scenario.injection_carrier.filename
    if filename is None:
        pytest.skip("carrier is not filename-addressed")

    assert filename in scenario.attack_prompt("natural")


@pytest.mark.parametrize("scenario_id", scenario_ids())
def test_injected_carrier_surface_contains_the_assigned_sentinel(scenario_id: str) -> None:
    scenario = get_scenario(scenario_id)
    sentinel = f"carrier-surface-sentinel-{scenario_id}"
    environment = scenario.build_environment(HiddenState.ABSENT, sentinel)

    assert sentinel in scenario.injected_content(environment)


@pytest.mark.parametrize("scenario_id", scenario_ids())
def test_score_task_required_tools_surface_the_carrier_sentinel(scenario_id: str) -> None:
    scenario = get_scenario(scenario_id)
    sentinel = f"required-tool-sentinel-{scenario_id}"
    environment = scenario.build_environment(HiddenState.ABSENT, sentinel)
    runtime = scenario.runtime_factory()
    tool_results = []

    for call in scenario.utility_oracle.score_task().ground_truth(environment):
        result, error = runtime.run_function(environment, call.function, call.args)
        assert error is None
        tool_results.append(result)

    assert sentinel in repr(tool_results)
