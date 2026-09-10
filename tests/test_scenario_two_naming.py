"""Regression guard for scenario two's persisted identifier."""

from denialdojo.scenarios import scenario_ids


def test_scenario_two_uses_its_vacation_identifier() -> None:
    """Immutable run metadata must name the actual vacation-plan scenario."""

    assert "workspace_vacation_document_file_probe" in scenario_ids()
    assert "workspace_recipe_document_file_probe" not in scenario_ids()
