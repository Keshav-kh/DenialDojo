"""Scenario registry populated automatically from scenario modules in this package."""

from importlib import import_module
from pkgutil import iter_modules

from denialdojo.scenarios.base import Scenario, get_scenario, scenario_ids
from denialdojo.scenarios.workspace_document_file_probe import WORKSPACE_DOCUMENT_FILE_PROBE

for module in iter_modules(__path__):
    if module.name != "base":
        import_module(f"{__name__}.{module.name}")

__all__ = ["WORKSPACE_DOCUMENT_FILE_PROBE", "Scenario", "get_scenario", "scenario_ids"]
