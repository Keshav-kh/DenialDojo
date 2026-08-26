"""Run the scripted genuine-Workspace Checkpoint 1B evidence matrix."""

import json

from denialdojo.models import DefenseMode, FeedbackMode, HiddenState
from denialdojo.workspace_experiment import run_workspace_attack, run_workspace_benign_control


def main() -> None:
    records = []
    for delay in (0, 2):
        for state in HiddenState:
            records.append(run_workspace_attack(state, delay=delay).record)
            records.append(
                run_workspace_attack(state, delay=delay, feedback_mode=FeedbackMode.UNIFORM).record
            )
            records.append(run_workspace_benign_control(state, delay=delay).record)
        records.append(
            run_workspace_benign_control(
                HiddenState.ABSENT,
                delay=delay,
                defense_mode=DefenseMode.IMMEDIATE_ADJACENCY,
            ).record
        )
    print(json.dumps([record.model_dump(mode="json") for record in records], indent=2))


if __name__ == "__main__":
    main()
