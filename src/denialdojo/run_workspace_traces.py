"""Write replayable scripted Workspace pilot-infrastructure traces."""

import argparse
from pathlib import Path

from denialdojo.models import HiddenState
from denialdojo.provenance import repository_state
from denialdojo.trace import ModelRuntimeMetadata, TerminalStatus, build_workspace_trace, write_trace_jsonl
from denialdojo.workspace_experiment import run_workspace_attack, run_workspace_benign_control


def _workspace_sink_messages(execution):
    sent_count = len(execution.record.sent_bodies)
    return execution.environment.inbox.sent[-sent_count:] if sent_count else []


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("runs/pilot/scripted/traces.jsonl"))
    args = parser.parse_args()
    commit, dirty, source_tree_hash = repository_state()
    runtime = ModelRuntimeMetadata(
        provider="scripted",
        runtime_version="agentdojo-0.1.35",
        model_tag="workspace-scripted-control",
        model_digest=None,
        quantization=None,
        context_window=None,
        temperature=0,
        maximum_steps=12,
        timeout_seconds=30,
        retry_count=0,
        seed=0,
    )
    traces = []
    for delay in (0, 2):
        for state in HiddenState:
            for benign in (False, True):
                execution = (
                    run_workspace_benign_control(state, delay=delay)
                    if benign
                    else run_workspace_attack(state, delay=delay)
                )
                control = "benign" if benign else "attack"
                traces.append(
                    build_workspace_trace(
                        execution,
                        sink_tool_name="send_email",
                        sink_messages=_workspace_sink_messages(execution),
                        run_id=f"scripted-{control}-{state.value}-d{delay}",
                        paired_run_group_id=f"scripted-{control}-d{delay}",
                        repetition=0,
                        runtime=runtime,
                        repository_commit=commit,
                        repository_dirty=dirty,
                        source_tree_hash=source_tree_hash,
                        elapsed_seconds=0,
                        terminal_status=TerminalStatus.COMPLETE,
                    )
                )
    write_trace_jsonl(args.output, traces)
    print(f"wrote {len(traces)} pilot-infrastructure records to {args.output}")


if __name__ == "__main__":
    main()
