"""Roar preparation CLI. Submission stays disabled pending authenticated discovery."""

import argparse
import json
import os
from pathlib import Path

from denialdojo.roar_artifacts import collect_evidence
from denialdojo.roar_config import STAGES, BudgetReceipt, Deployment, FrozenModelSelection, render_slurm
from denialdojo.run_ledger import RunLedger


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    schema = commands.add_parser("schema")
    schema.add_argument("kind", choices=("deployment", "model", "budget"))
    dry = commands.add_parser("dry-run")
    dry.add_argument("stage", choices=STAGES)
    dry.add_argument("--config", required=True, type=Path)
    dry.add_argument("--remote-config", required=True)
    run = commands.add_parser("run-stage")
    run.add_argument("stage", choices=STAGES)
    run.add_argument("--config", required=True, type=Path)
    status = commands.add_parser("status")
    status.add_argument("root", type=Path)
    status.add_argument("run_id")
    collect = commands.add_parser("collect")
    collect.add_argument("source", type=Path)
    collect.add_argument("destination", type=Path)
    args = parser.parse_args(argv)
    if args.command == "schema":
        model = {"deployment": Deployment, "model": FrozenModelSelection, "budget": BudgetReceipt}[args.kind]
        print(json.dumps(model.model_json_schema(), indent=2))
    elif args.command == "dry-run":
        config = Deployment.model_validate_json(args.config.read_bytes())
        print("# SUBMISSION DISABLED: site runtime, accounting and GPU smoke are not yet confirmed.")
        print(render_slurm(config, args.stage, args.remote_config), end="")
    elif args.command == "status":
        print(json.dumps(RunLedger(args.root).inspect(args.run_id), indent=2))
    elif args.command == "collect":
        print(json.dumps(collect_evidence(args.source, args.destination), indent=2))
    elif args.command == "run-stage":
        config = Deployment.model_validate_json(args.config.read_bytes())
        if not config.site_policy_confirmed or not os.environ.get("SLURM_JOB_ID"):
            raise ValueError("authenticated Roar discovery and an approved Slurm allocation are required")
        # Deliberately no guessed module/container/credit integration. This guard
        # must be replaced only after the actual site discovery and budget review.
        raise ValueError(
            "site-specific stage execution remains disabled pending verified runtime/accounting integration"
        )


if __name__ == "__main__":
    main()
