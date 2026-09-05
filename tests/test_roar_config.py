import time

import pytest

from denialdojo.roar_config import BudgetReceipt, Deployment, render_slurm


def deployment(**updates):
    values = dict(
        account="fixture-account",
        partition="fixture-partition",
        gpu_resource="gpu:fixture:1",
        walltime="00:05:00",
        cpus=4,
        memory_gb=16,
        source_dir="/storage/work/user/denialdojo",
        scratch_root="/scratch/user/denialdojo",
        run_label="smoke-01",
        artifact_dir="/storage/work/user/denialdojo/runs/roar/smoke-01",
        python_executable="/storage/work/user/denialdojo/.venv/bin/python",
        model_config="/storage/work/user/denialdojo/runs/roar/model.json",
        mail_confirmed=False,
    )
    return Deployment(**{**values, **updates})


def test_slurm_dry_run_has_explicit_single_gpu_and_no_submission():
    script = render_slurm(deployment(), "smoke", "/storage/work/user/config.json")
    assert "#SBATCH --gres=gpu:fixture:1" in script
    assert "#SBATCH --account=fixture-account" in script
    assert "#SBATCH --partition=fixture-partition" in script
    assert "#SBATCH --no-requeue" in script
    assert "--mail-type" not in script
    assert "run-stage" in script and "smoke" in script
    assert "sbatch " not in script


@pytest.mark.parametrize(
    "changes",
    [
        {"gpu_resource": "gpu:2"},
        {"partition": "x\n#SBATCH --gres=gpu:8"},
        {"run_label": "../escape"},
        {"scratch_root": "/scratch"},
        {"walltime": "999:99:99"},
        {"artifact_dir": "/scratch/user/run"},
    ],
)
def test_deployment_rejects_ambiguous_or_unsafe_targets(changes):
    with pytest.raises(ValueError):
        deployment(**changes)


def test_budget_receipt_is_fresh_bound_and_cumulative():
    receipt = BudgetReceipt(
        available_credits="2.9995",
        previously_reserved="0.2",
        job_estimate="0.1",
        confirmed_at=time.time(),
        script_sha256="a" * 64,
        evidence_sha256="b" * 64,
        charging_confirmed=True,
    )
    receipt.authorize("a" * 64)
    with pytest.raises(ValueError):
        receipt.authorize("c" * 64)
    with pytest.raises(ValueError):
        receipt.authorize("a" * 64, now=time.time() + 3600)
    with pytest.raises(ValueError):
        receipt.model_copy(update={"charging_confirmed": False}).authorize("a" * 64)
    with pytest.raises(ValueError):
        BudgetReceipt(**{**receipt.model_dump(), "job_estimate": "0.6"}).authorize("a" * 64)


def test_all_eight_stage_templates_are_dry_renderable():
    for stage in ("smoke", "warm", "server", "preflight", "readiness", "replay", "collect", "cleanup"):
        assert stage in render_slurm(deployment(), stage, "/storage/work/user/config.json")
