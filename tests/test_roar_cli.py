import json

import pytest
from test_roar_config import deployment

from denialdojo.roar import main


def test_dry_run_is_read_only_and_reports_submission_disabled(tmp_path, capsys):
    config = tmp_path / "deployment.json"
    config.write_text(deployment().model_dump_json(by_alias=True))
    before = list(tmp_path.iterdir())
    main(["dry-run", "smoke", "--config", str(config), "--remote-config", "/storage/work/user/deployment.json"])
    output = capsys.readouterr().out
    assert "#SBATCH --gres=gpu:fixture:1" in output
    assert "SUBMISSION DISABLED" in output
    assert list(tmp_path.iterdir()) == before


def test_run_stage_fails_closed_without_confirmed_site_discovery(tmp_path, monkeypatch):
    config = tmp_path / "deployment.json"
    config.write_text(deployment().model_dump_json(by_alias=True))
    monkeypatch.setenv("SLURM_JOB_ID", "fixture")
    with pytest.raises(ValueError, match="authenticated Roar discovery"):
        main(["run-stage", "smoke", "--config", str(config)])


def test_schema_command_can_be_used_without_roar_or_models(capsys):
    main(["schema", "deployment"])
    assert "partition" in json.loads(capsys.readouterr().out)["required"]
