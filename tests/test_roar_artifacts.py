import json

import pytest

from denialdojo.roar_artifacts import collect_evidence, verify_inventory


def test_evidence_collection_is_exclusive_and_digest_verified(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "raw.json").write_text('{"fixture":true}')
    destination = tmp_path / "durable"
    report = collect_evidence(source, destination)
    assert report["files"] == 1
    assert verify_inventory(destination, report["inventory"]) is None
    (source / "raw.json").write_text("changed")
    with pytest.raises(FileExistsError):
        collect_evidence(source, destination)
    assert json.loads((destination / "raw.json").read_text()) == {"fixture": True}


def test_collection_rejects_nested_destination_and_symlink(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    with pytest.raises(ValueError):
        collect_evidence(source, source / "copy")


def test_changed_inventory_fails_loudly(tmp_path):
    (tmp_path / "record").write_text("one")
    with pytest.raises(ValueError):
        verify_inventory(tmp_path, {"record": "0" * 64})
