from denialdojo.provenance import working_tree_digest


def test_working_tree_digest_covers_untracked_file_contents(tmp_path) -> None:
    source = tmp_path / "new.py"
    source.write_text("first", encoding="utf-8")
    first = working_tree_digest("head", "?? new.py\n", b"", ["new.py"], tmp_path)

    source.write_text("second", encoding="utf-8")
    second = working_tree_digest("head", "?? new.py\n", b"", ["new.py"], tmp_path)

    assert first != second
