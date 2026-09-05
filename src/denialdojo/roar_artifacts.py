"""Digest-verified, no-overwrite transfer of closed evidence directories."""

import hashlib
import shutil
from pathlib import Path

from denialdojo.run_ledger import exclusive_json


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def inventory(root: Path) -> dict[str, str]:
    if root.is_symlink() or not root.is_dir():
        raise ValueError("evidence root must be a real directory")
    result = {}
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError("symlinks are not evidence files")
        if path.is_file():
            result[path.relative_to(root).as_posix()] = file_sha256(path)
    return result


def verify_inventory(root: Path, expected: dict[str, str]) -> None:
    actual = inventory(root)
    # collection receipt is an operational sidecar, never part of source evidence.
    actual.pop("collection-receipt.json", None)
    if actual != expected:
        raise ValueError("evidence inventory mismatch: added, removed or changed files")


def collect_evidence(source: Path, destination: Path) -> dict:
    source, destination = Path(source), Path(destination)
    if source.resolve() == destination.resolve() or source.resolve() in destination.resolve().parents:
        raise ValueError("evidence destination must be separate from source")
    before = inventory(source)
    if "collection-receipt.json" in before:
        raise ValueError("source already contains a collection receipt")
    destination.mkdir(parents=True, exist_ok=False)
    for name in before:
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        with (source / name).open("rb") as reader, target.open("xb") as writer:
            shutil.copyfileobj(reader, writer)
    verify_inventory(source, before)
    verify_inventory(destination, before)
    report = {"files": len(before), "inventory": before, "source": str(source.resolve())}
    exclusive_json(destination / "collection-receipt.json", report)
    for name in before:
        (destination / name).chmod(0o400)
    return report
