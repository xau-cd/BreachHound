from __future__ import annotations

import hashlib
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path

from breachhound.config.settings import Settings
from breachhound.core.enums import Category
from breachhound.detectors.artifacts import checker as checker_module
from breachhound.detectors.artifacts.checker import ArtifactChecker
from breachhound.detectors.artifacts.integrity import diff_manifests, load_baseline, save_baseline
from breachhound.detectors.artifacts.webshell import scan_text

SHELL = "<?php @eval(base64_decode($_POST['z']));"
REF = datetime(2026, 10, 12, 18, tzinfo=timezone.utc)


def run(root: Path, **kw):
    checker = ArtifactChecker(Settings(), reference_time=REF, **kw)
    return checker, checker.analyze(root)


def cats(result) -> set[Category]:
    return {f.category for f in result.findings}


def test_webshell_in_uploads(tmp_path):
    (tmp_path / "uploads").mkdir()
    (tmp_path / "uploads" / "a.php").write_text(SHELL)
    _, result = run(tmp_path)
    assert {Category.WEBSHELL, Category.UPLOAD_EXEC} <= cats(result)
    shell = next(f for f in result.findings if f.category is Category.WEBSHELL)
    assert shell.confidence >= 0.6 and shell.metadata["relative_path"] == "uploads/a.php"


def test_normal_files_are_clean(tmp_path):
    (tmp_path / "index.php").write_text("<?php echo 'hello'; $x = base64_decode($v);")
    (tmp_path / "logo.png").write_bytes(b"\x89PNG\r\n\x1a\n" + b"0" * 50)
    (tmp_path / "readme.txt").write_text("hello")
    old = datetime(2026, 1, 1, tzinfo=timezone.utc).timestamp()
    for p in tmp_path.iterdir():
        os.utime(p, (old, old))
    _, result = run(tmp_path)
    assert result.findings == []


def test_sha256_is_recorded(tmp_path):
    data = b"hello world"
    (tmp_path / "f.bin").write_bytes(data)
    checker, _ = run(tmp_path)
    assert checker.manifest[0]["sha256"] == hashlib.sha256(data).hexdigest()


def test_extension_mismatch(tmp_path):
    (tmp_path / "pic.jpg").write_text("GIF89a<?php system($_GET['c']); ?>")
    (tmp_path / "shot.php.jpg").write_bytes(b"\xff\xd8\xff\xe0" + b"0" * 20)
    (tmp_path / "doc.pdf").write_bytes(b"\x7fELF" + b"\x00" * 30)
    _, result = run(tmp_path)
    mismatches = [f for f in result.findings if f.category is Category.EXTENSION_MISMATCH]
    assert len(mismatches) == 3


def test_hidden_file_in_upload_dir(tmp_path):
    (tmp_path / "uploads").mkdir()
    (tmp_path / "uploads" / ".x.php").write_text("<?php echo 1;")
    (tmp_path / "uploads" / ".htaccess").write_text("AddType application/x-httpd-php .jpg")
    _, result = run(tmp_path)
    assert Category.HIDDEN_FILE in cats(result) and Category.UPLOAD_EXEC in cats(result)


def test_recent_modification_uses_reference_time(tmp_path):
    path = tmp_path / "a.php"
    path.write_text("<?php echo 1;")
    ts = datetime(2026, 10, 11, tzinfo=timezone.utc).timestamp()
    os.utime(path, (ts, ts))
    assert Category.RECENT_MODIFICATION in cats(run(tmp_path)[1])
    ArtifactChecker(Settings(), reference_time=datetime(2027, 1, 1, tzinfo=timezone.utc))
    assert Category.RECENT_MODIFICATION not in cats(
        ArtifactChecker(Settings(), reference_time=datetime(2027, 1, 1, tzinfo=timezone.utc)).analyze(tmp_path)
    )


def test_unreadable_files_do_not_crash(tmp_path, monkeypatch):
    (tmp_path / "a.php").write_text("<?php echo 1;")
    (tmp_path / "b.txt").write_text("ok")

    def deny(path, *a, **k):
        if path.name == "a.php":
            raise PermissionError("denied")
        return hashlib.sha256(path.read_bytes()).hexdigest()

    monkeypatch.setattr(checker_module, "sha256_file", deny)
    checker, result = run(tmp_path)
    assert any("Permission refusée" in lim for lim in result.limitations)
    assert result.stats["artifact_unreadable_files"] == 1 and len(checker.manifest) == 1


def test_symlink_not_followed(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.php").write_text(SHELL)
    root = tmp_path / "root"
    root.mkdir()
    (root / "link").symlink_to(outside)
    (root / "flink.php").symlink_to(outside / "secret.php")
    _, result = run(root)
    assert Category.WEBSHELL not in cats(result) and Category.SUSPICIOUS_FILE in cats(result)


def test_ioc_hash_and_baseline(tmp_path):
    root = tmp_path / "site"
    root.mkdir()
    (root / "a.txt").write_text("alpha")
    (root / "b.txt").write_text("beta")
    checker, first = run(root)
    manifest = {m["path"]: m["sha256"] for m in checker.manifest}
    baseline = tmp_path / "baseline.json"
    save_baseline(manifest, baseline)
    (root / "a.txt").write_text("ALPHA changed")
    (root / "c.txt").write_text("new")
    (root / "b.txt").unlink()
    ioc = hashlib.sha256(b"new").hexdigest()
    _, result = run(root, baseline=baseline, ioc_hashes=[ioc])
    titles = {f.title for f in result.findings}
    assert {"File modified since baseline", "File added since baseline", "File removed since baseline"} <= titles
    assert Category.IOC_HASH_MATCH in cats(result)


def test_diff_and_bad_baseline(tmp_path):
    diff = diff_manifests({"a": "1", "b": "2"}, {"a": "1", "b": "9", "c": "3"})
    assert diff.modified == ["b"] and diff.removed == ["c"] and diff.added == []
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    try:
        load_baseline(bad)
    except Exception as exc:
        assert "Baseline" in str(exc) or "baseline" in str(exc)
    else:
        raise AssertionError("expected an error")


def test_read_only_guarantee(tmp_path, fixtures_dir):
    root = tmp_path / "copy"
    shutil.copytree(fixtures_dir / "artifacts", root)

    def snapshot():
        return {str(p): (p.stat().st_mtime_ns, hashlib.sha256(p.read_bytes()).hexdigest()) for p in root.rglob("*") if p.is_file()}

    before = snapshot()
    run(root)
    assert snapshot() == before


def test_missing_target(tmp_path):
    try:
        ArtifactChecker(Settings()).analyze(tmp_path / "nope")
    except Exception as exc:
        assert "introuvable" in str(exc)
    else:
        raise AssertionError("expected TargetNotFoundError")


def test_webshell_signatures_scoring():
    assert scan_text("<?php echo 'x';").flagged is False
    assert scan_text("<?php $a = base64_decode($b);").flagged is False
    assert scan_text("<?php system($_GET['c']);").flagged is True
    assert scan_text("<?php eval(base64_decode($_POST['z']));").severity.value == "CRITICAL"
    jsp = scan_text("<% Runtime.getRuntime().exec(request.getParameter(\"c\")); %>")
    assert jsp.flagged
