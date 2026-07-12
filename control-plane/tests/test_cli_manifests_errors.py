"""Issue #30: friendly error (exit 2) when --manifests path is missing or unreadable.

These exercise the REAL conditions (missing path, chmod 000 dir/file) rather
than monkeypatching PermissionError, because Path.rglob() silently swallows
EACCES during traversal — a naive fix would let an unreadable path masquerade
as a clean scan.
"""
import os
import stat
import pytest
from pathlib import Path

from app import cli

_is_root = hasattr(os, "geteuid") and os.geteuid() == 0


def test_missing_manifests_path_exits_2(capsys):
    with pytest.raises(SystemExit) as e:
        cli.build_graph_from_manifests("/nonexistent/path/for/test")
    assert e.value.code == 2
    assert "manifests path not found" in capsys.readouterr().err


@pytest.mark.skipif(_is_root, reason="root bypasses file permissions")
def test_unreadable_directory_exits_2_with_hint(tmp_path, capsys):
    d = tmp_path / "scan"
    d.mkdir()
    (d / "role.yaml").write_text("kind: Role\nmetadata: {name: x}\n")
    os.chmod(d, 0o000)
    try:
        if os.access(d, os.R_OK):  # environment doesn't enforce (e.g. some CI)
            pytest.skip("filesystem does not enforce dir permissions here")
        with pytest.raises(SystemExit) as e:
            cli.build_graph_from_manifests(str(d))
        assert e.value.code == 2
        err = capsys.readouterr().err
        assert "permission denied" in err
        assert ":z" in err  # actionable SELinux hint
    finally:
        os.chmod(d, stat.S_IRWXU)


@pytest.mark.skipif(_is_root, reason="root bypasses file permissions")
def test_unreadable_file_exits_2_with_hint(tmp_path, capsys):
    f = tmp_path / "role.yaml"
    f.write_text("kind: Role\n")
    os.chmod(f, 0o000)
    try:
        if os.access(f, os.R_OK):
            pytest.skip("filesystem does not enforce file permissions here")
        with pytest.raises(SystemExit) as e:
            cli.build_graph_from_manifests(str(f))
        assert e.value.code == 2
        assert ":z" in capsys.readouterr().err
    finally:
        os.chmod(f, stat.S_IRUSR | stat.S_IWUSR)
