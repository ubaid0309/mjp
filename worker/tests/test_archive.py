"""Safe extraction: traversal, symlinks, zip bombs, exclusions and limits."""
import io
import stat
import zipfile

import pytest

from securematrix_worker.archive import UnsafeArchiveError, classify, extract_archive

LIMITS = dict(max_file_bytes=64 * 1024, max_files=100, max_total_bytes=10 << 20, max_entries=1000, max_ratio=100)


def make_zip(tmp_path, entries, name="a.zip"):
    path = tmp_path / name
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        for entry in entries:
            if isinstance(entry, zipfile.ZipInfo):
                zf.writestr(entry, "target")
            else:
                zf.writestr(*entry)
    return path


@pytest.mark.parametrize("bad", ["../evil.py", "src/../../evil.py", "/etc/passwd", "C:/windows/evil.py", "..\\evil.py"])
def test_rejects_path_traversal_and_absolute_paths(tmp_path, bad):
    z = make_zip(tmp_path, [("ok.py", "x = 1"), (bad, "boom")])
    with pytest.raises(UnsafeArchiveError):
        extract_archive(z, tmp_path / "out", **LIMITS)
    assert not (tmp_path / "evil.py").exists()


def test_rejects_symlinks(tmp_path):
    link = zipfile.ZipInfo("link.py")
    link.external_attr = (stat.S_IFLNK | 0o777) << 16
    z = make_zip(tmp_path, [link])
    with pytest.raises(UnsafeArchiveError, match="symbolic link"):
        extract_archive(z, tmp_path / "out", **LIMITS)


def test_rejects_zip_bomb_ratio(tmp_path):
    z = make_zip(tmp_path, [("bomb.py", "a" * (5 << 20))])
    with pytest.raises(UnsafeArchiveError, match="compression ratio"):
        extract_archive(z, tmp_path / "out", **{**LIMITS, "max_file_bytes": 10 << 20})


def test_rejects_too_many_entries(tmp_path):
    z = make_zip(tmp_path, [(f"f{i}.py", "x") for i in range(20)])
    with pytest.raises(UnsafeArchiveError, match="entries"):
        extract_archive(z, tmp_path / "out", **{**LIMITS, "max_entries": 10})


def test_rejects_non_zip(tmp_path):
    p = tmp_path / "x.zip"
    p.write_bytes(b"not a zip")
    with pytest.raises(UnsafeArchiveError, match="not a valid ZIP"):
        extract_archive(p, tmp_path / "out", **LIMITS)


def test_excludes_dependencies_binaries_and_unsupported(tmp_path):
    z = make_zip(tmp_path, [
        ("app/main.py", "print('hi')\n"),
        ("app/node_modules/lib/index.js", "eval(x)"),
        ("app/vendor/lib.php", "<?php"),
        ("app/logo.png", "\x89PNG"),
        ("app/blob.py", "abc\x00def"),
        ("app/README.md", "# readme"),
        ("app/package-lock.json", "{}"),
        ("app/big.py", "x" * (100 * 1024)),
    ])
    res = extract_archive(z, tmp_path / "out", **LIMITS)
    scanned = {f.path for f in res.scannable}
    assert scanned == {"app/main.py"}
    reasons = {f.path: f.exclusion_reason for f in res.files if f.status == "excluded"}
    assert reasons["app/blob.py"] == "binary content"
    assert reasons["app/README.md"] == "unsupported file type"
    assert reasons["app/package-lock.json"] == "generated or lock file"
    assert "file limit" in reasons["app/big.py"]
    assert res.excluded_dir_counts == {"app/node_modules": 1, "app/vendor": 1}
    assert not (tmp_path / "out" / "app" / "node_modules").exists()
    main = next(f for f in res.files if f.path == "app/main.py")
    assert main.language == "python" and main.line_count == 1 and len(main.sha256) == 64


def test_file_count_limit_is_recorded(tmp_path):
    z = make_zip(tmp_path, [(f"f{i}.py", "x = 1") for i in range(5)])
    res = extract_archive(z, tmp_path / "out", **{**LIMITS, "max_files": 3})
    assert len(res.scannable) == 3
    assert sum(1 for f in res.files if f.exclusion_reason and "file-count" in f.exclusion_reason) == 2


@pytest.mark.parametrize("path,lang", [("a/b.ts", "typescript"), ("Dockerfile", "dockerfile"), (".env.production", "dotenv"),
                                       ("x.tf", "terraform"), ("k8s.yaml", "yaml"), ("notes.txt", None)])
def test_classify(path, lang):
    assert classify(path) == lang
