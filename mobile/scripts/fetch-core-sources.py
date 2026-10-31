#!/usr/bin/env python3
"""Fetch/verify SHA-pinned sources; never execute upstream scripts or replace WIP.

Existing source trees are compared with an independently extracted, patched tree.
Only exact, hash-pinned local receipt files may be present in addition to source.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import stat
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
LOCK = ROOT / "third_party/DEPENDENCIES.lock.json"
CORE_IDS = ("olcrtc", "openflux", "xray-core", "gvisor")
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
MAX_ARCHIVE_BYTES = 100 * 1024 * 1024
MAX_SOURCE_BYTES = 512 * 1024 * 1024
MAX_ENTRIES = 30000


class SourceError(Exception):
    """An integrity/policy failure; callers must leave existing trees untouched."""


def digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def relative(value: str) -> PurePosixPath:
    if not isinstance(value, str) or not value or "\\" in value or "\x00" in value:
        raise SourceError("invalid relative path")
    p = PurePosixPath(value)
    if p.is_absolute() or any(x in ("", ".", "..") for x in value.split("/")):
        raise SourceError("unsafe relative path")
    return p


def local_path(root: Path, value: str) -> Path:
    parts = relative(value).parts
    current = root
    if root.is_symlink():
        raise SourceError("symlink root rejected")
    for part in parts:
        current = current / part
        if current.is_symlink():
            raise SourceError("symlink path rejected")
    return current


def verify_digest(path: Path, expected: str) -> None:
    if not isinstance(expected, str) or not SHA256.fullmatch(expected):
        raise SourceError("missing pinned checksum")
    if path.is_symlink() or not path.is_file() or digest(path) != expected:
        raise SourceError("file checksum mismatch")


def download(dep: dict, root: Path, offline: bool) -> Path:
    info = dep["source_archive"]
    commit = dep["commit"]
    repo = dep["repository"]
    if not COMMIT.fullmatch(commit) or not re.fullmatch(r"https://github.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo):
        raise SourceError("invalid pinned repository")
    expected_url = "https://codeload.github.com/" + repo.removeprefix("https://github.com/") + "/tar.gz/" + commit
    if info["url"] != expected_url:
        raise SourceError("archive URL is not the exact pinned GitHub commit")
    cache = local_path(root, info["cache_path"])
    if not str(relative(info["cache_path"])).startswith("artifacts/upstream/"):
        raise SourceError("archive cache outside source artifacts")
    if not cache.exists():
        if offline:
            raise SourceError("archive is absent in offline mode")
        cache.parent.mkdir(parents=True, exist_ok=True)
        # A unique temporary belongs only to this invocation. No existing cache is replaced.
        with tempfile.NamedTemporaryFile(prefix=".source-download-", dir=cache.parent) as tmp:
            result = subprocess.run([
                "curl", "-4", "--fail", "--silent", "--show-error", "--location",
                "--proto", "=https", "--proto-redir", "=https", "--tlsv1.2",
                "--connect-timeout", "15", "--max-time", "90",
                "--max-filesize", str(MAX_ARCHIVE_BYTES), "--output", tmp.name,
                info["url"],
            ], capture_output=True, timeout=95)
            if result.returncode:
                raise SourceError("source download failed")
            verify_digest(Path(tmp.name), info["sha256"])
            # Atomic create; a concurrent invocation cannot overwrite a different archive.
            try:
                os.link(tmp.name, cache)
            except FileExistsError:
                pass
    if cache.stat().st_size > MAX_ARCHIVE_BYTES:
        raise SourceError("archive exceeds size policy")
    verify_digest(cache, info["sha256"])
    return cache


def extract(archive: Path, dest: Path, prefix: str) -> None:
    relative(prefix)
    if "/" in prefix or dest.exists() or dest.is_symlink():
        raise SourceError("invalid fresh extraction target")
    with tarfile.open(archive, "r:gz") as source:
        members = source.getmembers()
        if len(members) > MAX_ENTRIES:
            raise SourceError("archive has too many entries")
        records = []
        seen = set()
        total = 0
        for entry in members:
            # tarfile exposes PAX-resolved names; validate before stripping the root.
            name = entry.name.rstrip("/") if entry.isdir() else entry.name
            p = relative(name)
            if p.parts[0] != prefix or not (entry.isdir() or entry.isfile()):
                raise SourceError("archive prefix or entry type rejected")
            if entry.mode & 0o7000 or entry.size < 0:
                raise SourceError("special archive permissions or size rejected")
            if name in seen:
                raise SourceError("duplicate archive path")
            seen.add(name)
            if len(p.parts) == 1:
                if not entry.isdir():
                    raise SourceError("archive root must be directory")
                continue
            rel = PurePosixPath(*p.parts[1:])
            total += entry.size
            if total > MAX_SOURCE_BYTES:
                raise SourceError("source tree exceeds size policy")
            records.append((entry, rel))
        if not records:
            raise SourceError("empty source archive")
        # Reject file/parent collisions before any extraction.
        types = {str(p): e.isdir() for e, p in records}
        for _, p in records:
            for parent in p.parents:
                if str(parent) in types and not types[str(parent)]:
                    raise SourceError("file used as archive directory")
        dest.mkdir()
        for entry, rel in records:
            target = dest.joinpath(*rel.parts)
            if entry.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            incoming = source.extractfile(entry)
            if incoming is None:
                raise SourceError("unreadable archive file")
            with incoming, target.open("xb") as output:
                remaining = entry.size
                while remaining:
                    chunk = incoming.read(min(1024 * 1024, remaining))
                    if not chunk:
                        raise SourceError("truncated archive entry")
                    output.write(chunk)
                    remaining -= len(chunk)
            target.chmod(0o755 if entry.mode & 0o111 else 0o644)


def check_metadata(source: Path, dep: dict) -> None:
    for name, proof in dep["provenance_files"].items():
        path = local_path(source, name)
        if proof.get("sha256") is None:
            if path.exists():
                raise SourceError("unexpected metadata previously recorded absent")
        else:
            verify_digest(path, proof["sha256"])


def apply_patches(source: Path, dep: dict, root: Path) -> None:
    for patch in dep["source_archive"].get("patches", []):
        path = local_path(root, patch["path"])
        if not str(relative(patch["path"])).startswith("third_party/patches/"):
            raise SourceError("patch outside reviewed patch directory")
        verify_digest(path, patch["sha256"])
        headers = []
        for line in path.read_text().splitlines():
            if line.startswith("diff --git "):
                fields = shlex.split(line)
                if len(fields) != 4 or not fields[2].startswith("a/") or not fields[3].startswith("b/"):
                    raise SourceError("unrecognized patch header")
                old, new = fields[2][2:], fields[3][2:]
                relative(old); relative(new)
                if old != new:
                    raise SourceError("patch rename is not permitted")
                headers.append(new)
            elif line.startswith(("new file mode ", "old mode ", "new mode ", "deleted file mode ")):
                if line.split()[-1] not in ("100644", "100755"):
                    raise SourceError("patch special file mode rejected")
            elif line.startswith(("rename from ", "rename to ", "copy from ", "copy to ", "GIT binary patch")):
                raise SourceError("non-text patch operation rejected")
        expected = patch["affected_files"]
        if not headers or len(headers) != len(set(headers)) or sorted(headers) != sorted(expected):
            raise SourceError("patch affected-file manifest mismatch")
        env = os.environ.copy()
        for name in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"):
            env.pop(name, None)
        # Apply as a standalone source directory, never as a change in the parent bot Git index.
        env["GIT_CEILING_DIRECTORIES"] = str(source.parent)
        for options in (["--check"], []):
            result = subprocess.run(["git", "apply", *options, "--whitespace=error-all", str(path)],
                                    cwd=source, env=env, capture_output=True, timeout=30)
            if result.returncode:
                raise SourceError("reviewed patch did not apply cleanly")


def tree(source: Path, optional: dict | None = None) -> dict:
    if source.is_symlink() or not source.is_dir():
        raise SourceError("source is not an ordinary directory")
    result = {}
    optional = optional or {}
    for base, dirs, files in os.walk(source, followlinks=False):
        for name in dirs + files:
            p = Path(base) / name
            rel = p.relative_to(source).as_posix()
            info = p.lstat()
            if stat.S_ISLNK(info.st_mode) or not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
                raise SourceError("non-regular entry in existing source")
            if stat.S_ISDIR(info.st_mode):
                result[rel] = {"kind": "dir"}
            elif rel in optional:
                verify_digest(p, optional[rel])
            else:
                result[rel] = {"kind": "file", "sha256": digest(p), "executable": bool(info.st_mode & 0o111)}
    return result


def prepare(dep: dict, root: Path, offline: bool, verify_only: bool) -> dict:
    info = dep["source_archive"]
    destination = local_path(root, info["destination"])
    if not str(relative(info["destination"])).startswith("artifacts/upstream/"):
        raise SourceError("source destination outside artifacts")
    if verify_only and not destination.exists():
        raise SourceError("source absent in verify-only mode")
    archive = download(dep, root, offline)
    staging = local_path(root, "artifacts/upstream/.fetch-work")
    staging.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=dep["id"] + "-", dir=staging) as tmp:
        fresh = Path(tmp) / "source"
        extract(archive, fresh, info["prefix"])
        check_metadata(fresh, dep)
        apply_patches(fresh, dep, root)
        # Patches may not silently change metadata recorded by the provenance lock.
        check_metadata(fresh, dep)
        expected = tree(fresh)
        manifest = hashlib.sha256(json.dumps(expected, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        if destination.exists():
            actual = tree(destination, info.get("allowed_local_files", {}))
            if actual != expected:
                changed = sum(actual.get(k) != expected.get(k) for k in actual.keys() | expected.keys())
                raise SourceError(f"existing source differs at {changed} entries; no files replaced")
            status = "VERIFIED_EXISTING"
        else:
            destination.parent.mkdir(parents=True, exist_ok=True)
            fresh.rename(destination)
            status = "EXTRACTED_VERIFIED"
    return {"dependency": dep["id"], "commit": dep["commit"], "status": status,
            "archive_sha256": info["sha256"], "tree_manifest_sha256": manifest,
            "source_files": sum(x["kind"] == "file" for x in expected.values()),
            "patches": len(info.get("patches", [])), "scripts_executed": False}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dependency", action="append", choices=(*CORE_IDS, "libxray-reference"))
    parser.add_argument("--offline", action="store_true", help="Require already cached exact archives")
    parser.add_argument("--verify-only", action="store_true", help="Refuse to install missing source trees")
    args = parser.parse_args()
    document = json.loads(LOCK.read_text())
    deps = {x["id"]: x for x in document["dependencies"]}
    try:
        for name in args.dependency or CORE_IDS:
            print(json.dumps(prepare(deps[name], ROOT, args.offline, args.verify_only)), flush=True)
    except (SourceError, OSError, ValueError, KeyError, tarfile.TarError, subprocess.SubprocessError) as exc:
        # Sources are public; still avoid dumping external commands or environment on failure.
        reason = str(exc) if isinstance(exc, SourceError) else type(exc).__name__
        print(json.dumps({"status": "SOURCE_CHECK_FAILED", "reason": reason}), flush=True)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
