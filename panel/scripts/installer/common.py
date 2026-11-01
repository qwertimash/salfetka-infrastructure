"""Bounded I/O and private, atomic state shared by the installer modules."""
import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import tempfile


class Failure(Exception):
    """Only fixed, non-secret error codes may cross the command-line boundary."""


def require(condition, code):
    if not condition:
        raise Failure(code)


def unique(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, 'duplicate_json_field')
        result[key] = value
    return result


def decode(raw):
    try:
        return json.loads(raw, object_pairs_hook=unique)
    except (ValueError, TypeError, RecursionError):
        raise Failure('invalid_json') from None


def regular(path, limit=1 << 20, private=False):
    path = Path(path).absolute()
    require(not any(p.is_symlink() for p in (path, *path.parents)), 'unsafe_file_path')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        require(stat.S_ISREG(info.st_mode) and info.st_size <= limit, 'unsafe_file')
        require(not private or info.st_mode & 0o077 == 0, 'private_file_required')
        raw = stream.read(limit + 1)
    require(len(raw) <= limit, 'file_too_large')
    return raw


def atomic(path, raw, mode=0o600):
    path = Path(path).absolute()
    require(not any(p.is_symlink() for p in (path, *path.parents)), 'unsafe_state_path')
    require(path.parent.is_dir(), 'state_parent_missing')
    fd, temporary = tempfile.mkstemp(prefix='.' + path.name + '-', dir=path.parent)
    try:
        with os.fdopen(fd, 'wb') as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def save(path, value):
    atomic(path, (json.dumps(value, ensure_ascii=False, indent=2) + '\n').encode())


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1 << 20), b''):
            digest.update(block)
    return digest.hexdigest()


def version(value):
    require(isinstance(value, str) and re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)', value), 'invalid_version')
    return tuple(map(int, value.split('.')))


@contextlib.contextmanager
def lock(path):
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
                and info.st_mode & 0o077 == 0 and info.st_nlink == 1, 'unsafe_lock')
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Failure('another_installer_is_running') from None
        yield
    finally:
        os.close(fd)


def run(argv, *, cwd=None, env=None, timeout=180, input=None, output=None):
    """Never interpolate shell commands or surface subprocess stderr/secrets."""
    if Path(argv[0]).name == 'docker':
        # This installer owns services on this host only. Never inherit a remote
        # Docker context, even when an operator uses one for unrelated work.
        env = dict(os.environ if env is None else env)
        for name in ('DOCKER_CONTEXT', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH'):
            env.pop(name, None)
        env['DOCKER_HOST'] = 'unix:///var/run/docker.sock'
    try:
        result = subprocess.run([str(arg) for arg in argv], cwd=cwd, env=env,
                                input=input, stdout=output or subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        raise Failure('command_unavailable_or_timed_out:' + Path(argv[0]).name) from None
    require(result.returncode == 0, 'command_failed:' + Path(argv[0]).name)
    return result.stdout
