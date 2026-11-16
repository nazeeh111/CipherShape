"""Owned local artifact stages; setup commits when its public directory appears.

Recovery takes one private journal, never scans paths or resumes native work.
Supported on local macOS/Linux filesystems with exclusive directory rename.
Parents must stay stable; this is not a power-loss or hostile-host transaction.
"""
from contextlib import contextmanager
import ctypes
import fcntl
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import uuid


MAX_ARTIFACT = 256 * 1024 * 1024
MAX_MEMBERS = 260
MAX_RECORD = 100_000
ROLES = {"setup": ("private", "public"), "request": ("request",), "response": ("response",)}


class ProtocolError(ValueError):
    pass


class CleanupPending(ProtocolError):
    """Final artifacts exist; only the named, owned cleanup remains."""

    def __init__(self, journal: Path, reason: str = "OSError"):
        self.journal = journal
        self.cleanup_error_type = reason
        self.artifact_state = "committed_cleanup_required"
        super().__init__(f"artifacts published; cleanup pending ({reason}); recover with journal {journal}")


def _blocks_fd(fd: int, limit: int):
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
        raise ProtocolError("artifact must be a bounded regular file")
    remaining = limit + 1
    while remaining:
        block = os.read(fd, min(1024 * 1024, remaining))
        if not block:
            break
        remaining -= len(block)
        if remaining == 0:
            raise ProtocolError("artifact byte limit exceeded")
        yield block


def _read_fd(fd: int, limit: int) -> bytes:
    return b"".join(_blocks_fd(fd, limit))


def read_bytes(path: Path, limit: int, *, dir_fd: int | None = None) -> bytes:
    """Read/hash/parse callers can share one no-follow bounded byte snapshot."""
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    fd = os.open(path, flags, dir_fd=dir_fd)
    try:
        return _read_fd(fd, limit)
    finally:
        os.close(fd)


def _digest_size(path: Path, limit: int) -> tuple[str, int]:
    h = hashlib.sha256()
    size = 0
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        for block in _blocks_fd(fd, limit):
            h.update(block)
            size += len(block)
    finally:
        os.close(fd)
    return h.hexdigest(), size


def digest(path: Path) -> str:
    return _digest_size(path, MAX_ARTIFACT)[0]


def separate_paths(*paths: Path) -> None:
    resolved = [p.resolve() for p in paths]
    for i, path in enumerate(resolved):
        if any(path == other or path in other.parents or other in path.parents
               for other in resolved[i+1:]):
            raise ProtocolError("artifact roots must be separate directories")


def new_destination(path: Path) -> Path:
    # Resolve parents, not the last entry: even a dangling destination link exists.
    destination = path.parent.resolve() / path.name
    if os.path.lexists(destination):
        raise ProtocolError("artifact destination must be new")
    return destination


def _rename_function():
    libc = ctypes.CDLL(None, use_errno=True)
    if sys.platform == "darwin" and hasattr(libc, "renamex_np"):
        fn = libc.renamex_np
        fn.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
        args = lambda src, dst: (src, dst, 4)  # RENAME_EXCL, sys/stdio.h
    elif sys.platform.startswith("linux") and hasattr(libc, "renameat2"):
        fn = libc.renameat2
        fn.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        args = lambda src, dst: (-100, src, -100, dst, 1)  # AT_FDCWD, RENAME_NOREPLACE
    else:
        raise ProtocolError("exclusive directory publication is unavailable on this platform")
    fn.restype = ctypes.c_int
    return fn, args


def _rename_new(source: Path, destination: Path) -> None:
    fn, args = _rename_function()
    if fn(*args(os.fsencode(source), os.fsencode(destination))) != 0:
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error), str(source), None, str(destination))


def _identity(path: Path) -> list[int]:
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        raise ProtocolError("stage ownership changed")
    return [info.st_dev, info.st_ino]


def _same(path: Path, identity: list[int]) -> bool:
    if not os.path.lexists(path):
        return False
    info = path.lstat()
    return (stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid()
            and [info.st_dev, info.st_ino] == identity)


def _write_record(path: Path, value: dict):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(value, f, sort_keys=True, allow_nan=False)
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())


def _tree(path: Path, limit: int = MAX_ARTIFACT) -> dict[str, str]:
    result = {}
    total = 0
    for file in path.iterdir():
        if len(result) >= MAX_MEMBERS:
            raise ProtocolError("artifact member limit exceeded")
        fingerprint, size = _digest_size(file, min(MAX_ARTIFACT, limit - total))
        if not size:
            raise ProtocolError("invalid staged artifact")
        total += size
        result[file.name] = fingerprint
    return result


def _parse_record(data: bytes) -> dict:
    try:
        value = json.loads(data)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ProtocolError("invalid recovery record") from exc
    if not isinstance(value, dict):
        raise ProtocolError("invalid recovery record")
    return value


def _load(path: Path) -> dict:
    return _parse_record(read_bytes(path, MAX_RECORD))


def _validate_record(record: dict, journal: Path) -> list[dict]:
    try:
        operation, attempt, entries = record["operation"], record["attempt"], record["entries"]
        if (type(record["version"]) is not int or record["version"] != 1 or operation not in ROLES or
                str(uuid.UUID(attempt)) != attempt or
                [entry["role"] for entry in entries] != list(ROLES[operation])):
            raise ValueError
        for entry in entries:
            root, target = Path(entry["stage"]), Path(entry["destination"])
            if (not root.is_absolute() or not target.is_absolute() or root.parent != target.parent or
                    root.name != f".ciphershape-stage-{attempt}-{entry['role']}" or
                    root.parent.resolve() != root.parent or target == root):
                raise ValueError
            limit = entry.get("max_bytes", MAX_ARTIFACT)
            if type(limit) is not int or not 0 < limit <= MAX_ARTIFACT * MAX_MEMBERS:
                raise ValueError
            if os.path.lexists(root) and (not _same(root, entry["stage_identity"]) or
                                          root.stat().st_mode & 0o077):
                raise ValueError
            payload = root / "payload"
            if os.path.lexists(payload) and not _same(payload, entry["payload_identity"]):
                raise ValueError
            if root.exists():
                allowed = {"payload", "stage.json", "complete.json"} if root == journal.parent else {"payload"}
                if set(p.name for p in root.iterdir()) - allowed:
                    raise ValueError
        if journal != Path(entries[0]["stage"]) / "stage.json":
            raise ValueError
        separate_paths(*(Path(e["destination"]) for e in entries))
    except (KeyError, TypeError, ValueError, OSError) as exc:
        raise ProtocolError("recovery ownership or layout mismatch; preserved") from exc
    return entries


def _settle(record: dict, journal: Path) -> str:
    """Reconcile actual directory identities, including rename-before-exception."""
    entries = _validate_record(record, journal)
    committed = _same(Path(entries[-1]["destination"]), entries[-1]["payload_identity"])
    if not committed:
        last = entries[-1]
        if not _same(Path(last["stage"]) / "payload", last["payload_identity"]):
            raise ProtocolError("publication is indeterminate; outputs and recovery journal preserved")
        rollback = [e for e in entries if _same(Path(e["destination"]), e["payload_identity"])]
        if rollback:
            complete = _load(journal.parent / "complete.json")
            # Check every published path before moving any. User changes survive.
            for entry in rollback:
                if (_tree(Path(entry["destination"]), entry.get("max_bytes", MAX_ARTIFACT)) != complete.get(entry["role"]) or
                        os.path.lexists(Path(entry["stage"]) / "payload")):
                    raise ProtocolError("published stage changed; explicit recovery refused")
            for entry in rollback:
                moved = Path(entry["stage"]) / "payload"
                _rename_new(Path(entry["destination"]), moved)
                # Recheck the actual moved object, not the pathname seen earlier.
                if (not _same(moved, entry["payload_identity"]) or
                        _tree(moved, entry.get("max_bytes", MAX_ARTIFACT)) != complete.get(entry["role"])):
                    raise ProtocolError(f"rollback target changed; preserved at {moved}")
    for entry in reversed(entries):  # journal/lock owner is removed last
        root = Path(entry["stage"])
        if root.exists():
            if not _same(root, entry["stage_identity"]):
                raise ProtocolError("cleanup stage identity changed; preserved")
            shutil.rmtree(root)
    return "committed" if committed else "aborted"


def _failure(record: dict, journal: Path | None, phase: str, state: str, error: BaseException) -> Path:
    first = record["entries"][0]
    receipt = Path(first["destination"]).parent / f".ciphershape-failure-{record['attempt']}.json"
    _write_record(receipt, {"version": 1, "operation": record["operation"], "attempt": record["attempt"],
                           "phase": phase, "state": state, "error_type": type(error).__name__,
                           "recovery_journal": str(journal) if journal and journal.exists() else None})
    return receipt


@contextmanager
def staged_artifacts(operation: str, *, byte_limits: dict[str, int] | None = None,
                     on_prepared=None, **destinations: Path):
    """Yield fresh payload directories; publish only after the body validates them."""
    if operation not in ROLES or set(destinations) != set(ROLES[operation]):
        raise ProtocolError("unsupported artifact stage")
    targets = {role: new_destination(destinations[role]) for role in ROLES[operation]}
    limits = byte_limits or {role: MAX_ARTIFACT for role in targets}
    if (set(limits) != set(targets) or any(type(n) is not int or not 0 < n <= MAX_ARTIFACT * MAX_MEMBERS
                                         for n in limits.values())):
        raise ProtocolError("invalid artifact byte budgets")
    separate_paths(*targets.values())
    _rename_function()  # Fail before native work if the required primitive is absent.
    attempt = str(uuid.uuid4())
    record = {"version": 1, "attempt": attempt, "operation": operation, "entries": []}
    journal = None
    lock = None
    phase = "prepare"
    try:
        for role, target in targets.items():
            target.parent.mkdir(parents=True, exist_ok=True)
            root = target.parent / f".ciphershape-stage-{attempt}-{role}"
            root.mkdir(mode=0o700)
            entry = {"role": role, "stage": str(root), "destination": str(target),
                     "stage_identity": _identity(root), "max_bytes": limits[role]}
            record["entries"].append(entry)
            payload = root / "payload"
            payload.mkdir(mode=0o700)
            entry["payload_identity"] = _identity(payload)
        journal = Path(record["entries"][0]["stage"]) / "stage.json"
        fd = os.open(journal, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
        lock = os.fdopen(fd, "r+")
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        json.dump(record, lock, sort_keys=True)
        lock.flush()
        os.fsync(lock.fileno())
        if on_prepared is not None:
            on_prepared(journal)
        phase = "work"
        yield {e["role"]: Path(e["stage"]) / "payload" for e in record["entries"]}
        complete = {e["role"]: _tree(Path(e["stage"]) / "payload", e["max_bytes"])
                    for e in record["entries"]}
        _write_record(journal.parent / "complete.json", complete)
        phase = "publish"
        for entry in record["entries"]:
            source, target = Path(entry["stage"]) / "payload", Path(entry["destination"])
            if not _same(source, entry["payload_identity"]):
                raise ProtocolError("stage ownership changed")
            try:
                _rename_new(source, target)
            except OSError:
                if source.exists() or not _same(target, entry["payload_identity"]):
                    raise
        phase = "cleanup"
        _settle(record, journal)
    except BaseException as exc:
        state = "recovery_required"
        try:
            if journal is not None and lock is not None:
                if phase == "cleanup" and isinstance(exc, PermissionError):
                    last = record["entries"][-1]
                    if _same(Path(last["destination"]), last["payload_identity"]):
                        state = "committed_cleanup_required"
                else:
                    state = _settle(record, journal)
            else:
                for entry in reversed(record["entries"]):
                    root = Path(entry["stage"])
                    if _same(root, entry["stage_identity"]):
                        shutil.rmtree(root)
                state = "aborted"
        except (OSError, ProtocolError):
            if _same(Path(record["entries"][-1]["destination"]),
                     record["entries"][-1].get("payload_identity", [])):
                state = "committed_cleanup_required"
        if record["entries"]:
            try:
                exc.artifact_failure_receipt = _failure(record, journal, phase, state, exc)
            except OSError:
                exc.artifact_failure_receipt = journal
            exc.add_note(f"artifact state: {state}; receipt: {exc.artifact_failure_receipt}")
            exc.artifact_state = state
        if phase == "cleanup" and state == "committed" and isinstance(exc, OSError):
            return  # Cleanup retry succeeded; the confirmed output is successful.
        if state == "committed_cleanup_required" and isinstance(exc, Exception):
            raise CleanupPending(journal, type(exc).__name__) from exc
        raise
    finally:
        if lock is not None:
            lock.close()


def recover_artifacts(journal: Path) -> dict:
    """Discard one inactive interrupted attempt, or retain its committed output."""
    if not os.path.lexists(journal):
        return {"state": "absent"}
    if journal.name != "stage.json" or journal.is_symlink() or journal.parent.is_symlink():
        raise ProtocolError("invalid recovery journal")
    journal = journal.parent.resolve() / journal.name
    fd = os.open(journal, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "r+") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ProtocolError("artifact stage is still active") from exc
        info = os.fstat(lock.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_mode & 0o077 or info.st_size > MAX_RECORD):
            raise ProtocolError("recovery journal must be a private bounded regular file")
        record = _parse_record(_read_fd(lock.fileno(), MAX_RECORD))
        named = journal.lstat()
        if (not stat.S_ISREG(named.st_mode) or
                (named.st_dev, named.st_ino) != (info.st_dev, info.st_ino)):
            raise ProtocolError("locked journal path changed; recovery refused")
        state = _settle(record, journal)
    return {"state": state, "attempt": record["attempt"], "operation": record["operation"]}
