"""Publish generated files together, rolling back ordinary filesystem failures."""

import os
import tempfile
from pathlib import Path


def publish(updates: dict[Path, bytes | None]) -> None:
    """Stage on each destination filesystem before touching any old artifact.

    A None value removes an obsolete part. This rolls back caught failures; like
    other multi-file filesystem writes it is not a power-loss transaction.
    """
    staged, backups, applied = {}, {}, []
    temporary = []

    def stage(path, data):
        fd, name = tempfile.mkstemp(prefix='.rules-stage-', dir=path.parent)
        temporary.append(Path(name))
        with os.fdopen(fd, 'wb') as stream:
            stream.write(data)
        return Path(name)

    try:
        for path, data in updates.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            old = path.read_bytes() if path.exists() else None
            if old == data:
                continue
            backups[path] = stage(path, old) if old is not None else None
            staged[path] = stage(path, data) if data is not None else None
        for path, new in staged.items():
            if new is None:
                path.unlink(missing_ok=True)
            else:
                os.replace(new, path)
            applied.append(path)
    except BaseException:
        for path in reversed(applied):
            backup = backups[path]
            if backup is None:
                path.unlink(missing_ok=True)
            else:
                os.replace(backup, path)
        raise
    finally:
        for path in temporary:
            path.unlink(missing_ok=True)
