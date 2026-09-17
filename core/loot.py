#!/usr/bin/env python3
"""
DNSemble - Output persistence.

Everything about turning a completed session into a file on disk lives
here: path sanitising, collision handling (never overwrite a previously
received file), and atomic writes so a failed disk write cannot leave a
truncated loot file behind.
"""

import os

from core.domains import MAX_NAME_LEN


class LootError(Exception):
    """Raised when a completed transfer cannot be persisted."""


def sanitize_component(text, max_len=64):
    """Filename-safe component: alnum plus -_. everything else → _."""
    cleaned = "".join(c if c.isalnum() or c in "-_." else "_" for c in text)
    cleaned = cleaned.lstrip(".").rstrip(".")
    while ".." in cleaned:
        cleaned = cleaned.replace("..", ".")
    return cleaned[:max_len] or "_"


def loot_path(loot_dir, hostname, filename):
    return os.path.join(
        loot_dir, f"{sanitize_component(hostname)}_{sanitize_component(filename)}")


class LootWriter:
    def __init__(self, loot_dir):
        self.loot_dir = loot_dir

    def save(self, hostname, filename, content, incomplete=False):
        """Write received content; never overwrites an existing loot file.

        Incomplete transfers are stored under a .incomplete suffix so a
        gapped capture can never pass for a successful one.  Returns
        (path, collided) where collided is True when the original name
        was already taken and a numbered suffix was used.
        """
        path = loot_path(self.loot_dir, hostname, filename)
        if incomplete:
            path += ".incomplete"
        collided = os.path.exists(path)
        if collided:
            n = 1
            while os.path.exists(f"{path}-{n}"):
                n += 1
            path = f"{path}-{n}"

        tmp = f"{path}.tmp"
        try:
            with open(tmp, "w") as f:
                f.write(content)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, path)
        except OSError as e:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise LootError(
                f"Cannot save exfiltrated file to {path!r}: {e}  "
                f"(check loot directory permissions and free space)")
        return path, collided

    def truncate(self, path, content):
        """Replace an existing loot file (operator-requested rewrite)."""
        try:
            with open(path, "w") as f:
                f.write(content)
        except OSError as e:
            raise LootError(f"Cannot write {path!r}: {e}")


__all__ = ["LootWriter", "LootError", "loot_path", "sanitize_component", "MAX_NAME_LEN"]
