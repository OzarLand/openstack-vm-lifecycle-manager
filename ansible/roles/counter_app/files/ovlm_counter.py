#!/usr/bin/env python3
"""ovlm-counter: the OVLM reference workload (Python standard library only).

A counter persisted in SQLite on the data volume, plus /health which reports
whether the data volume is really mounted (by filesystem UUID), the marker
file and its SHA-256.

  GET  /        increment and return the counter (state written to the data volume)
  POST /marker  write DATA_DIR/<marker> with a random token; returns its SHA-256
  GET  /health  JSON; HTTP 503 if the data volume is absent/wrong (never writes)

Identity (docs/automation-contract.md section 3.6.1): every response carries the header X-OVLM-Server-Id and /health
carries `server_id` in the JSON: the cloud-init instance-id (the Nova server id on OpenStack), read at request time
from OVLM_COUNTER_SERVER_ID_FILES (default: /run/cloud-init/instance-data.json v1.instance_id, then
/var/lib/cloud/data/instance-id). When unknown the header is omitted and `server_id` is null; the external probe then
fails, by design.

Configuration (environment, set by the systemd unit or the test-mode launcher):
  OVLM_COUNTER_DATA_DIR       mount point of the data volume      (default /srv/data)
  OVLM_COUNTER_MARKER         marker file name in DATA_DIR        (default .ovlm-marker)
  OVLM_COUNTER_PORT           TCP port                            (default 8080)
  OVLM_COUNTER_BIND           bind address                        (default 0.0.0.0)
  OVLM_COUNTER_VOLUME_ID      Cinder volume id; the mount must be backed by
                              /dev/disk/by-id/virtio-<first 20 chars of the id>
  OVLM_COUNTER_FS_TYPE        expected filesystem type, if set
  OVLM_COUNTER_SERVER_ID_FILES colon-separated files to read the instance-id from (tests)
  OVLM_COUNTER_TEST_MODE      "1" = CI only: no real mount is required, the
                              filesystem UUID is read from OVLM_COUNTER_TEST_FS_UUID
                              and /health says "simulated": true. Never set on a real VM.
"""
import hashlib
import json
import os
import secrets
import socket
import sqlite3
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DATA_DIR = os.environ.get("OVLM_COUNTER_DATA_DIR", "/srv/data")
MARKER = os.environ.get("OVLM_COUNTER_MARKER", ".ovlm-marker")
PORT = int(os.environ.get("OVLM_COUNTER_PORT", "8080"))
BIND = os.environ.get("OVLM_COUNTER_BIND", "0.0.0.0")
VOLUME_ID = os.environ.get("OVLM_COUNTER_VOLUME_ID", "")
FS_TYPE = os.environ.get("OVLM_COUNTER_FS_TYPE", "")
TEST_MODE = os.environ.get("OVLM_COUNTER_TEST_MODE", "") == "1"
TEST_FS_UUID = os.environ.get("OVLM_COUNTER_TEST_FS_UUID", "")

SERVER_ID_FILES = os.environ.get(
    "OVLM_COUNTER_SERVER_ID_FILES", "/run/cloud-init/instance-data.json:/var/lib/cloud/data/instance-id"
).split(":")

DB_PATH = os.path.join(DATA_DIR, "counter.db")
MARKER_PATH = os.path.join(DATA_DIR, MARKER)


def _unescape(s):
    # /proc/self/mountinfo escapes space, tab, newline, backslash as octal
    return s.replace("\\040", " ").replace("\\011", "\t").replace("\\012", "\n").replace("\\134", "\\")


def mount_info(path):
    """Return (source, fstype) if `path` is exactly a mount point, else None."""
    path = os.path.realpath(path)
    found = None
    with open("/proc/self/mountinfo", encoding="utf-8") as fh:
        for line in fh:
            left, _, right = line.partition(" - ")
            fields = left.split()
            rfields = right.split()
            if len(fields) >= 5 and len(rfields) >= 2 and _unescape(fields[4]) == path:
                found = (rfields[1], rfields[0])  # later lines win (stacked mounts)
    return found


def fs_uuid_of(device):
    """Filesystem UUID of a block device, read from /dev/disk/by-uuid (world readable)."""
    real = os.path.realpath(device)
    base = "/dev/disk/by-uuid"
    try:
        for name in os.listdir(base):
            if os.path.realpath(os.path.join(base, name)) == real:
                return name
    except OSError:
        pass
    return None


def volume_device():
    """The device the expected Cinder volume has in this guest (by-id, 20-char prefix)."""
    if not VOLUME_ID:
        return None
    link = "/dev/disk/by-id/virtio-" + VOLUME_ID[:20]
    return os.path.realpath(link) if os.path.exists(link) else None


def server_id():
    """The cloud-init instance-id of this VM, or None. Read per request: a VM never changes it, but a file that
    appears late (cloud-init still running) must not be cached as 'unknown'."""
    for path in SERVER_ID_FILES:
        try:
            with open(path, encoding="utf-8") as fh:
                text = fh.read(65536)
            if path.endswith(".json"):
                doc = json.loads(text)
                value = (doc.get("v1") or {}).get("instance_id") or doc.get("instance_id")
            else:
                value = text.strip()
        except (OSError, ValueError, AttributeError):
            continue
        if isinstance(value, str) and 0 < len(value) <= 128 and value.isprintable() and " " not in value:
            return value
    return None


def marker_sha256():
    try:
        with open(MARKER_PATH, "rb") as fh:
            return hashlib.sha256(fh.read()).hexdigest()
    except OSError:
        return None


def connect():
    # WAL off and synchronous=FULL: the data must be on the volume when we answer.
    con = sqlite3.connect(DB_PATH, timeout=10)
    con.execute("PRAGMA journal_mode=DELETE")
    con.execute("PRAGMA synchronous=FULL")
    con.execute("CREATE TABLE IF NOT EXISTS counter (id INTEGER PRIMARY KEY CHECK (id = 1), value INTEGER NOT NULL)")
    con.execute("CREATE TABLE IF NOT EXISTS generation (id INTEGER PRIMARY KEY AUTOINCREMENT, hostname TEXT NOT NULL)")
    con.execute("INSERT OR IGNORE INTO counter (id, value) VALUES (1, 0)")
    return con


def data_mount_state():
    """Evaluate the data volume. Returns a dict; 'mounted' is the gate for 503."""
    st = {"mounted": False, "simulated": False, "mount_point": DATA_DIR,
          "device": None, "fs_type": None, "fs_uuid": None, "reason": None}
    if TEST_MODE:
        st.update(simulated=True, mounted=os.path.isdir(DATA_DIR), fs_uuid=TEST_FS_UUID or None,
                  fs_type=FS_TYPE or None, reason=None if os.path.isdir(DATA_DIR) else "data dir missing")
        return st
    info = mount_info(DATA_DIR)
    if info is None:
        st["reason"] = "data dir is not a mount point"
        return st
    device, fs_type = info
    st.update(device=device, fs_type=fs_type, fs_uuid=fs_uuid_of(device))
    expected_dev = volume_device()
    if VOLUME_ID and expected_dev is None:
        st["reason"] = "expected volume not present in /dev/disk/by-id"
    elif VOLUME_ID and os.path.realpath(device) != expected_dev:
        st["reason"] = "mount is not backed by the expected volume"
    elif FS_TYPE and fs_type != FS_TYPE:
        st["reason"] = "unexpected filesystem type"
    elif not st["fs_uuid"]:
        st["reason"] = "filesystem UUID not found"
    else:
        st["mounted"] = True
    return st


def counter_value():
    try:
        con = connect()
        try:
            return con.execute("SELECT value FROM counter WHERE id = 1").fetchone()[0]
        finally:
            con.close()
    except sqlite3.Error:
        return None


class Handler(BaseHTTPRequestHandler):
    server_version = "ovlm-counter/1"

    def log_message(self, fmt, *args):  # one line per request on stderr (journal)
        sys.stderr.write("%s %s\n" % (self.address_string(), fmt % args))

    def _send(self, code, body):
        raw = json.dumps(body, sort_keys=True).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        sid = server_id()
        if sid:
            self.send_header("X-OVLM-Server-Id", sid)
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):
        path = self.path.split("?", 1)[0]
        if path == "/health":
            return self._health()
        if path == "/":
            return self._increment()
        self._send(404, {"error": "not found"})

    def do_POST(self):
        if self.path.split("?", 1)[0] != "/marker":
            return self._send(404, {"error": "not found"})
        state = data_mount_state()
        if not state["mounted"]:
            return self._send(503, {"error": "data volume not available", "reason": state["reason"]})
        token = secrets.token_hex(32).encode()
        tmp = MARKER_PATH + ".tmp"
        with open(tmp, "wb") as fh:
            fh.write(token + b"\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, MARKER_PATH)
        self._send(200, {"marker": MARKER, "marker_sha256": marker_sha256()})

    def _increment(self):
        state = data_mount_state()
        if not state["mounted"]:  # never write to the root disk by mistake
            return self._send(503, {"error": "data volume not available", "reason": state["reason"]})
        con = connect()
        try:
            with con:
                con.execute("UPDATE counter SET value = value + 1 WHERE id = 1")
                value = con.execute("SELECT value FROM counter WHERE id = 1").fetchone()[0]
        finally:
            con.close()
        self._send(200, {"counter": value, "generation": GENERATION, "hostname": socket.gethostname(),
                         "server_id": server_id()})

    def _health(self):
        state = data_mount_state()
        sha = marker_sha256() if state["mounted"] else None
        value = counter_value() if state["mounted"] else None
        ok = state["mounted"] and value is not None
        body = {"ok": ok, "mounted": state["mounted"], "simulated": state["simulated"],
                "mount_point": state["mount_point"], "device": state["device"],
                "fs_type": state["fs_type"], "fs_uuid": state["fs_uuid"], "reason": state["reason"],
                "marker": MARKER, "marker_sha256": sha, "counter": value,
                "generation": GENERATION, "hostname": socket.gethostname(),
                "server_id": server_id()}
        self._send(200 if ok else 503, body)


GENERATION = None


def register_generation():
    """Each start of the service on a VM adds a row: 'generation' only ever grows."""
    global GENERATION
    state = data_mount_state()
    if not state["mounted"]:
        return  # serve /health with 503; do not touch the root disk
    con = connect()
    try:
        with con:
            cur = con.execute("INSERT INTO generation (hostname) VALUES (?)", (socket.gethostname(),))
            GENERATION = cur.lastrowid
    finally:
        con.close()


def main():
    register_generation()
    srv = ThreadingHTTPServer((BIND, PORT), Handler)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
