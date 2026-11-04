"""Identity contract of the reference workload (docs/automation-contract.md section 3.6.1). Standard library only.

Runs the real server in test mode (no mount) with a fake cloud-init instance-id file, and checks that the
`X-OVLM-Server-Id` header and the JSON `server_id` carry it, on every endpoint, and that nothing is claimed when
the id is unknown.  Run: python3 -I ansible/tests/test_identity.py
"""
import http.client
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import time
import unittest

APP = pathlib.Path(__file__).resolve().parent.parent / "roles/counter_app/files/ovlm_counter.py"
PORT = 18089


def start(env_extra, data_dir):
    env = {"PATH": os.environ.get("PATH", ""), "OVLM_COUNTER_TEST_MODE": "1", "OVLM_COUNTER_TEST_FS_UUID": "u-1",
           "OVLM_COUNTER_DATA_DIR": data_dir, "OVLM_COUNTER_PORT": str(PORT), "OVLM_COUNTER_BIND": "127.0.0.1",
           **env_extra}
    proc = subprocess.Popen([sys.executable, "-I", str(APP)], env=env, stderr=subprocess.DEVNULL)
    for _ in range(50):
        try:
            get("/health")
            return proc
        except OSError:
            time.sleep(0.1)
    proc.kill()
    raise RuntimeError("server did not start")


def get(path, method="GET"):
    c = http.client.HTTPConnection("127.0.0.1", PORT, timeout=5)
    c.request(method, path)
    r = c.getresponse()
    return r.status, r.getheader("X-OVLM-Server-Id"), json.loads(r.read())


class Identity(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = pathlib.Path(self.tmp.name)
        (self.dir / "data").mkdir()

    def serve(self, files):
        proc = start({"OVLM_COUNTER_SERVER_ID_FILES": ":".join(map(str, files))}, str(self.dir / "data"))
        self.addCleanup(proc.wait)
        self.addCleanup(proc.terminate)

    def test_header_and_json_from_instance_data_json(self):
        f = self.dir / "instance-data.json"
        f.write_text(json.dumps({"v1": {"instance_id": "11111111-2222-3333-4444-555555555555"}}))
        self.serve([f])
        for path in ("/health", "/", "/nope"):
            status, header, body = get(path)
            self.assertEqual(header, "11111111-2222-3333-4444-555555555555", path)
        status, header, body = get("/health")
        self.assertEqual(status, 200)
        self.assertEqual(body["server_id"], header)

    def test_falls_back_to_the_plain_instance_id_file(self):
        f = self.dir / "instance-id"
        f.write_text("aaaaaaaa-0000-0000-0000-000000000000\n")
        self.serve([self.dir / "missing.json", f])
        status, header, body = get("/health")
        self.assertEqual((header, body["server_id"]), ("aaaaaaaa-0000-0000-0000-000000000000",) * 2)

    def test_unknown_id_is_not_invented(self):
        self.serve([self.dir / "missing.json", self.dir / "missing"])
        status, header, body = get("/health")
        self.assertIsNone(header)
        self.assertIsNone(body["server_id"])  # the external probe must fail, never guess from the hostname

    def test_garbage_ids_are_ignored(self):
        f = self.dir / "instance-id"
        f.write_text("has space\n")
        self.serve([f])
        self.assertIsNone(get("/health")[1])

    def test_503_still_carries_identity(self):
        f = self.dir / "instance-id"
        f.write_text("bbbbbbbb\n")
        proc = start({"OVLM_COUNTER_SERVER_ID_FILES": str(f)}, str(self.dir / "absent"))  # data dir missing -> 503
        self.addCleanup(proc.wait)
        self.addCleanup(proc.terminate)
        status, header, body = get("/health")
        self.assertEqual((status, header, body["server_id"]), (503, "bbbbbbbb", "bbbbbbbb"))


if __name__ == "__main__":
    unittest.main()
