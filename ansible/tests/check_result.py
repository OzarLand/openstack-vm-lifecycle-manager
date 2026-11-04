#!/usr/bin/env python3
"""Assert on an ovlm.result/1 file: check_result.py FILE phase ok|fail [classification]"""
import json
import sys

path, phase, expect = sys.argv[1], sys.argv[2], sys.argv[3]
cls = sys.argv[4] if len(sys.argv) > 4 else None
doc = json.load(open(path, encoding="utf-8"))
errs = []
if doc.get("schema") != "ovlm.result/1":
    errs.append("schema")
if doc.get("phase") != phase:
    errs.append("phase %r" % doc.get("phase"))
if doc.get("ok") is not (expect == "ok"):
    errs.append("ok=%r" % doc.get("ok"))
if cls and doc.get("classification") != cls:
    errs.append("classification=%r" % doc.get("classification"))
for key, typ in (("changed", bool), ("facts", dict), ("checks", list), ("message", str)):
    if not isinstance(doc.get(key), typ):
        errs.append("type of %s" % key)
for c in doc.get("checks", []):
    if not {"name", "ok", "detail"} <= set(c) or not isinstance(c["ok"], bool):
        errs.append("bad check %r" % (c,))
if len(json.dumps(doc)) > 64 * 1024:
    errs.append("larger than 64 KiB")
if errs:
    sys.exit("RESULT CHECK FAILED %s: %s\n%s" % (path, errs, json.dumps(doc, indent=1)))
print("result ok: %s %s -> %s changed=%s" % (phase, expect, doc["classification"], doc["changed"]))
