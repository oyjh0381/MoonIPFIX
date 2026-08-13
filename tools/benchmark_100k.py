#!/usr/bin/env python3
"""Reproducible 100,000-record offline decode benchmark; no CI time gate."""
import json, platform, subprocess, tempfile, time
from pathlib import Path
ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = bytes.fromhex("000a001c00000000000000000000002a0002000c01000001000a0004")
def message(sequence: int, count: int) -> bytes:
    payload = b"\x00\x00\x00\x01" * count
    length = 20 + len(payload)
    return (b"\x00\x0a" + length.to_bytes(2,"big") + b"\x00\x00\x00\x00" + sequence.to_bytes(4,"big") + b"\x00\x00\x00\x2a" + b"\x01\x00" + (4+len(payload)).to_bytes(2,"big") + payload)
def main():
    counts=[16000]*6+[4000]; stream=TEMPLATE+b"".join(message(i*16000,n) for i,n in enumerate(counts))
    with tempfile.TemporaryDirectory(prefix="moonipfix-bench-") as d:
        p=Path(d,"100k.ipfix"); p.write_bytes(stream)
        start=time.perf_counter(); result=subprocess.run(["moon","run","cmd/moonipfix","--target","native","--","stats",str(p)],cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.PIPE,check=True); elapsed=time.perf_counter()-start
    final=json.loads(result.stdout.decode().splitlines()[-1])
    report={"environment":platform.platform(),"python":platform.python_version(),"input_bytes":len(stream),"records":final["record_count"],"fields":final["field_count"],"messages":final["message_count"],"elapsed_seconds":round(elapsed,6),"records_per_second":round(final["record_count"]/elapsed,2),"retained_templates":1}
    assert report["records"]==100000 and report["fields"]==100000
    print(json.dumps(report,ensure_ascii=False,sort_keys=True))
if __name__=="__main__": main()
