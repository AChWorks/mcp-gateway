"""Sample only nonsecret aggregate process counters inside the owned PID namespace."""
import json
import os
import pathlib
import sys
import time

stop = pathlib.Path(sys.argv[1])
page_kib = os.sysconf("SC_PAGE_SIZE") // 1024
hz = os.sysconf("SC_CLK_TCK")
seen = {}
cpu = {}
peak = {}
peak_total = 0
samples = 0
start = time.monotonic()
while not stop.exists():
    rss = {}
    for proc in pathlib.Path("/proc").iterdir():
        if not proc.name.isdecimal():
            continue
        try:
            raw = (proc / "stat").read_text()
            end = raw.rindex(")")
            comm = raw[raw.index("(") + 1:end]
            fields = raw[end + 2:].split()
            key = (int(proc.name), int(fields[19]))
            ticks = int(fields[11]) + int(fields[12])
            baseline = seen.get(key, ticks if samples == 0 else 0)
            cpu[comm] = cpu.get(comm, 0) + max(0, ticks - baseline)
            seen[key] = ticks
            rss[comm] = rss.get(comm, 0) + max(0, int(fields[21])) * page_kib
        except (FileNotFoundError, ProcessLookupError, PermissionError, ValueError, IndexError):
            continue
    for comm, size in rss.items():
        peak[comm] = max(peak.get(comm, 0), size)
    peak_total = max(peak_total, sum(rss.values()))
    samples += 1
    time.sleep(0.1)
print(json.dumps({
    "samples": samples, "wall_seconds": round(time.monotonic() - start, 3),
    "logical_cpus": len(os.sched_getaffinity(0)),
    "peak_sampled_aggregate_rss_kib": peak_total,
    "peak_sampled_rss_kib_by_process_name": peak,
    "sampled_cpu_seconds_lower_bound_by_process_name": {
        k: round(v / hz, 3) for k, v in cpu.items()
    },
    "method": "100ms PID namespace samples; RSS double-counts shared memory; short-lived process CPU may be missed; MariaDB outside namespace",
}))
