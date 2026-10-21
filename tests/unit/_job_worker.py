"""Fake long job for the interruption test. Usage: _job_worker.py <job_dir> <n_steps> <step_sleep_s>

Result of step i is {"i": i, "v": i*i}. At the end state.json (state derived from the events) is written.
"""

import os
import sys
import time
from pathlib import Path

from redharness.core.journal import Journal, write_snapshot
from redharness.core.lock import JobLock
from redharness.jobs.stepcache import StepCache

TARGET = "ab" * 32


def reducer(state, ev):
    if ev["type"] == "STEP_FINISHED":
        state = {**state, "done": {**state["done"], ev["payload"]["key"]: ev["payload"]["digest"]}}
    return state


def main() -> None:
    job_dir, n, sleep_s = Path(sys.argv[1]), int(sys.argv[2]), float(sys.argv[3])
    job_dir.mkdir(parents=True, exist_ok=True)
    lock = JobLock(job_dir / "lock")
    stale = lock.acquire()
    journal = Journal(job_dir / "events.jsonl")
    if stale is not None:
        journal.append("LOCK_RECLAIMED", {"pid": stale.pid})
    cache = StepCache(journal, job_dir / "steps")
    # Deterministic kill point: if RH_KILL_AT=k, the k-th step that ACTUALLY runs in this process
    # (STEP_STARTED written, STEP_FINISHED not yet) writes the marker file and waits forever;
    # the test process runs taskkill /F when it sees the marker. Not timing-dependent.
    kill_at = int(os.environ.get("RH_KILL_AT", "0"))
    marker = os.environ.get("RH_MARKER")
    executed = 0
    for i in range(n):
        def work(i=i):
            nonlocal executed
            executed += 1
            if kill_at and executed == kill_at:
                Path(marker).write_text(str(os.getpid()))
                time.sleep(600)
            time.sleep(sleep_s)
            return {"i": i, "v": i * i}
        cache.run("fake", {"i": i}, TARGET, work)
    write_snapshot(job_dir / "state.json", journal.replay(reducer, {"done": {}}), journal)
    journal.close()
    lock.release()


if __name__ == "__main__":
    main()
