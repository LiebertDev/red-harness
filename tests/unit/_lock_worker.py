"""Worker for the concurrent lock test. Usage: _lock_worker.py <lock> <start_epoch> <hold_s>
Waits until the start time (all try at once); the result is a single line: WON <pid> | HELD | ERR <name>."""

import sys
import time

from redharness.core.lock import JobLock, LockHeldError


def main() -> None:
    path, start_at, hold = sys.argv[1], float(sys.argv[2]), float(sys.argv[3])
    while time.time() < start_at:
        pass
    lk = JobLock(path)
    try:
        lk.acquire()
    except LockHeldError:
        print("HELD", flush=True)
        return
    except Exception as e:  # noqa: BLE001
        print(f"ERR {type(e).__name__}: {e}", flush=True)
        return
    print("WON", lk.info.token, flush=True)
    time.sleep(hold)
    lk.release()


if __name__ == "__main__":
    main()
