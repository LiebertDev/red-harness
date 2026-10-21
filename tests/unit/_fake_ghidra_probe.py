"""Mimics LaunchSupport -jdk_home. FAKE_PROBE=ok|fail|nopath."""
import os
import sys

mode = os.environ.get("FAKE_PROBE", "ok")
if mode == "fail":
    print("ERROR: JDK 21 not found", file=sys.stderr)
    sys.exit(1)
print("Picked up JAVA_TOOL_OPTIONS: x")
print(sys.prefix if mode == "ok" else r"Z:\missing\jdk")
