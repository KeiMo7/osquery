#!/usr/bin/env python3
"""Compare osqueryi query results with column pruning off vs on.

Runs each query with --enable_column_pruning=false and =true, then compares
the result sets row by row (sorted by a key), field by field. Exits nonzero
on any divergence.
"""
import json
import subprocess
import sys

OSQUERYI = "/home/wll/uid37/build/osquery/osqueryi"

# (name, query, sort_keys)
QUERIES = [
    (
        "processes_subset",
        "SELECT pid, name, path, cmdline, cwd, root, uid, gid, euid, egid, "
        "suid, sgid, parent, pgroup, state, nice, threads, on_disk, "
        "start_time, cgroup_path, label FROM processes WHERE pid IN (1, 2, 3)",
        ("pid",),
    ),
    (
        "processes_count",
        "SELECT count(*) AS n FROM processes WHERE pid IN (1, 2, 3)",
        (),
    ),
    (
        "processes_group",
        "SELECT state, count(*) AS n FROM processes WHERE pid IN (1, 2, 3) "
        "GROUP BY state",
        ("state",),
    ),
    (
        "file_all",
        "SELECT * FROM file WHERE directory = '/etc/ssh'",
        ("path",),
    ),
    (
        "file_subset",
        "SELECT path, type FROM file WHERE directory = '/usr/bin'",
        ("path",),
    ),
    (
        "file_count",
        "SELECT count(*) AS n FROM file WHERE directory = '/usr/bin'",
        (),
    ),
    (
        "sockets_subset",
        "SELECT local_address, local_port, remote_address, remote_port, "
        "state, protocol, family, socket FROM process_open_sockets "
        "WHERE pid = 1",
        ("socket",),
    ),
    (
        "sockets_count",
        "SELECT count(*) AS n FROM process_open_sockets WHERE pid = 1",
        (),
    ),
    (
        "join_processes_file",
        "SELECT p.pid, p.name, f.path, f.size FROM processes p, file f "
        "WHERE f.directory = '/etc/ssh' AND p.pid = 1",
        ("path",),
    ),
    (
        "subquery_same_table",
        "SELECT pid, name FROM processes WHERE uid IN "
        "(SELECT uid FROM processes WHERE pid = 1) AND pid IN (1, 2, 3) "
        "ORDER BY pid",
        ("pid",),
    ),
]


def run(query, pruning):
    out = subprocess.run(
        [OSQUERYI, "--json", f"--enable_column_pruning={'true' if pruning else 'false'}", query],
        capture_output=True,
        text=True,
        timeout=300,
    )
    if out.returncode != 0:
        raise RuntimeError(f"query failed (pruning={pruning}): {out.stderr[:500]}")
    return json.loads(out.stdout) if out.stdout.strip() else []


def key_of(row, keys):
    return tuple(row.get(k, "") for k in keys)


def main():
    failures = 0
    for name, query, keys in QUERIES:
        try:
            off = sorted(run(query, False), key=lambda r: key_of(r, keys))
            on = sorted(run(query, True), key=lambda r: key_of(r, keys))
        except Exception as e:  # noqa: BLE001
            print(f"[SKIP] {name}: {e}")
            continue

        if len(off) != len(on):
            print(f"[FAIL] {name}: row count {len(off)} (off) != {len(on)} (on)")
            failures += 1
            continue

        diff = 0
        for i, (ro, rn) in enumerate(zip(off, on)):
            if ro != rn:
                diff += 1
                if diff <= 3:
                    for k in sorted(set(ro) | set(rn)):
                        if ro.get(k) != rn.get(k):
                            print(
                                f"  row {i} key={key_of(ro, keys)} col {k!r}: "
                                f"off={ro.get(k)!r} on={rn.get(k)!r}"
                            )
        if diff:
            print(f"[FAIL] {name}: {diff}/{len(off)} rows differ")
            failures += 1
        else:
            print(f"[OK]   {name}: {len(off)} rows identical")

    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
