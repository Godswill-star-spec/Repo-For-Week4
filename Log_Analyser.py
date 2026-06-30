#!/usr/bin/env python3

import re
import sys
from collections import defaultdict

LOGFILE = "payliteNG_auth.log"

FAILED_RE = re.compile(r"^(\w+ \d+ [\d:]+) sshd: Failed password for (\S+) from (\S+) port (\d+)")
ACCEPTED_RE = re.compile(r"^(\w+ \d+ [\d:]+) sshd: Accepted password for (\S+) from (\S+) port (\d+)")
OPENED_RE = re.compile(r"^(\w+ \d+ [\d:]+) sshd: session opened for user (\S+) from (\S+)")
CLOSED_RE = re.compile(r"^(\w+ \d+ [\d:]+) sshd: session closed for user (\S+) from (\S+)")
SUDO_RE = re.compile(r"^(\w+ \d+ [\d:]+) sudo: (\S+) : TTY=(\S+) ; COMMAND=(.+)$")


def load_lines(path):
    try:
        with open(path, "r") as f:
            return [line.rstrip("\n") for line in f if line.strip()]
    except FileNotFoundError:
        print(f"Log file not found: {path}")
        sys.exit(1)


def analyse(lines):
    failed_attempts = []
    accepted_logins = []
    sessions_opened = []
    sessions_closed = []
    sudo_events = []

    for line in lines:
        m = FAILED_RE.match(line)
        if m:
            failed_attempts.append({"time": m.group(1), "user": m.group(2), "ip": m.group(3)})
            continue
        m = ACCEPTED_RE.match(line)
        if m:
            accepted_logins.append({"time": m.group(1), "user": m.group(2), "ip": m.group(3)})
            continue
        m = OPENED_RE.match(line)
        if m:
            sessions_opened.append({"time": m.group(1), "user": m.group(2), "ip": m.group(3)})
            continue
        m = CLOSED_RE.match(line)
        if m:
            sessions_closed.append({"time": m.group(1), "user": m.group(2), "ip": m.group(3)})
            continue
        m = SUDO_RE.match(line)
        if m:
            sudo_events.append({"time": m.group(1), "user": m.group(2), "tty": m.group(3), "command": m.group(4)})
            continue

    return failed_attempts, accepted_logins, sessions_opened, sessions_closed, sudo_events


def build_timeline(failed, accepted, opened, closed, sudo):
    timeline = []
    for f in failed:
        timeline.append((f["time"], f"FAILED login: {f['user']} from {f['ip']}"))
    for a in accepted:
        timeline.append((a["time"], f"ACCEPTED login: {a['user']} from {a['ip']}"))
    for o in opened:
        timeline.append((o["time"], f"SESSION OPENED: {o['user']} from {o['ip']}"))
    for c in closed:
        timeline.append((c["time"], f"SESSION CLOSED: {c['user']} from {c['ip']}"))
    for s in sudo:
        timeline.append((s["time"], f"SUDO: {s['user']} ran {s['command']} on {s['tty']}"))
    timeline.sort(key=lambda x: x[0])
    return timeline


def ip_breakdown(failed):
    counts = defaultdict(int)
    for f in failed:
        counts[(f["user"], f["ip"])] += 1
    return counts


def flag_breach_files(accepted, sudo):
    breach_ips = {a["ip"] for a in accepted}
    flags = []
    for s in sudo:
        if s["command"].strip() == "/bin/bash":
            flags.append(s)
    return breach_ips, flags


def main():
    lines = load_lines(LOGFILE)
    failed, accepted, opened, closed, sudo = analyse(lines)

    print("=== SUMMARY ===")
    print(f"Total log lines parsed   : {len(lines)}")
    print(f"Failed login attempts    : {len(failed)}")
    print(f"Successful logins        : {len(accepted)}")
    print(f"Sessions opened          : {len(opened)}")
    print(f"Sessions closed          : {len(closed)}")
    print(f"Sudo events              : {len(sudo)}")
    print()

    print("=== FAILED ATTEMPTS BY USER AND SOURCE IP ===")
    for (user, ip), count in sorted(ip_breakdown(failed).items()):
        print(f"{count:>3}  {user:<8} {ip}")
    print()

    print("=== SUCCESSFUL LOGINS ===")
    for a in accepted:
        print(f"{a['time']}  {a['user']:<8} from {a['ip']}")
    print()

    print("=== SUDO EVENTS ===")
    for s in sudo:
        print(f"{s['time']}  {s['user']:<8} ran {s['command']}")
    print()

    breach_ips, shell_flags = flag_breach_files(accepted, sudo)
    print("=== SOURCE IPs THAT SUCCEEDED ===")
    for ip in sorted(breach_ips):
        print(ip)
    print()

    print("=== FLAGGED: SHELL SPAWNED VIA SUDO ===")
    if shell_flags:
        for s in shell_flags:
            print(f"{s['time']}  {s['user']} ran {s['command']} on {s['tty']} - review required")
    else:
        print("None found.")
    print()

    print("=== FULL TIMELINE ===")
    timeline = build_timeline(failed, accepted, opened, closed, sudo)
    for time, event in timeline:
        print(f"{time}  {event}")


if __name__ == "__main__":
    main()
