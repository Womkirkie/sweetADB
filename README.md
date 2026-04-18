# sweetADB 🍯
> Lightweight Android Debug Bridge (ADB) honeypot

## What It Does

- Dumps raw payloads from attackers to disk
- Logs every event to structured JSONL + per-IP session files
---

## Quickstart

```bash
git clone https://github.com/Womkirkie/sweetADB
cd sweetADB
gcc -O2 -pthread -o sweetadb sweetadb.c
./sweetadb           # listens on default port 5555
./sweetadb 5556      # custom port
```

Requires: `gcc`, `pthreads`, Linux

---

## Output Structure

```
mimic/
├── events.jsonl              # All events, one JSON object per line
├── all_ips.txt               # IP connection frequency tracker
├── sessions/
│   └── <ip>_0001.txt         # Full session transcript per connection
└── payloads/
    └── <ip>_<ts>_<id>.bin    # Raw binary payloads (file pushes, exploits, etc.)
```
