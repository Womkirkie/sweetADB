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
│   └── <ip>_0001.txt                 # Per-connection transcript
├── payloads/
│   └── <ip>_<sec>_<usec>_<id>_<seq>.bin
│                                    # Raw binary payload chunks when sent
└── bin/
    └── little.jsonl                  # Parsed payload-link
```

### `little.jsonl` schema

One JSON object per detected payload URL:

```json
{
  "src_ip": "45.135.194.83",
  "payload_server": "1.1.1.1",
  "method": "wget",
  "link": "http://1.1.1.1/hack/arm.bin"
}
```

Fields:

- `src_ip`: source IP
- `payload_server`: host/IP extracted from URL in dropped payload
- `method`: (`curl`, `wget`, `ftp`)
- `link`: Its the link.
