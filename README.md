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
├── events.jsonl              # All events
├── all_ips.txt               # IP connection tracker
├── sessions/
│   └── <ip>_0001.txt                 # Connection transcript
├── payloads/
│   └── <ip>_<sec>_<usec>_<id>_<seq>.bin
└── bin/
    └── little.jsonl                  # Parsed payload-link
```

### `little.jsonl`

```json
{
  "scan_ip": "notboob",
  "attack_ip": "notboob",
  "payload_server": "boob",
  "method": "wget",
  "link": "http://boob/hack/arm.bin"
}
```

Fields:

- `scan_ip`: source IP 
- `attack_ip`: same as `scan_ip` (ps its the same shit different name)
- `payload_server`: host/IP extracted from URL in dropped payload
- `method`: (`curl`, `wget`, `ftp`)
- `link`: Its the link.
