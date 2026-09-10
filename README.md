# quantum_readiness_spray.py
Masscan + hand-rolled SSH/RDP/TLS probes to assess post-quantum crypto readiness across a subnet — rates every server Ready/Capable/Planning Required/Legacy/Unknown, outputs a color-coded Excel/CSV report.

# Overview

Subnet-wide post-quantum-readiness sweep across SSH, RDP, and HTTPS, built
the same way as `ssh_vuln_scan.py` / `sslspray.py`: masscan for fast
discovery, then a worker pool for the actual assessment, with the same live
progress bar / logging conventions. Single Python file — scan, parse, CSV,
and `.xlsx` are all in it. This is the original tool in the family; the SSH
and SSL/TLS sibling scripts were both split out of the pattern it
established.

## What it finds

For every SSH (22), RDP (3389), and HTTPS (443) server in scope, whether it
shows real evidence of post-quantum / hybrid cryptography, by comparing what
the server actually offers or negotiates against known PQC/hybrid
identifiers (e.g. OpenSSL's `X25519MLKEM768`-family key-exchange codepoints).
Every host is placed into one of five assessment buckets — **our**
categories for this engagement, not official NIST labels:

| Rating | Meaning |
|---|---|
| 🟢 Ready | Actual evidence of a PQC/hybrid algorithm being negotiated |
| 🟡 Capable | Advertises a PQC/hybrid identifier, but it wasn't what got negotiated under a realistic client preference |
| 🟠 Planning Required | Modern classical crypto only (curve25519/ECDHE, AES-GCM/ChaCha20, SHA-2, TLS 1.2/1.3) — good today, not quantum-resistant |
| 🔴 Legacy | Deprecated/weak crypto detected (SSHv1-era KEX, CBC/RC4/3DES, MD5/SHA-1 MACs, TLS 1.0/1.1, SSLv3) — takes priority over Planning Required |
| ⚪ Unknown | No response, connection refused, or an unparseable result |

**Capable is expected to be reliable for SSH but rare-to-never for RDP/
HTTPS** — SSH's `SSH_MSG_KEXINIT` always discloses the server's full
algorithm list regardless of what gets negotiated, but TLS 1.3 servers only
reveal what they actually select. A "Planning Required" RDP/HTTPS host may
still run PQC-capable software this scan simply couldn't prove.

## Why hand-rolled probes instead of an off-the-shelf tool

**SSH** prefers `ssh-audit` (more battle-tested) if it's on PATH, falling
back per-host to a hand-rolled raw-socket probe — connect, exchange
identification strings, send our own `SSH_MSG_KEXINIT`, capture the
server's — if `ssh-audit` is missing or its output can't be parsed. Either
way the connection closes immediately after the algorithm exchange, well
before any `SSH_MSG_USERAUTH_*` message would be sent.

**RDP** has no off-the-shelf option: it requires its own X.224 Connection
Request/Confirm negotiation on the raw TCP stream *before* the server will
speak TLS at all, and no existing TLS scanner (sslscan/sslyze/openssl
s_client/etc.) knows how to send that RDP-specific prefix. The X.224 step
and a hand-built TLS 1.3 `ClientHello` that follows it are both hand-rolled
here, on the same socket, in sequence — key material is a single ephemeral
X25519 keypair (via the `cryptography` package) for the `key_share`
extension; no ML-KEM/Kyber implementation is needed client-side, since PQC
hybrid-group support is detected via `HelloRetryRequest`, not by completing
a real PQC handshake.

**HTTPS** reuses the exact same hand-built TLS 1.3 `ClientHello`/response
parsing directly (no X.224-style prefix needed), including the already-
resolved hostname as SNI when available. It could be pointed at a real TLS
tool instead, but currently isn't, purely to keep one shared code path for
every TLS-based protocol in this script.

## Why two phases

The configured scope (`SUBNETS` below) includes a `/8`. Pointing per-host
probes at that much address space without narrowing it first would take
far too long. **Phase 1** uses masscan — a stateless SYN scanner — to find
which hosts across all configured subnets have TCP/22, TCP/3389, or TCP/443
open, in a fraction of the time. **Phase 2** then only touches real hosts,
one worker per host/port pair, running the protocol-appropriate probe above.

## Scope

```python
SUBNETS: List[str] = [
    "156.141.0.0/16",
    "156.140.0.0/16",
    "146.208.0.0/16",
    "141.184.0.0/16",
    "141.183.0.0/16",
    # "141.121.0.0/16",
    "192.168.0.0/16",
    "172.16.0.0/12",
    "10.0.0.0/8",
]
```

Edit this list in the script to change scope — same convention as the
sibling scripts.

## Requirements

- `masscan` on PATH (unless `--skip-masscan` with a valid `--masscan-output-file`) — needs root/administrator to run
- `ssh-audit` on PATH — optional but recommended, used as the primary SSH algorithm-collection method; the script is fully functional without it (falls back to the raw-socket probe)
- `cryptography` (Python package) — used only to generate one ephemeral X25519 keypair for the RDP/HTTPS `ClientHello`. Without it, RDP and HTTPS hosts are reported as Unknown; SSH is unaffected.
- `openpyxl` — only for the `.xlsx` step. If missing, the run degrades to CSV-only instead of failing.
- Python 3.8+

```bash
pip install openpyxl cryptography
```

## Usage

```bash
sudo python quantum_readiness_spray.py
```

Common options:

| Flag | Default | Purpose |
|---|---|---|
| `--workers` | `30` | Concurrent probes in Phase 2. Higher than the SSH/TLS sibling scripts' worker counts — each unit of work here is a handful of raw socket reads/writes, not a full external process, so it's much cheaper per worker. |
| `--rate` | `25000` | masscan packets/sec |
| `--timeout` | `4.0` | Per-probe socket timeout, in seconds |
| `--retries` | `1` | Retries per host if a scan comes back empty (covers a transient miss) |
| `--output-dir` | script's own directory | Where the log/CSV/xlsx are written |
| `--ssh-audit-path` | `ssh-audit` | Path to the ssh-audit executable |
| `--interface` | *(none)* | Passed to masscan's `-e` |
| `--skip-masscan` + `--masscan-output-file` | — | Reuse a previous masscan run instead of re-scanning |

Resume from a previous masscan run (e.g. discovery already done, iterating on Phase 2 only):

```bash
python quantum_readiness_spray.py --skip-masscan --masscan-output-file .masscan_output_2026-09-10.txt
```

Unlike the SSH/SSL sibling scripts, this one doesn't have `--keep-temp`,
`--no-xlsx`, `--csv-out`/`--xlsx-out`, or `--from-csv` — it's the original,
simpler tool the pattern started from; nothing here reads back its own CSV.

## Output

Everything is timestamped and written to `--output-dir`:

- `quantum_readiness_spray_<date>.log` — full run log (DEBUG-level to file, INFO-level to console)
- `quantum_readiness_spray_<date>.csv` — wide format, one row per assessed service (all three protocols combined)
- `quantum_readiness_spray_<date>.xlsx` — Overview + SSH + RDP + HTTPS sheets
- `.masscan_output_<date>.txt` — raw masscan hit list (hidden file, kept so `--skip-masscan` can reuse it)

### `quantum_readiness_spray_<date>.csv`

```
Timestamp,IP Address,Hostname,Subnet Range,Port,Protocol,Service,QC Rating,Evidence,Details,Algorithm,Algorithm Description,Scan Status
```

`Scan Status` is deliberately the last column and `Algorithm`/`Algorithm
Description` are the two rightmost columns before it — an explicit layout
choice made early in this project, kept as new columns were added
elsewhere in the sibling scripts (always appended at the very end, never
inserted here).

### `quantum_readiness_spray_<date>.xlsx`

- **Overview** — legend explaining each of the five ratings, methodology
  notes (how SSH vs. RDP/HTTPS ratings are derived, and why "Capable" means
  different things for each), and a per-protocol summary: total servers
  found, a Rating/Count/% breakdown, and a one-line "X% of Y servers found
  are quantum ready" callout. The headline ready percentage counts **Ready
  only** — Capable and Planning Required are broken out separately and are
  not included in it.
- **SSH / RDP / HTTPS** — one sheet per protocol, same column layout as the
  CSV, with the QC Rating column colored per rating and long text columns
  (Evidence, Details, Algorithm Description) wrapped.

## Architecture notes

**Phase 1 (masscan)** is the original version of what `ssh_vuln_scan.py` and
`sslspray.py` later ported near-verbatim — same live progress bar, same
`-oL` list-output parsing, same dedup-by-key approach, generalized here to
three ports (`T:22,3389,443`) instead of one.

**Phase 2** is a worker pool of raw Python socket probes (not external
processes) — `probe_ssh`, `probe_rdp`, and `probe_https` each open their own
socket directly, since no combination of off-the-shelf tools covers this
scan's three-protocol, no-off-the-shelf-RDP-option shape in one engine the
way nmap+NSE does for the sibling scripts.

**Retry logic** matches the sibling scripts' "only retry a `No
Response`-shaped outcome" pattern — this is the tool the pattern was
originally built for.

## Limitations

**SSH ratings assume a realistic modern-client preference order** (RFC 4253
negotiation: first client-preferred algorithm present in the server's list
wins), with legacy algorithms placed at the very bottom purely so a
legacy-only server still yields a determinate classification instead of "no
data" — a real hardened client would omit them entirely and simply refuse
to connect.

**RDP/HTTPS quantum-readiness detection is necessarily best-effort.** Unlike
SSH's KEXINIT, TLS doesn't broadcast an unused capability list, so "Capable"
can't be reliably proven for RDP/HTTPS the way it can for SSH — see the
Overview sheet's own methodology notes.

**No certificate validation, ever, on any protocol** — this tool stops at
the ServerHello/HelloRetryRequest/Alert (TLS-based protocols) or after
reading the server's KEXINIT (SSH), well before anything resembling a
completed, trustable connection.

**Reverse DNS depends on corporate DNS infrastructure**; failures resolve
to `"UNKNOWN"` and do not stop the scan.

**Assesses only SSH, RDP, and HTTPS** — no other protocol is in scope for
this tool. (SSL/TLS protocol-version legacy detection more broadly — SSLv2/
SSLv3/TLS1.0-1.3 support, independent of PQC readiness — was split out into
the separate `sslspray.py` sibling instead of being added here.)

**Ctrl+C behavior**: first interrupt finishes in-flight work and writes
partial reports; second interrupt force-exits.
