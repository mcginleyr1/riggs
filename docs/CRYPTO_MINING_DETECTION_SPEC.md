# Crypto Mining Detection (T1496) — Design Spec

## Overview

Detect unauthorized cryptocurrency mining on endpoints by correlating network
connections to known mining infrastructure with process behavior indicators.

**MITRE ATT&CK:** T1496 — Resource Hijacking  
**BehaviorPattern:** `CryptoMining`  
**Severity:** Medium  
**Confidence:** 0.65 (Suspicious) → 0.80 (Malicious)

---

## Detection Architecture

Crypto mining detection uses a **multi-signal approach** to reduce false positives.
No single signal is definitive on its own — we look for **combinations**:

```
┌─────────────────────────────────────────────────────────┐
│                  Crypto Mining Detector                   │
│                                                         │
│  Signal 1: Network → Mining Pool                        │
│  Signal 2: DNS → Mining Domain                          │
│  Signal 3: Process → High CPU + Mining Network          │
│  Signal 4: Process → Known Miner Binary/Name            │
│                                                         │
│  Decision: 2+ signals → Malicious                       │
│            1 signal + strong indicator → Suspicious      │
└─────────────────────────────────────────────────────────┘
```

---

## Signal Definitions

### Signal 1: Outbound Connections to Mining Pool Ports

**Trigger:** Outbound network connection to known mining ports.

**Ports:**
| Port | Protocol | Notes |
|---|---|---|
| 3333 | TCP | Stratum (Bitcoin, Ethereum Classic) |
| 443 | TCP | Stratum over SSL/TLS (common for pool proxies) |
| 4433 | TCP | Stratum (alternative) |
| 4444 | TCP | Stratum (F2Pool, AntPool) |
| 5555 | TCP | Stratum (SlushPool) |
| 6666 | TCP | Stratum (F2Pool) |
| 7777 | TCP | Stratum (common default) |
| 8333 | TCP | Bitcoin P2P (may indicate pool connection) |
| 8888 | TCP | Stratum (SlushPool alt) |
| 9999 | TCP | Stratum (F2Pool alt) |
| 14444 | TCP | Stratum (Ethermine) |
| 14445 | TCP | Stratum (Ethermine SSL) |
| 45700 | TCP | Stratum (NiceHash) |
| 55555 | TCP | Stratum (NiceHash v2) |

**Implementation:**
```rust
const MINING_PORTS: &[u16] = &[
    3333, 443, 4433, 4444, 5555, 6666, 7777, 8333,
    8888, 9999, 14444, 14445, 45700, 55555,
];
```

**Threshold:** Single connection is suspicious but not conclusive.
Requires Signal 2 or 3 for Malicious verdict.

---

### Signal 2: DNS Queries to Mining Pool Domains

**Trigger:** DNS query resolving to known mining pool domains.

**Known Mining Pool Domains (partial list):**
```
# Bitcoin
btc.com
chia-blockchain.com
coinbase.com
coinbasepro.com
f2pool.com
genuinevesta.com
hashvault.pro
hashflare.io
nicehash.com
pool.bitcoin.com
slushpool.com
wafflepool.com

# Ethereum (pre-merge) / Ethereum Classic
ethermine.org
ethpool.org
2miners.com
herominers.com
miningpoolhub.com
navpool.com
pool.ethermine.org
solo.ethermine.org

# General / Multi-coin
coinhive.com (defunct, but historical indicator)
minexmr.com
coinpot.co
miningrigrentals.com
poolin.com
antpool.com
pool.antpool.com
pool.btc.com
```

**Implementation Strategy:**
- Maintain a curated list of 50-100 known mining pool domains
- Use case-insensitive prefix matching (e.g., `*.ethermine.org`)
- Check against DNS query field AND DNS response field
- Bloom filter for fast lookup (similar to IOC matching in `riggs-rules`)

**Threshold:** Single DNS query is suspicious.
Requires Signal 1 or 3 for Malicious verdict.

---

### Signal 3: High CPU Process + Mining Network Connection

**Trigger:** Process with sustained high CPU usage (inferred from exec frequency)
connected to mining infrastructure.

**CPU Heuristic (since we lack direct CPU metrics):**
- **Rapid exec events:** Process spawning child processes rapidly (fork/exec storms)
- **Long-running process with no file activity:** Process that exists for hours
  with no file I/O but constant network connections (compute-bound)
- **Process name patterns:** `xmrig`, `cpuminer`, `minerd`, `ethminer`,
  `ethdcrminer`, `ccminer`, `bfgminer`, `cgminer`, `lolminers`, `t-rex`,
  `nvcc`, `nvidia-smi` (GPU mining indicators)

**Implementation:**
```rust
// Mining-related process names
const MINER_NAMES: &[&str] = &[
    "xmrig", "cpuminer", "minerd", "ethminer", "ethdcrminer",
    "ccminer", "bfgminer", "cgminer", "lolminers", "t-rex",
    "mining", "hashcash", "cryptonight", "randomx",
];

// High CPU indicator: process with many child processes in short time
const CHILD_PROCESS_THRESHOLD: usize = 10;
const CHILD_PROCESS_WINDOW_SECS: i64 = 60;
```

**Threshold:** Requires Signal 1 (mining port connection) for Malicious verdict.
Single signal alone → Suspicious.

---

### Signal 4: Known Miner Binary Execution

**Trigger:** Process execution matching known miner binaries or paths.

**Known Miner Paths:**
```
/usr/local/bin/xmrig
/tmp/xmrig
/tmp/miner
/tmp/cpuminer
/var/tmp/xmrig
/home/*/xmrig
/home/*/mining
/opt/miners/
.solo/mining
```

**Implementation:**
```rust
const MINER_PATHS: &[&str] = &[
    "/usr/local/bin/xmrig",
    "/tmp/xmrig",
    "/tmp/miner",
    "/tmp/cpuminer",
    "/var/tmp/xmrig",
    "/home/",
    "/opt/miners/",
    "/.solo/mining",
];
```

**Threshold:** Single signal → Suspicious.
Combined with network connection → Malicious.

---

## Scoring Model

| Signals Detected | Verdict | Confidence |
|---|---|---|
| 1 weak signal (port only) | Suspicious | 0.40 |
| 1 strong signal (miner binary) | Suspicious | 0.50 |
| 2 signals (any combination) | Malicious | 0.75 |
| 3+ signals | Malicious | 0.85 |
| Miner binary + mining port | Malicious | 0.90 |

---

## False Positive Mitigation

### Legitimate Mining Software
Some organizations deploy mining software legitimately (e.g., for internal
benchmarking). Mitigation:
- **Allowlist by user:** Admin user running known miner binary = allowed
- **Allowlist by path:** `/opt/miners/` = allowed path
- **DLP integration:** Cross-reference with DLP policy exclusions

### Cloud/CDN Ports
Port 443 is used by both mining pools and legitimate services. Mitigation:
- **Domain correlation:** Only flag 443 connections if DNS query matches
  known mining domain
- **IP reputation:** Check against threat intel feeds (VirusTotal, AbuseIPDB)

### GPU Driver Activity
`nvidia-smi` and GPU drivers may connect to NVIDIA servers on various ports.
Mitigation:
- **Process name allowlist:** `nvidia-smi`, `nvml`, `nvcuda` = allowed
- **Connection context:** Only flag if combined with mining domain DNS queries

---

## Implementation Plan

### Phase 1: Network + DNS Signals (Quick Win)
1. Define `MINING_PORTS` constant list
2. Define `MINING_DOMAINS` curated list (50-100 domains)
3. Implement `check_mining_ports()` — scan NetworkEvents for mining ports
4. Implement `check_mining_domains()` — scan DnsEvents for mining domains
5. Add `is_mining_domain()` helper with wildcard matching
6. Unit tests for both signals

### Phase 2: Process Signals
1. Define `MINER_NAMES` list
2. Define `MINER_PATHS` list
3. Implement `check_miner_names()` — scan ProcessContext for miner names
4. Implement `check_miner_paths()` — scan ProcessContext paths for miner paths
5. Implement `check_high_cpu_heuristic()` — fork/exec storm detection
6. Unit tests for all process signals

### Phase 3: Scoring + Integration
1. Implement multi-signal scoring in `check_crypto_mining()`
2. Update `BehaviorPattern::CryptoMining` severity mapping if needed
3. Integrate with verdict merger in `riggs-engine`
4. End-to-end test: simulated mining scenario

### Phase 4: Tuning + Allowlists
1. Add user/path allowlist support
2. Integrate with threat intel for IP reputation
3. Add configurable thresholds via config
4. Performance benchmarking

---

## Testing Strategy

### Unit Tests
- Mining port connection detected (multiple ports)
- Mining domain DNS query detected (exact + wildcard)
- Miner binary name detected
- Miner path detected
- High CPU heuristic detected (fork/exec storm)
- No false positive: normal HTTPS on port 443
- No false positive: normal DNS queries
- No false positive: nvidia-smi process
- Multi-signal scoring: 2 signals → Malicious, 1 signal → Suspicious

### Integration Tests
- Simulated mining scenario: DNS → network → process execution
- Simulated legitimate mining with allowlist bypass
- Simulated mining pool connection without DNS (port-only detection)

---

## Configuration

Future config options (not in Phase 1):

```toml
[behavioral.crypto_mining]
enabled = true
port_threshold = 2          # connections to mining ports before alert
domain_threshold = 1        # DNS queries to mining domains before alert
score_threshold = 0.65      # verdict confidence threshold
allowlist_users = ["admin"]
allowlist_paths = ["/opt/miners/"]
```

---

## References

- MITRE ATT&CK T1496: https://attack.mitre.org/techniques/T1496/
- Stratum Protocol: https://en.wikipedia.org/wiki/Stratum_mining_protocol
- Known Mining Pools: https://www.coinwarz.com/mining-pools/
- XMRig GitHub: https://github.com/xmrig/xmrig
- NiceHash Mining Ports: https://www.nicehash.com/port-check
