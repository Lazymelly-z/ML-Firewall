
# AI-Firewall — ML-Powered Stateful Firewall in C++ & Python

A stateful, zone-aware network firewall that uses a trained XGBoost machine learning model to classify and block suspicious traffic in real time. Built with WinDivert for packet interception and ZeroMQ for inter-process communication between the C++ firewall engine and a Python ML inference server.

---

## Overview
Traditional firewalls like [Firewall_V1](https://github.com/Lazymelly-z/Firewall_V1) and [Firewall_V2](https://github.com/Lazymelly-z/Firewall_V2) rely on static rules that can't adapt on the fly. This project combines rule-based zone filtering like the one in [Firewall_V2](https://github.com/Lazymelly-z/Firewall_V2) with a machine learning model trained on the CIC-IDS2017 dataset to detect suspicious traffic behaviour. Blocking threats that static rules would miss. 

---

## How it works
```
   Incoming/Outgoing Packet
        ↓
   WinDivert (kernel-level packet intercept)
        ↓
   Parse IPv4 / IPv6 / TCP / UDP headers
        ↓
   SYN flood detection → SYN cookie validation
   (half-open connections capped at 15 per IP)
        ↓
   IP Blacklist check → BLOCKED zone? → Drop
        ↓
   Connection Table lookup → Established session? → Pass
        ↓
   Zone classification (LOCAL / LOOPBACK / PUBLIC / BLOCKED)
        ↓
   Static rule evaluation (zone + port + protocol)
        ↓
   [If PASS] → Send to Python AI over ZeroMQ (port 5555)
        ↓
   Python receives JSON → builds feature vector → XGBoost predicts
        ↓
   "PASS" or "DROP" returned to C++
        ↓
   PASS → TrackConnection → Forward    |    DROP → Packet dropped
        ↓
   Every 50 packets: evict idle/stale connections from table
```
---

## Architecture
The firewall is split into two processes that communicate over a local ZeroMQ REQ/REP socket:
 Component | Language | Role |
|---|---|---|
| `main.cpp` | C++ | Packet capture, stateful inspection, zone rules, SYN protection |
| `ai.py` | Python | Receives packet metadata, runs XGBoost inference, returns decision |

C++ sends a JSON message per packet:

```
{"SrcPort": 51234, "DstPort": 80, "Protocol": 6, "PacketLen": 120, "Flags": 18}
```
Python responds with `"PASS"` or `"DROP"`.

---

## Features

- **IPv4 & IPv6 support** — dual-stack packet parsing and zone classification
- **Zone-based static rules** — traffic filtered by direction between zones (LOCAL, LOOPBACK, PUBLIC, BLOCKED)
- **Stateful connection tracking** — established sessions bypass rule evaluation; reply packets pass automatically
- **SYN flood protection** — SYN cookies + per-IP half-open connection cap (max 15); offending IPs auto-blacklisted
- **ML-based threat detection** — XGBoost model trained on CIC-IDS2017 dataset classifies packets as benign or malicious
- **Dynamic IP blacklisting** — IPs auto-added to blacklist at runtime on SYN flood detection
- **TCP FIN/RST handling** — graceful and forceful connection teardown removes sessions from the table
- **Connection timeout cleanup** — SYN_RECEIVED entries expire after 5s; ACTIVE entries after 120s
- **ZeroMQ IPC** — low-latency local socket between C++ and Python with automatic reconnection on failure

---

## Security concepts demonstrated

- **Stateful packet inspection** — tracks TCP session lifecycle (SYN → ACTIVE → CLOSED)
- **SYN flood mitigation** — SYN cookies prevent resource exhaustion from half-open connections
- **Zone-based access control** — analogous to security zones in enterprise firewalls (pfSense, Cisco ASA)
- **Behavioral threat detection** — ML model flags anomalous traffic patterns rather than relying solely on signatures
- **Fail-open design** — AI inference failures default to PASS to avoid blocking legitimate traffic
- **Defense in depth** — multiple layers: blacklist → connection state → zone rules → ML model

---

## ML Model
 
| Detail | Value |
|---|---|
| Algorithm | XGBoost (XGBClassifier) |
| Training dataset | [CIC-IDS2017](https://www.unb.ca/cic/datasets/ids-2017.html) |
| Features used | Source Port, Destination Port, Protocol, Total Length of Fwd Packets, TCP Flags |
| Output | `0` = Benign (PASS) · `1` = Malicious (DROP) |
| Model files | `Model.json` (architecture) · `Model.pkl` (feature list) |

---

## Feature vector
 
TCP flags are packed into a single byte in C++ before being sent:
 
| Bit | Flag |
|---|---|
| 0 | FIN |
| 1 | SYN |
| 2 | RST |
| 3 | PSH |
| 4 | ACK |
| 5 | URG |
 
---

## Zone classification
 
### IPv4
 
| Zone | Range |
|---|---|
| LOOPBACK | 127.x.x.x |
| LOCAL | 192.168.x.x · 10.x.x.x · 172.16–31.x.x · 169.254.x.x |
| BLOCKED | Manually configured or auto-blacklisted IPs |
| PUBLIC | Everything else |
 
### IPv6
 
| Zone | Range |
|---|---|
| LOOPBACK | : :1 |
| LOCAL | fe80: :/10 (link-local) · fc00: :/7 (ULA) |
| PUBLIC | Everything else |
 
---

## Static rule set
 
Rules are evaluated top-to-bottom; first match wins. Only packets that pass all static rules are forwarded to the ML model.
 
```
    {Zone::LOOPBACK, Zone::LOOPBACK, 0, 0, Action::PASS, "Allow Loopbacks"},
	{Zone::BLOCKED, Zone::LOCAL, 0, 0, Action::DROP, "Block Blacklisted IP"},
	{Zone::LOCAL, Zone::BLOCKED, 0, 0, Action::DROP, "Block to Blacklisted IP"},
	{Zone::PUBLIC, Zone::BLOCKED, 0, 0, Action::DROP, "Block to Blacklisted IP"},
	{Zone::LOCAL, Zone::PUBLIC, 0, 0, Action::PASS, "Allow sending everything out"},
	{Zone::PUBLIC, Zone::LOCAL, 80, 6, Action::DROP, "Block HTTP"},
	{Zone::PUBLIC, Zone::LOCAL, 22, 6, Action::DROP, "Block SSH"},
	{Zone::PUBLIC, Zone::LOCAL, 3389, 6, Action::DROP, "Block RDP"},
	{Zone::PUBLIC, Zone::LOCAL, 80, 6, Action::DROP, "Block HTTP"},
	{Zone::LOCAL, Zone::LOCAL, 0, 0, Action::PASS, "Allow sending to local network"}

```
 
---

## Requirements

### C++ (Firewall engine)
- Windows 10 / 11 (64-bit)
- Visual Studio 2019 or 2022 with **Desktop development with C++** workload
- [WinDivert 2.x](https://github.com/basil00/WinDivert/releases)
- [ZeroMQ (libzmq) 4.3.5](https://zeromq.org/download/) — or install via vcpkg: `vcpkg install zeromq:x64-windows`
- Administrator privileges

### Python (ML inference server)
- Python 3
- Dependencies:

```
xgboost
pyzmq
numpy
```
 
Install with:
```
pip install xgboost pyzmq numpy
```

---
 
## Setup & run
 
### 1. Build the C++ firewall
 
- Download WinDivert and extract to e.g. `C:\WinDivert\`
- Install ZeroMQ via vcpkg or manually
- In Visual Studio project properties, configure:
   - Include dirs → WinDivert `include\` + ZeroMQ `include\`
   - Library dirs → WinDivert `x64\` + ZeroMQ `lib\`
   - Additional dependencies → `WinDivert.lib`, `libzmq-mt-4_3_5.lib`
- Copy `WinDivert.dll` and `WinDivert64.sys` into the build output folder
- Build with `Ctrl+Shift+B`
### 2. Start the Python AI server first
 
```
python ai.py
```
 
You should see:
```
Ai Loading....
Ai Model loaded features : [...]
Ai is running on port 5555
```

### 3. Run the firewall as Administrator
 
```
Ai-Firewall.exe
```

**Important:** Always start `ai.py` before the firewall executable. The C++ engine waits 500ms on startup for the Python server to bind.
 
---

## Known limitations
 
- Windows-only (WinDivert dependency)
- Single-threaded — may drop packets under very high throughput
- ML model uses only 5 features — a richer feature set would improve detection accuracy
- Rules and blacklists are hardcoded at compile time
- Code is currently uncommented 
- ML inference over ZeroMQ introduces latency on the packet path, high-traffic scenarios may cause noticeable delays.

---

## Project structure
 
```
Ai-Firewall/
├── main.cpp          # C++ firewall engine
├── ai.py             # Python ML inference server
├── Model.json        # XGBoost model architecture
├── Model.pkl         # Feature list used during training
├── Ai-Firewall.vcxproj
└── README.md
```
 
---

## Built with
 
- C++ (C++17)
- Python 3.14
- [WinDivert](https://github.com/basil00/WinDivert) — Windows packet interception
- [ZeroMQ](https://zeromq.org/) — inter-process communication
- [XGBoost](https://xgboost.readthedocs.io/) — gradient boosted ML classifier
- [CIC-IDS2017](https://www.unb.ca/cic/datasets/ids-2017.html) — intrusion detection training dataset
---

## Author
**Matthew Belvian** · [GitHub](https://github.com/Lazymelly-z)

**Matt Belvian** · [LinkedIn](https://www.linkedin.com/in/matt-belvian-18b27b354/)


 










