# NetGuard 🛡️
> **Lightweight Terminal-Based Linux `nftables` Firewall Engine & Showcase**

NetGuard is a clean, zero-dependency Node.js firewall engine designed to execute and test Linux `nftables` rulesets against incoming IP network traffic directly in your terminal.

---

## ⚡ Highlights

- **Zero External Dependencies**: Pure Node.js built-ins (`fs`, `path`, `readline`, `assert`). No npm packages needed.
- **Configurable Ruleset (`rules.json`)**: Plain JSON file defining firewall chains (`input`, `forward`), actions (`ACCEPT`, `DROP`, `REJECT`), protocols, and ports.
- **Dynamic IP Blocklist (`blocklist.json`)**: Enforces exact IP and bitwise CIDR subnet blocks (e.g. `194.26.29.0/24`).
- **Live Traffic Inspection (`incoming_ips.json`)**: Evaluates incoming network packets directly against active firewall rules.
- **Terminal Interface (`cli.js`)**: Interactive menu shell and CLI commands with color-coded verdicts (`ACCEPT`, `DROP`, `REJECT`).
- **Rule-Driven Verification**: 100% dynamic packet evaluation based solely on defined rules, blocklist, and chain policies.

---

## 🚀 Quick Start

No `npm install` needed! Just clone and run:

### 1. Run the Showcase (Execute Incoming IPs)

```bash
npm run showcase
# or
node cli.js showcase
```

This reads `incoming_ips.json`, runs every packet through the firewall rules and blocklist, and prints color-coded verdicts and an execution summary:

```text
[1 /14] [ACCEPT] 198.51.100.42:22       TCP   [chain: input]    -> Matched Rule #10: Allow SSH traffic
[2 /14] [ DROP ] 203.0.113.88:23        TCP   [chain: input]    -> Matched Rule #15: Drop unauthorized Telnet probes
[3 /14] [ DROP ] 185.220.101.5:443      TCP   [chain: input]    -> Blocked by @blocklist set (185.220.101.5: Tor exit node brute force)
[4 /14] [ DROP ] 45.143.200.12:22       TCP   [chain: input]    -> Blocked by @blocklist set (45.143.200.12: Repeated SSH dictionary scan)
[5 /14] [ DROP ] 194.26.29.105:80       TCP   [chain: input]    -> Blocked by @blocklist set (194.26.29.0/24: Known malicious botnet subnet)
```

---

### 2. Interactive Terminal Shell

```bash
npm start
# or
node cli.js
```

Displays an interactive management menu:

```text
ACTIONS:
  [1] 🚀 Run Showcase (Execute incoming_ips.json)
  [2] 🎯 Test Single IP Address
  [3] 📋 View Rules (rules.json)
  [4] ➕ Add Rule
  [5] ❌ Delete Rule
  [6] 🛡️  View Blocklist (blocklist.json)
  [7] 🚫 Block IP / CIDR
  [8] 🔓 Unblock IP / CIDR
  [9] 🔄 Reset Rules to Defaults
  [0] 🚪 Exit
```

---

## 📁 Files Overview

| File | Description |
|---|---|
| [`rules.json`](./rules.json) | The active firewall ruleset (ports, protocols, chains, actions). |
| [`blocklist.json`](./blocklist.json) | Blocked IPs and CIDR subnets. |
| [`incoming_ips.json`](./incoming_ips.json) | Incoming IP network packets to inspect against rules. |
| [`firewall.js`](./firewall.js) | Core rule execution engine with bitwise CIDR matching. |
| [`cli.js`](./cli.js) | Terminal runner and interactive CLI. |
| [`test.js`](./test.js) | Rule-driven unit test suite. |

---

## ⚙️ Firewall Rules (`rules.json`)

You can edit [`rules.json`](./rules.json) directly or use the CLI:

```json
[
  {
    "handle": 10,
    "chain": "input",
    "protocol": "tcp",
    "src_ip": null,
    "port": "22",
    "action": "ACCEPT",
    "comment": "Allow SSH traffic"
  },
  {
    "handle": 15,
    "chain": "input",
    "protocol": "tcp",
    "src_ip": null,
    "port": "23",
    "action": "DROP",
    "comment": "Drop unauthorized Telnet probes"
  }
]
```

### Rule Commands:
```bash
# View active rules
node cli.js rules

# Delete rule by handle number
node cli.js rules delete 15

# Reset rules to default configuration
node cli.js rules reset
```

---

## 📝 Incoming IP Packets (`incoming_ips.json`)

Add or modify incoming IP packets in [`incoming_ips.json`](./incoming_ips.json):

```json
[
  {
    "ip": "198.51.100.42",
    "port": 22,
    "protocol": "TCP",
    "chain": "input"
  },
  {
    "ip": "194.26.29.105",
    "port": 80,
    "protocol": "TCP",
    "chain": "input"
  }
]
```

---

## 🎯 Test a Single IP Packet

Test what verdict an incoming IP packet receives based on current active rules:

```bash
# Syntax: node cli.js test <ip> [port] [protocol] [chain]
node cli.js test 185.220.101.5 443 TCP
# Output: [ DROP ] 185.220.101.5:443 [TCP] [chain: input] -> Blocked by @blocklist set (185.220.101.5: Tor exit node brute force)

node cli.js test 198.51.100.42 22 TCP
# Output: [ACCEPT] 198.51.100.42:22 [TCP] [chain: input] -> Matched Rule #10: Allow SSH traffic
```

---

## 🛡️ Blocklist Management (`blocklist.json`)

```bash
# View active blocklist
node cli.js blocklist

# Block an IP or CIDR subnet
node cli.js block 194.26.29.0/24 "Known botnet subnet"

# Unblock an IP or CIDR subnet
node cli.js unblock 194.26.29.0/24
```

---

## 🧪 Testing

Run all unit tests:

```bash
npm test
# or
node test.js
```
