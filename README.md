# NetGuard 🛡️
> **Web-Based Linux `nftables` Firewall Management & Monitoring Dashboard**

NetGuard is a full-stack Node.js + React web application that enables authenticated administrators to monitor and manage a Linux `nftables` firewall through an intuitive, dark-mode cyber defense interface.

---

## ⚡ Key Highlights & Architecture

- **Strict Boundary Separation**: The frontend SPA communicates exclusively via the Express REST API and authenticated WebSockets. It is never allowed to run or craft raw shell commands.
- **Server-Side Command Construction**: All firewall rules and set modifications are built and validated in the Node.js backend using strictly sanitized arrays (`execFile`) rather than string concatenation.
- **Embedded Database (`node:sqlite`)**: Uses Node.js 22+ built-in synchronous SQLite engine. No external C++ compiler, python, or visual studio build tools required.
- **Authenticated Real-Time WebSocket (`/ws`)**: Streams live network packet telemetry with JWT verification on connection handshake (`?token=<jwt>`).
- **Stateful Rule-Matching Traffic Simulator**: Simulated traffic is actively evaluated against current firewall rules and the `@blocklist` set. A newly added `DROP` rule or blocked IP immediately triggers dropped packets in the live telemetry feed with its matching rule handle!
- **Strict Chain Scoping**: Rule creations are strictly locked to the `input` and `forward` chains to eliminate arbitrary kernel chain injection.
- **Brute-Force Rate Limiting**: Dedicated rate limiting on `POST /api/auth/login` (5 attempts per 15m) keyed by IP and target username for NAT compatibility.

---

## 📋 Prerequisites

- **Node.js**: `>= 22.5.0` (required for native `node:sqlite` module support)
- **npm**: `>= 10.0.0`

---

## 🚀 Quick Start

### 1. Start the Backend Daemon (Port 5000)

```bash
cd backend
npm install
npm run dev
```

The daemon will start on `http://localhost:5000` with the SQLite database initialized and WebSocket server listening at `ws://localhost:5000/ws`.

> [!NOTE]
> In development mode, if no `JWT_SECRET` is defined in `.env`, NetGuard generates a secure ephemeral secret. In production mode (`NODE_ENV=production`), `JWT_SECRET` is strictly required.

### 2. Start the Frontend Application (Port 5173)

In a separate terminal:

```bash
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173` in your browser.

---

## 🔐 Authentication & First-Login Flow

- **Default Seeded Admin**: `admin`
- **Initial Dev Password**: `admin123`

> [!IMPORTANT]
> When logging in with the default seeded credentials, NetGuard's security layer detects `must_change_password: 1` and prompts you to change the initial password before full console access is unlocked.

---

## 📡 API Endpoints

| Method | Endpoint | Description | Auth Required |
|---|---|---|---|
| `POST` | `/api/auth/login` | Authenticate admin & acquire JWT (Rate limited) | No |
| `POST` | `/api/auth/change-password` | Update administrator password | Yes |
| `GET` | `/api/auth/me` | Fetch current session and profile info | Yes |
| `GET` | `/api/stats/summary` | 24-hour summary metrics (ACCEPT / DROP / REJECT) | Yes |
| `GET` | `/api/logs/recent` | Recent connection logs with matched handles | Yes |
| `GET` | `/api/rules` | Fetch current `nftables` parsed ruleset | Yes |
| `POST` | `/api/rules` | Add new firewall rule (scoped to `input`/`forward`) | Yes |
| `PUT` | `/api/rules/:handle` | Edit existing rule by handle ID | Yes |
| `DELETE` | `/api/rules/:handle` | Delete rule from `nftables` by handle | Yes |
| `GET` | `/api/ip-blocklist` | List blocked IPs in `nftables` `@blocklist` set | Yes |
| `POST` | `/api/ip-blocklist` | Add IP or CIDR subnet to blocklist set | Yes |
| `DELETE` | `/api/ip-blocklist/:ip` | Remove IP or CIDR from blocklist set | Yes |
| `GET` | `/api/audit-logs` | Retrieve administrator audit trail with filters | Yes |
| `WS` | `/ws?token=<jwt>` | Live streaming connection telemetry | Yes |

---

## 🖥️ Application Pages

1. **`/login`**: Cyber-security themed login card with demo credentials helper and rate-limit guard.
2. **`/dashboard`**: Real-time overview featuring live counters, an interactive 24-hour traffic volume chart (Recharts), and a live connection stream connected to the authenticated WebSocket.
3. **`/rules`**: Full `nftables` rules viewer with filters by chain (`input`, `forward`) and action (`ACCEPT`, `DROP`, `REJECT`), plus an "Add Rule" modal with server-side validation.
4. **`/ip-management`**: Dedicated IP blocklist interface managing the kernel `@blocklist` set with instant add and unblock capabilities.
5. **`/logs`**: Complete audit trail recording all rule creations, deletions, IP blocks, and administrative logins.
6. **`/settings`**: Admin password change and firewall engine runtime telemetry.

---

## 🧪 Testing

Run backend tests verifying database initialization, admin seeding, rule management, and packet evaluation:

```bash
cd backend
npm test
```
