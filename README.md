# Simple SOCKS5 Proxy with Username/Password Auth

A minimal SOCKS5 proxy written in Node.js using only standard libraries (`net` and `dns`).  
Supports basic username/password authentication and tunnels raw TCP traffic.

---
## How it works

01) Start the server (node socks5.js) — it listens on PORT (default 1080).
02) Client connects and sends method selection. Server insists on username/password (0x02).
03) Client sends username/password; server checks against AUTH_USER/AUTH_PASS.
04) After successful auth, client sends CONNECT request with dest address and port.
05) Server connects to destination and, on success, replies REP=0x00 and starts piping bytes both ways (socket.pipe()), achieving tunneling.
06) The server logs source IP and requested destination host:port.

## 🚀 How to Run

1. **Clone & Install**
   ```bash
   git clone https://github.com/IsuruIndrajith/SOCKS5-proxy-server.git
   cd SOCKS5-proxy-server
   npm install   # only if you added a package.json for scripts/env; not required for pure Node


2. **Set Credentials (Optional)**
   Default credentials are:

   ```
   USERNAME: user01
   PASSWORD: password123
   ```

   To change them, set environment variables:

   ```bash
   set AUTH_USER=myuser      # Windows (PowerShell)
   set AUTH_PASS=mypassword
   ```

   or on Linux/macOS:

   ```bash
   export AUTH_USER=myuser
   export AUTH_PASS=mypassword
   ```

3. **Start the Proxy**

   ```bash
   node socks5.js
   ```

   By default it listens on `127.0.0.1:1080`.
   To use a different port:

   ```bash
   node socks5.js 0.0.0.0 1081
   ```

---

## ✅ Example Test

Fetch your external IP through the proxy using `curl`:

```bash
curl.exe --socks5 127.0.0.1:1080 --proxy-user user01:password123 https://ipinfo.io
```

If everything works, you’ll see JSON output like:

```json
{
  "ip": "192.248.58.1",
  "city": "Jaffna",
  "region": "Northern Province",
  "country": "LK",
  "loc": "9.6684,80.0074",
  "org": "AS38229 Lanka Education & Research Network, NREN",
  "postal": "40000",
  "timezone": "Asia/Colombo",
  "readme": "https://ipinfo.io/missingauth"
}
```

---

## 📂 Project Structure

```
socks5.js        # main proxy implementation
README.md        # this file
```

---

## 🛠️ Notes

* Implemented SOCKS5 handshake (method selection + username/password).
* Implemented CONNECT request parsing for IPv4 / domain / IPv6.
* Established remote connection and piped streams to tunnel traffic.
* Logs source IP and destination host:port.
* Configurable port and credentials via environment variables.
  
