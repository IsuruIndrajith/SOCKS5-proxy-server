## 📝 README.md

````markdown
# Simple SOCKS5 Proxy with Username/Password Auth

A minimal SOCKS5 proxy written in Node.js using only standard libraries (`net` and `dns`).  
Supports basic username/password authentication and tunnels raw TCP traffic.

---

## 🚀 How to Run

1. **Clone & Install**
   ```bash
   git clone https://github.com/<your-username>/<your-repo>.git
   cd <your-repo>
   npm install   # only if you added a package.json for scripts/env; not required for pure Node
````

2. **Set Credentials (Optional)**
   Default credentials are:

   ```
   USERNAME: intern
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
curl --proxy socks5://intern:password123@127.0.0.1:1080 https://ipinfo.io
```

If everything works, you’ll see JSON output like:

```json
{
  "ip": "203.x.x.x",
  "city": "...",
  ...
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

* Implements only the essential subset of RFC1928 for CONNECT requests.
* Uses Node’s built-in `net` module for TCP tunneling.
* Perfect for learning or small internal tools; **not** production-hardened.

```
