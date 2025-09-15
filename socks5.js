const net = require("net");
// net is the NOde's built-in TCP library

// Configurations
const LISTEN_PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 1080;
const AUTH_USER = process.env.AUTH_USER || "user01";
const AUTH_PASS = process.env.AUTH_PASS || "password123";

console.log(`Starting SOCKS5 proxy on port ${LISTEN_PORT}`);
console.log(`Auth username: "${AUTH_USER}" (change via AUTH_USER / AUTH_PASS env vars)`);

// create a TCP server using net.createServer
const server = net.createServer((clientSocket) => {
  const clientAddr = `${clientSocket.remoteAddress}:${clientSocket.remotePort}`;
  // client address for logging with combined remote IP and port

  // the following wait s for the first data chunk from the client
  clientSocket.once("data", (chunk) => {
    try {
      handleMethodSelection(chunk, clientSocket, clientAddr);
    } catch (err) {
      console.error("Handshake error:", err);
      clientSocket.destroy();
    }
  });

  clientSocket.on("error", (err) => {
    console.error(`Client socket error (${clientAddr}):`, err.message);
  });
});

// on the server, start listening
server.on("error", (err) => {
  console.error("Server error:", err);
});

// accepting the connections
server.listen(LISTEN_PORT);

// handle method selections
function handleMethodSelection(buf, clientSocket, clientAddr) {
  // buf: VER(1) NMETHODS(1) METHODS...
  if (buf.length < 2) {
    clientSocket.end();
    return;
  }
  const ver = buf[0];
  if (ver !== 0x05) {
    clientSocket.end();
    return;
  }
  const nmethods = buf[1];
  const methods = buf.slice(2, 2 + nmethods);

  // here it is required username/password. If client doesn't offer it, refuse.
  const METHOD_USERNAME = 0x02;
  if (!methods.includes(METHOD_USERNAME)) {
    // reply NO ACCEPTABLE METHODS (0xFF)
    clientSocket.write(Buffer.from([0x05, 0xff]));
    clientSocket.end();
    console.log(`Client ${clientAddr} did not offer username/password auth. Rejected.`);
    return;
  }
  // Offer username/password
  clientSocket.write(Buffer.from([0x05, METHOD_USERNAME]));
  // Wait for username/password subnegotiation
  clientSocket.once("data", (authBuf) => {
    handleUserPassAuth(authBuf, clientSocket, clientAddr);
  });
}

// handle username and password authentication
function handleUserPassAuth(buf, clientSocket, clientAddr) {
  if (buf.length < 2) {
    clientSocket.end();
    return;
  }
  const ver = buf[0];
  if (ver !== 0x01) {
    clientSocket.end();
    return;
  }
  let offset = 1;
  const ulen = buf[offset++];
  if (buf.length < offset + ulen + 1) { clientSocket.end(); return; }
  const username = buf.slice(offset, offset + ulen).toString(); offset += ulen;
  const plen = buf[offset++];
  if (buf.length < offset + plen) { clientSocket.end(); return; }
  const password = buf.slice(offset, offset + plen).toString();

  const ok = username === AUTH_USER && password === AUTH_PASS;
  // Reply: VER=0x01 STATUS(1) (0x00 success, otherwise failure)
  clientSocket.write(Buffer.from([0x01, ok ? 0x00 : 0x01]));
  if (!ok) {
    console.log(`Auth failed from ${clientAddr} (username="${username}")`);
    clientSocket.end();
    return;
  }
  console.log(`Auth success from ${clientAddr} (username="${username}")`);
  // Now wait for the SOCKS5 request
  clientSocket.once("data", (reqBuf) => {
    handleSocksRequest(reqBuf, clientSocket, clientAddr);
  });
}

// parse CONNECT request and open remote socket
function handleSocksRequest(buf, clientSocket, clientAddr) {
  // Request: VER(1)=0x05, CMD(1)=0x01 connect, RSV(1)=0x00, ATYP(1), DST.ADDR, DST.PORT(2)
  if (buf.length < 7) { clientSocket.end(); return; }
  const ver = buf[0];
  const cmd = buf[1];
  // const rsv = buf[2];
  const atyp = buf[3];

  if (ver !== 0x05) { clientSocket.end(); return; }
  if (cmd !== 0x01) {
    // Only support CONNECT
    sendSocksReply(clientSocket, 0x07); // Command not supported
    clientSocket.end();
    console.log(`Unsupported CMD ${cmd} from ${clientAddr}`);
    return;
  }

  let addr = null;
  let port = null;
  let offset = 4;
  if (atyp === 0x01) {
    // IPv4
    if (buf.length < offset + 4 + 2) { clientSocket.end(); return; }
    addr = `${buf[offset++]}.${buf[offset++]}.${buf[offset++]}.${buf[offset++]}`;
  } else if (atyp === 0x03) {
    // Domain name
    const len = buf[offset++];
    if (buf.length < offset + len + 2) { clientSocket.end(); return; }
    addr = buf.slice(offset, offset + len).toString(); offset += len;
  } else if (atyp === 0x04) {
    // IPv6
    if (buf.length < offset + 16 + 2) { clientSocket.end(); return; }
    const parts = [];
    for (let i = 0; i < 8; i++) {
      parts.push(buf.readUInt16BE(offset).toString(16));
      offset += 2;
    }
    addr = parts.join(":");
  } else {
    sendSocksReply(clientSocket, 0x08); // Address type not supported
    clientSocket.end();
    return;
  }
  port = buf.readUInt16BE(offset); offset += 2;

  console.log(`Request from ${clientAddr} -> ${addr}:${port}`);

  //connect to destination
  const remoteSocket = net.createConnection({ host: addr, port: port }, () => {
    // On success, send success reply.
    // Use BND.ADDR = local address of the outgoing connection, BND.PORT = local port
    const localAddress = remoteSocket.localAddress || "0.0.0.0";
    const localPort = remoteSocket.localPort || 0;
    sendSocksSuccess(clientSocket, localAddress, localPort);
    // Pipe data both ways
    clientSocket.pipe(remoteSocket);
    remoteSocket.pipe(clientSocket);
  });

  remoteSocket.on("error", (err) => {
    console.error(`Remote connection error to ${addr}:${port} -`, err.message);
    sendSocksReply(clientSocket, 0x05); // Connection refused
    clientSocket.end();
    remoteSocket.destroy();
  });

  clientSocket.on("close", () => {
    remoteSocket.destroy();
  });
}

// Send Socks Reply(Negative)
function sendSocksReply(sock, rep) {
  
  const resp = Buffer.from([0x05, rep, 0x00, 0x01, 0,0,0,0, 0,0]);
  sock.write(resp);
}

// Send Socks Reply(Success)
function sendSocksSuccess(sock, bndAddr, bndPort) {
  // Decide whether IPv4, IPv6 or domain
  let resp;
  if (net.isIPv4(bndAddr)) {
    resp = Buffer.alloc(10);
    resp[0] = 0x05; // VER
    resp[1] = 0x00; // REP success
    resp[2] = 0x00; // RSV
    resp[3] = 0x01; // ATYP IPv4
    const parts = bndAddr.split(".").map(Number);
    resp[4] = parts[0]; resp[5] = parts[1]; resp[6] = parts[2]; resp[7] = parts[3];
    resp.writeUInt16BE(bndPort, 8);
  } else if (net.isIPv6(bndAddr)) {
    // IPv6
    resp = Buffer.alloc(4 + 16 + 2);
    resp[0] = 0x05; resp[1] = 0x00; resp[2] = 0x00; resp[3] = 0x04;
    // write IPv6 address bytes
    const segments = bndAddr.split(":").map(s => parseInt(s, 16) || 0);
    for (let i = 0; i < 8; i++) {
      resp.writeUInt16BE(segments[i] || 0, 4 + i*2);
    }
    resp.writeUInt16BE(bndPort, 4 + 16);
  } else {
    // Fallback: send IPv4 0.0.0.0
    resp = Buffer.from([0x05, 0x00, 0x00, 0x01, 0,0,0,0, 0,0]);
  }
  sock.write(resp);
}
