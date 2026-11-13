"use strict";

// Remote TLS gateway. Clients speak TLS HTTP/2. The gateway forwards each
// stream to the loopback Lore Server over TLS. It does not read tokens,
// cache authorization, or decide which repository is allowed.
//
// GATEWAY_ALLOW is a network boundary: peer addresses not on the list are
// disconnected before a stream is forwarded. Being listed is not a
// repository grant.

const fs = require("fs");
const http2 = require("http2");
const tls = require("tls");
const net = require("net");

const host = process.env.GATEWAY_HOST || "";
const port = Number(process.env.GATEWAY_PORT || "0");
const upstream = process.env.UPSTREAM_ORIGIN || "";
const upstreamCA = process.env.UPSTREAM_CA || "";
const certPath = process.env.GATEWAY_CERT || "";
const keyPath = process.env.GATEWAY_KEY || "";
const logPath = process.env.GATEWAY_LOG || "";
const allowText = process.env.GATEWAY_ALLOW || "";
const managerUpstream = process.env.MANAGER_UPSTREAM || "";
const managerPort = Number(process.env.MANAGER_TLS_PORT || "0");
const authUpstream = process.env.AUTH_UPSTREAM || "";
const authPort = Number(process.env.AUTH_TLS_PORT || "0");

function fail(message) {
  process.stderr.write(message + "\n");
  process.exit(1);
}

if (!net.isIP(host) || host === "0.0.0.0" || host === "::") fail("GATEWAY_HOST must be one address");
if (!Number.isInteger(port) || port < 1 || port > 65535) fail("GATEWAY_PORT is required");
if (!upstream.startsWith("https://127.0.0.1:")) fail("upstream must be https://127.0.0.1:<port>");
if (!upstreamCA || !certPath || !keyPath || !logPath) fail("certificate paths are required");
if (!allowText) fail("GATEWAY_ALLOW is required");

const rules = allowText.split(",").map((item) => item.trim()).filter(Boolean);
if (rules.length === 0) fail("GATEWAY_ALLOW is empty");

const ca = fs.readFileSync(upstreamCA);
const cert = fs.readFileSync(certPath);
const key = fs.readFileSync(keyPath);
const upstreamHost = upstream.slice("https://".length);
let sessions = 0;

function log(event) {
  event.at = new Date().toISOString();
  fs.appendFileSync(logPath, JSON.stringify(event) + "\n");
}

function ipv4(address) {
  if (!address) return "";
  if (address.startsWith("::ffff:")) return address.slice(7);
  return address;
}

function matchRule(ip, rule) {
  if (!rule.includes("/")) return ip === rule;
  const [base, bitsText] = rule.split("/");
  const bits = Number(bitsText);
  if (!net.isIPv4(ip) || !net.isIPv4(base) || !Number.isInteger(bits) || bits < 0 || bits > 32) return false;
  const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
  const toInt = (value) => value.split(".").reduce((acc, part) => ((acc << 8) + Number(part)) >>> 0, 0);
  return (toInt(ip) & mask) === (toInt(base) & mask);
}

function allowed(address) {
  const ip = ipv4(address);
  return rules.some((rule) => matchRule(ip, rule));
}

let session = null;

function upstreamSession() {
  if (session && !session.closed && !session.destroyed) return session;
  const created = http2.connect(upstream, {
    ca: ca,
    servername: "localhost",
    rejectUnauthorized: true,
  });
  session = created;
  created.on("error", (err) => {
    log({ event: "upstream_session_error", message: err.message });
    if (session === created) session = null;
  });
  created.on("close", () => {
    if (session === created) session = null;
    log({ event: "upstream_session_close" });
  });
  created.on("connect", () => {
    const sock = created.socket;
    log({
      event: "upstream_tls",
      authorized: Boolean(sock && sock.authorized),
      protocol: sock && sock.getProtocol ? sock.getProtocol() : "",
      servername: "localhost",
      alpn: sock && sock.alpnProtocol ? sock.alpnProtocol : "",
    });
  });
  return created;
}

function copyHeaders(headers) {
  const out = {};
  for (const key of Object.keys(headers)) {
    if (key === ":authority") out[key] = upstreamHost;
    else if (key === ":scheme") out[key] = "https";
    else out[key] = headers[key];
  }
  return out;
}

function forward(client, headers) {
  const rpc = String(headers[":path"] || "");
  let up;
  try {
    up = upstreamSession().request(copyHeaders(headers));
  } catch (err) {
    log({ event: "stream_error", rpc: rpc, message: err.message, forwarded: false });
    try {
      client.respond({
        ":status": 200,
        "content-type": "application/grpc",
        "grpc-status": "14",
        "grpc-message": "upstream unavailable",
      }, { endStream: true });
    } catch (_e) {}
    return;
  }
  let clientBytes = 0;
  let upstreamBytes = 0;
  let framesUp = 0;
  let framesDown = 0;
  let trailers = null;
  let responded = false;
  let logged = false;

  function finish(statusCode, forwarded) {
    if (logged) return;
    logged = true;
    log({
      event: "stream_end",
      rpc: rpc,
      forwarded: forwarded,
      grpc_status: statusCode == null ? "" : String(statusCode),
      client_bytes: clientBytes,
      upstream_bytes: upstreamBytes,
      frames_up: framesUp,
      frames_down: framesDown,
      sessions: sessions,
    });
  }

  client.on("data", (chunk) => {
    clientBytes += chunk.length;
    framesUp += 1;
    const ok = up.write(chunk);
    if (!ok) {
      client.pause();
      up.once("drain", () => client.resume());
    }
  });
  client.on("end", () => {
    try { up.end(); } catch (_e) {}
  });
  client.on("aborted", () => {
    try { up.close(http2.constants.NGHTTP2_CANCEL); } catch (_e) {}
  });
  client.on("error", (err) => {
    finish("", true);
    log({ event: "client_stream_error", rpc: rpc, message: err.message });
    try { up.close(http2.constants.NGHTTP2_CANCEL); } catch (_e) {}
  });
  client.on("close", () => {
    if (!up.closed) {
      try { up.close(http2.constants.NGHTTP2_CANCEL); } catch (_e) {}
    }
  });
  up.on("response", (responseHeaders, flags) => {
    responded = true;
    const endStream = Boolean(flags & http2.constants.NGHTTP2_FLAG_END_STREAM);
    try {
      client.respond(responseHeaders, { waitForTrailers: !endStream, endStream: endStream });
    } catch (err) {
      finish("", true);
      log({ event: "respond_error", rpc: rpc, message: err.message });
      return;
    }
    if (endStream) finish(responseHeaders["grpc-status"], true);
  });
  up.on("data", (chunk) => {
    upstreamBytes += chunk.length;
    framesDown += 1;
    if (client.closed || client.destroyed) return;
    const ok = client.write(chunk);
    if (!ok) {
      up.pause();
      client.once("drain", () => up.resume());
    }
  });
  up.on("trailers", (value) => {
    trailers = value;
  });
  client.on("wantTrailers", () => {
    const value = trailers || { "grpc-status": "0" };
    try { client.sendTrailers(value); } catch (_e) {}
    finish(value["grpc-status"], true);
  });
  up.on("end", () => {
    if (!client.closed && responded) {
      try { client.end(); } catch (_e) {}
    }
  });
  up.on("close", () => {
    const statusCode = trailers && trailers["grpc-status"];
    finish(statusCode == null ? "" : statusCode, true);
  });
  up.on("error", (err) => {
    finish("", true);
    log({ event: "upstream_stream_error", rpc: rpc, message: err.message });
    if (!responded && !client.closed) {
      try {
        client.respond({
          ":status": 200,
          "content-type": "application/grpc",
          "grpc-status": "14",
          "grpc-message": "upstream stream error",
        }, { endStream: true });
      } catch (_e) {}
    } else {
      try { client.close(http2.constants.NGHTTP2_CANCEL); } catch (_e) {}
    }
  });
}

function guard(socket) {
  if (allowed(socket.remoteAddress)) return true;
  log({ event: "rejected", address: ipv4(socket.remoteAddress) });
  socket.destroy();
  return false;
}

const server = http2.createSecureServer({ cert: cert, key: key, ALPNProtocols: ["h2"] });
server.on("error", (err) => fail("listen error " + err.message));
server.on("secureConnection", (socket) => {
  guard(socket);
});
server.on("session", (httpSession) => {
  sessions += 1;
  // The connection was already checked in secureConnection. Node wraps an
  // HTTP/2 session socket and deliberately rejects direct socket property
  // access with ERR_HTTP2_NO_SOCKET_MANIPULATION.
  log({ event: "client_session_open", sessions: sessions });
  httpSession.on("error", (err) => log({ event: "client_session_error", message: err.message }));
  httpSession.on("close", () => {
    sessions = Math.max(0, sessions - 1);
    log({ event: "client_session_close", sessions: sessions });
  });
});
server.on("stream", (stream, headers) => {
  stream.on("error", () => {});
  log({ event: "client_stream", rpc: String(headers[":path"] || ""), scheme: String(headers[":scheme"] || "") });
  forward(stream, headers);
});

function startManagerProxy() {
  if (!managerUpstream || !managerPort) return;
  const target = new URL(managerUpstream);
  const proxy = tls.createServer({ cert: cert, key: key }, (socket) => {
    if (!guard(socket)) return;
    const up = net.connect(Number(target.port), target.hostname, () => {
      socket.pipe(up);
      up.pipe(socket);
    });
    up.on("error", () => socket.destroy());
    socket.on("error", () => up.destroy());
  });
  proxy.on("error", (err) => fail("manager proxy " + err.message));
  proxy.listen(managerPort, host, () => {
    log({ event: "manager_tls_listening", host: host, port: managerPort });
  });
}

function startAuthProxy() {
  if (!authUpstream || !authPort) return;
  const target = new URL(authUpstream);
  let authSession = null;
  function authUpstreamSession() {
    if (authSession && !authSession.closed && !authSession.destroyed) return authSession;
    authSession = http2.connect(authUpstream);
    authSession.on("error", () => { authSession = null; });
    authSession.on("close", () => { authSession = null; });
    return authSession;
  }
  const proxy = http2.createSecureServer({ cert: cert, key: key, ALPNProtocols: ["h2"] });
  proxy.on("error", (err) => fail("auth proxy " + err.message));
  proxy.on("secureConnection", (socket) => { guard(socket); });
  proxy.on("stream", (stream, headers) => {
    stream.on("error", () => {});
    if (!guard(stream.session.socket)) return;
    const rpc = String(headers[":path"] || "");
    log({ event: "auth_stream", rpc: rpc });
    const out = {};
    for (const key of Object.keys(headers)) {
      if (key === ":authority") out[key] = target.host;
      else if (key === ":scheme") out[key] = "http";
      else out[key] = headers[key];
    }
    let up;
    try { up = authUpstreamSession().request(out); }
    catch (err) {
      log({ event: "auth_request_error", rpc: rpc, message: err.message });
      try { stream.respond({ ":status": 200, "grpc-status": "14", "content-type": "application/grpc" }, { endStream: true }); } catch (_e) {}
      return;
    }
    stream.pipe(up);
    up.on("response", (responseHeaders, flags) => {
      log({ event: "auth_response", rpc: rpc, status: responseHeaders[":status"], grpc: responseHeaders["grpc-status"] || "" });
      const endStream = Boolean(flags & http2.constants.NGHTTP2_FLAG_END_STREAM);
      try { stream.respond(responseHeaders, { waitForTrailers: !endStream, endStream: endStream }); } catch (_e) {}
    });
    up.on("data", (chunk) => {
      if (!stream.write(chunk)) { up.pause(); stream.once("drain", () => up.resume()); }
    });
    up.on("trailers", (value) => {
      log({ event: "auth_trailers", rpc: rpc, grpc: value["grpc-status"] || "" });
      stream.on("wantTrailers", () => { try { stream.sendTrailers(value); } catch (_e) {} });
    });
    up.on("end", () => { try { stream.end(); } catch (_e) {} });
    up.on("error", (err) => {
      log({ event: "auth_upstream_error", rpc: rpc, message: err.message });
      try { stream.close(http2.constants.NGHTTP2_CANCEL); } catch (_e) {}
    });
    stream.on("aborted", () => { try { up.close(http2.constants.NGHTTP2_CANCEL); } catch (_e) {} });
  });
  proxy.listen(authPort, host, () => {
    log({ event: "auth_tls_listening", host: host, port: authPort });
  });
}

const upstreamURL = new URL(upstream);
const probe = tls.connect({
  host: "127.0.0.1",
  port: Number(upstreamURL.port),
  servername: "localhost",
  ca: ca,
  rejectUnauthorized: true,
  ALPNProtocols: ["h2"],
}, () => {
  log({
    event: "upstream_probe",
    authorized: probe.authorized,
    protocol: probe.getProtocol(),
    alpn: probe.alpnProtocol || "",
  });
  probe.end();
  server.listen(port, host, () => {
    const addr = server.address();
    log({ event: "listening", host: addr.address, port: addr.port, tls: true });
    startManagerProxy();
    startAuthProxy();
  });
});
probe.on("error", (err) => fail("upstream TLS probe failed: " + err.message));
