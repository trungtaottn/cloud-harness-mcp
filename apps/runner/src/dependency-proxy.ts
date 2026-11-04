/** Fixed sidecar program. Only this process joins both the isolated job and provisioning networks. */
export const DEPENDENCY_PROXY_SCRIPT = String.raw`
const http = require('node:http');
const net = require('node:net');
const [ecosystem, upstreamUrl, maxText, timeoutText] = process.argv.slice(1);
const hosts = ecosystem === 'go' ? ['proxy.golang.org', 'sum.golang.org', 'storage.googleapis.com'] : ecosystem === 'pnpm' ? ['registry.npmjs.org'] : [];
const upstream = new URL(upstreamUrl);
const max = Number(maxText), timeout = Number(timeoutText);
if (upstream.protocol !== 'http:' || upstream.username || upstream.password || !Number.isSafeInteger(max) || max < 1 || !Number.isSafeInteger(timeout) || timeout < 1) process.exit(1);
const sockets = new Set();
let used = 0, exhausted = false;
const stop = () => { exhausted = true; for (const socket of sockets) socket.destroy(); server.close(); };
const consume = chunk => { used += chunk.length; if (used > max) { stop(); return false; } return true; };
const track = socket => { sockets.add(socket); socket.on('error', () => socket.destroy()); socket.on('close', () => sockets.delete(socket)); };
const server = http.createServer((_req, res) => { res.writeHead(403); res.end(); });
server.maxConnections = 32;
server.headersTimeout = Math.min(timeout, 10000);
server.on('connection', track);
server.on('connect', (req, client, head) => {
  if (exhausted || !hosts.some(host => req.url === host + ':443') || head.length) { client.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n'); return; }
  const remote = net.connect({host: upstream.hostname, port: Number(upstream.port) || 80});
  track(remote);
  const close = () => { remote.destroy(); client.destroy(); };
  client.on('close', () => remote.destroy());
  remote.on('close', () => client.destroy());
  remote.on('error', close);
  remote.setTimeout(Math.min(timeout, 30000), close);
  remote.on('connect', () => remote.write('CONNECT ' + req.url + ' HTTP/1.1\r\nHost: ' + req.url + '\r\n\r\n'));
  let headers = Buffer.alloc(0), ready = false;
  remote.on('data', chunk => {
    if (!consume(chunk)) return;
    if (ready) { if (!client.write(chunk)) remote.pause(); return; }
    headers = Buffer.concat([headers, chunk]);
    const end = headers.indexOf('\r\n\r\n');
    if (end < 0) { if (headers.length > 8192) close(); return; }
    if (end > 8192 || !/^HTTP\/1\.[01] 200(?: |\r)/.test(headers.toString('ascii', 0, end))) { close(); return; }
    ready = true;
    client.write('HTTP/1.1 200 Connection Established\r\n\r\n');
    const rest = headers.subarray(end + 4); headers = Buffer.alloc(0);
    if (rest.length && !client.write(rest)) remote.pause();
  });
  client.on('data', chunk => { if (!ready || !consume(chunk)) { close(); return; } if (!remote.write(chunk)) client.pause(); });
  client.on('drain', () => remote.resume());
  remote.on('drain', () => client.resume());
});
const timer = setTimeout(stop, timeout);
server.on('close', () => clearTimeout(timer));
server.listen(Number(process.env.DEPENDENCY_PROXY_PORT || 3128), '0.0.0.0', () => process.stdout.write('ready\n'));
process.on('SIGTERM', stop);
`;
