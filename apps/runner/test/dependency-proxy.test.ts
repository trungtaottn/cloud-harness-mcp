import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { createServer, connect, type Socket } from 'node:net';
import { once } from 'node:events';
import { afterEach, describe, expect, it } from 'vitest';
import { DEPENDENCY_PROXY_SCRIPT } from '../src/dependency-proxy.js';
const children: ChildProcessWithoutNullStreams[] = [];
const sockets: Socket[] = [];
afterEach(async () => { for (const socket of sockets.splice(0)) socket.destroy(); for (const child of children.splice(0)) { if (child.exitCode === null) { child.kill(); await once(child, 'exit'); } } });
async function proxy(max = 10000, timeout = 2000) {
  const upstream = createServer(socket => { sockets.push(socket); socket.once('data', () => { socket.write('HTTP/1.1 200 OK\r\n\r\n'); socket.on('data', chunk => socket.write(chunk)); }); });
  upstream.listen(0, '127.0.0.1'); await once(upstream, 'listening');
  const upstreamPort = (upstream.address() as { port: number }).port;
  const script = DEPENDENCY_PROXY_SCRIPT.replace("process.stdout.write('ready\\n')", "process.stdout.write(String(server.address().port)+'\\n')");
  const child = spawn(process.execPath, ['-e', script, 'pnpm', `http://127.0.0.1:${upstreamPort}`, String(max), String(timeout)], { env: { ...process.env, DEPENDENCY_PROXY_PORT: '0' }, stdio: 'pipe' });
  children.push(child);
  const [output] = await once(child.stdout, 'data');
  return { port: Number(String(output).trim()), close: () => new Promise<void>(resolve => upstream.close(() => resolve())) };
}
async function request(port: number, authority: string) {
  const socket = connect(port, '127.0.0.1'); sockets.push(socket); await once(socket, 'connect');
  socket.write(`CONNECT ${authority} HTTP/1.1\r\nHost: ${authority}\r\n\r\n`);
  const [output] = await once(socket, 'data');
  return { socket, output: String(output) };
}
describe('dependency CONNECT proxy', () => {
  it('permits only exact official registry on port 443', async () => {
    const p = await proxy();
    for (const authority of ['evil.registry.npmjs.org:443', 'registry.npmjs.org:80', 'registry.npmjs.org', 'registry.npmjs.org:443:443', 'proxy.golang.org:443', '127.0.0.1:443']) {
      const result = await request(p.port, authority); expect(result.output).toContain('403'); result.socket.destroy();
    }
    const result = await request(p.port, 'registry.npmjs.org:443'); expect(result.output).toContain('200'); result.socket.destroy(); await p.close();
  });
  it('terminates all tunnels at the shared transfer budget', async () => {
    const p = await proxy(80);
    const result = await request(p.port, 'registry.npmjs.org:443');
    const closed = once(result.socket, 'close'); result.socket.write(Buffer.alloc(100)); await closed; await p.close();
  });
  it('terminates idle tunnels at the job deadline', async () => {
    const p = await proxy(10000, 250);
    const result = await request(p.port, 'registry.npmjs.org:443'); await once(result.socket, 'close'); await p.close();
  });
});
