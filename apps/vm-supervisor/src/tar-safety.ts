import { createReadStream } from 'node:fs';
import { stat } from 'node:fs/promises';

/**
 * Host-side tar safety inspection for `pushTree` uploads. Runs BEFORE any
 * guest extraction: rejects absolute paths, `..` traversal, device nodes,
 * escaping link targets, and unbounded entry counts. Handles ustar prefix
 * fields, GNU longname/longlink ('L'/'K') and PAX extended headers ('x') so
 * hidden path overrides cannot smuggle traversal past the check.
 *
 * The tar is produced by the RUNNER (trusted single-owner path), but the
 * staged bytes cross an authenticated-but-untrusted wire; validation is
 * defense-in-depth, not the primary boundary.
 */

const TAR_HEADER = 512;
const MAX_ENTRIES = 50_000;
const BLOCK_TYPES_ALLOWED = new Set(['0', '\0', '5', '1', '2', '7']);

export interface TarSafetyResult {
  safe: boolean;
  reason?: string;
  entryCount: number;
  /**
   * Archive member paths in order (only meaningful when safe). The guest
   * extractor uses them to reject pre-existing destination symlinks that
   * sit on any entry's ancestor path — the one vector archive inspection
   * cannot see because it lives in the guest filesystem, not the tar.
   */
  paths: string[];
}

function octal(field: Buffer): number {
  const text = field.toString('utf8').replace(/\0.*$/s, '').trim();
  if (text === '') return 0;
  const value = Number.parseInt(text, 8);
  return Number.isFinite(value) ? value : -1;
}

function cstr(field: Buffer): string {
  const idx = field.indexOf(0);
  return field.subarray(0, idx === -1 ? field.length : idx).toString('utf8');
}

/** Reject names that escape the extraction root. */
function pathSafe(name: string): boolean {
  if (name === '' || name.length > 4096) return false;
  if (name.startsWith('/') || name.startsWith('\\')) return false;
  if (name.includes('\0')) return false;
  const segments = name.split('/');
  for (const seg of segments) {
    if (seg === '..') return false;
  }
  return true;
}

/** Link targets (hardlink/symlink) must stay inside the extraction root. */
function linkSafe(target: string): boolean {
  if (target === '' || target.length > 4096) return false;
  if (target.startsWith('/') || target.startsWith('\\')) return false;
  return !target.split('/').includes('..');
}

/** Parse PAX extended-header content for path/linkpath overrides. */
function parsePaxOverrides(data: Buffer): { path?: string; linkpath?: string } {
  const out: { path?: string; linkpath?: string } = {};
  let offset = 0;
  while (offset < data.length) {
    const spaceIdx = data.indexOf(0x20, offset); // ' '
    if (spaceIdx === -1) break;
    const len = Number.parseInt(data.subarray(offset, spaceIdx).toString('utf8'), 10);
    if (!Number.isFinite(len) || len <= 0 || offset + len > data.length) break;
    const record = data.subarray(spaceIdx + 1, offset + len).toString('utf8');
    const eq = record.indexOf('=');
    if (eq !== -1) {
      const key = record.slice(0, eq);
      const value = record.slice(eq + 1).replace(/\n$/, '');
      if (key === 'path') out.path = value;
      else if (key === 'linkpath') out.linkpath = value;
    }
    offset += len;
  }
  return out;
}

interface PendingMeta {
  longName: string | undefined;
  longLink: string | undefined;
  paxPath: string | undefined;
  paxLink: string | undefined;
}

/**
 * Inspect a tar file for unsafe entries. Returns entryCount for the trailer.
 * Throws on I/O errors; malformed archives return safe:false.
 */
export async function inspectTarSafety(path: string, maxBytes: number): Promise<TarSafetyResult> {
  const fileStat = await stat(path);
  if (fileStat.size > maxBytes) {
    return { safe: false, reason: 'archive exceeds maxBytes', entryCount: 0, paths: [] };
  }
  const pending: PendingMeta = { longName: undefined, longLink: undefined, paxPath: undefined, paxLink: undefined };
  let entries = 0;
  let declaredBytes = 0n;
  let sawZeroBlock = false;
  const seen: { name: string; typeflag: string; linkTarget: string }[] = [];

  const stream = createReadStream(path, { highWaterMark: 1024 * 1024 });
  let carry: Buffer = Buffer.alloc(0);

  const processHeader = (header: Buffer, data: Buffer): string | undefined => {
    const typeflag = String.fromCharCode(header[156] ?? 0);
    if (typeflag === 'L') {
      pending.longName = cstr(data);
      return undefined;
    }
    if (typeflag === 'K') {
      pending.longLink = cstr(data);
      return undefined;
    }
    if (typeflag === 'x' || typeflag === 'g') {
      const pax = parsePaxOverrides(data);
      if (typeflag === 'x') {
        if (pax.path !== undefined) pending.paxPath = pax.path;
        if (pax.linkpath !== undefined) pending.paxLink = pax.linkpath;
      }
      return undefined;
    }
    if (!BLOCK_TYPES_ALLOWED.has(typeflag)) {
      return `unsupported entry type '${typeflag}'`;
    }
    entries += 1;
    if (entries > MAX_ENTRIES) return `too many entries (> ${MAX_ENTRIES})`;

    const prefix = cstr(header.subarray(345, 500));
    const rawName = cstr(header.subarray(0, 100));
    const headerName = prefix !== '' ? `${prefix}/${rawName}` : rawName;
    const name = pending.paxPath ?? pending.longName ?? headerName;
    const linkTarget = pending.paxLink ?? pending.longLink ?? cstr(header.subarray(157, 257));
    pending.longName = undefined;
    pending.longLink = undefined;
    pending.paxPath = undefined;
    pending.paxLink = undefined;

    if (!pathSafe(name)) return `unsafe entry path '${name.slice(0, 120)}'`;
    if ((typeflag === '1' || typeflag === '2') && linkTarget !== '' && !linkSafe(linkTarget)) {
      return `unsafe link target '${linkTarget.slice(0, 120)}'`;
    }
    seen.push({ name, typeflag, linkTarget });
    return undefined;
  };

  /** Proper ancestor dir paths of a member path ('a/b/c' -> ['a','a/b']). */
  const ancestors = (p: string): string[] => {
    const segs = p.split('/');
    const out: string[] = [];
    for (let i = 1; i < segs.length; i += 1) out.push(segs.slice(0, i).join('/'));
    return out;
  };
  const normalizeRel = (p: string): string => {
    const out: string[] = [];
    for (const seg of p.split('/')) {
      if (seg === '' || seg === '.') continue;
      out.push(seg);
    }
    return out.join('/');
  };

  try {
    for await (const chunk of stream) {
      carry = carry.length === 0 ? (chunk as Buffer) : Buffer.concat([carry, chunk as Buffer]);
      let offset = 0;
      while (carry.length - offset >= TAR_HEADER) {
        const header = carry.subarray(offset, offset + TAR_HEADER);
        if (header.every((b) => b === 0)) {
          sawZeroBlock = true;
          offset = carry.length; // consume rest; trailing blocks ignored
          break;
        }
        const size = octal(header.subarray(124, 136));
        if (size < 0) return { safe: false, reason: 'malformed tar size field', entryCount: entries, paths: [] };
        const padded = Math.ceil(size / TAR_HEADER) * TAR_HEADER;
        const need = TAR_HEADER + padded;
        if (carry.length - offset < need) break; // wait for more data
        const data = carry.subarray(offset + TAR_HEADER, offset + need);
        const problem = processHeader(header, data);
        if (problem !== undefined) {
          stream.destroy();
          return { safe: false, reason: problem, entryCount: entries, paths: [] };
        }
        declaredBytes += BigInt(size);
        if (declaredBytes > BigInt(maxBytes) * 4n) {
          stream.destroy();
          return { safe: false, reason: 'declared content exceeds bound', entryCount: entries, paths: [] };
        }
        offset += need;
      }
      carry = carry.subarray(offset);
      if (sawZeroBlock) break;
    }
  } finally {
    stream.destroy();
  }
  if (!sawZeroBlock && entries > 0) {
    // Truncated archive without end blocks — the guest tar would also fail;
    // treat as unsafe rather than risk partial extraction reporting success.
    return { safe: false, reason: 'archive missing terminator blocks', entryCount: entries, paths: [] };
  }
  // Cross-entry link canonicalization: every link target is already
  // lexically confined (no absolute/`..`), but ordering still matters — a
  // symlink created early must never sit on the ancestor path of any member
  // written later, and hardlinks may only target regular members. Reject
  // conservatively regardless of archive order: legitimate tars never nest
  // members beneath their own link paths.
  const linkPaths = new Set<string>();
  const regularPaths = new Set<string>();
  for (const e of seen) {
    if (e.typeflag === '1' || e.typeflag === '2') linkPaths.add(e.name);
    else if (e.typeflag === '0' || e.typeflag === '\0' || e.typeflag === '7') regularPaths.add(e.name);
  }
  for (const e of seen) {
    for (const anc of ancestors(e.name)) {
      if (linkPaths.has(anc)) {
        return { safe: false, reason: `member '${e.name.slice(0, 120)}' nests beneath link '${anc.slice(0, 120)}'`, entryCount: entries, paths: [] };
      }
    }
    if (e.typeflag === '1') {
      // Hardlink linkpath names another archive member: accept the
      // root-relative spelling or one resolved against the link's dir.
      const dir = e.name.includes('/') ? e.name.slice(0, e.name.lastIndexOf('/')) : '';
      const candidates = [normalizeRel(e.linkTarget), normalizeRel(dir === '' ? e.linkTarget : `${dir}/${e.linkTarget}`)];
      const ok = candidates.some((c) => regularPaths.has(c) && !ancestors(c).some((a) => linkPaths.has(a)));
      if (!ok) {
        return { safe: false, reason: `hardlink '${e.name.slice(0, 120)}' target is not a regular archive member`, entryCount: entries, paths: [] };
      }
    }
  }
  return { safe: true, entryCount: entries, paths: seen.map((e) => e.name) };
}
