/* Shared IPv4 / IPv6 prefix math (BigInt based): parsing, ranges, aggregation, subtraction, VLSM.
   Depends on common.js (parseIPv4, parseIPv6, fmtIPv4, fmtIPv6). */
const ALL4 = (1n << 32n) - 1n, ALL6 = (1n << 128n) - 1n;
const bitsOf = v => v === 4 ? 32 : 128;
const allOf = v => v === 4 ? ALL4 : ALL6;
const fmtIP = (n, v) => v === 4 ? fmtIPv4(Number(n)) : fmtIPv6(n);
const parseAny = s => { const a = parseIPv4(s); if (a != null) return { n: BigInt(a), v: 4 }; const b = parseIPv6(s); return b != null ? { n: b, v: 6 } : null; };
const maskOf = (p, v) => p === 0 ? 0n : allOf(v) ^ ((1n << BigInt(bitsOf(v) - p)) - 1n);
const cidrStr = (net, p, v) => `${fmtIP(net, v)}/${p}`;
const blockSize = (p, v) => 1n << BigInt(bitsOf(v) - p);

function maskToPrefix(m){   // accepts netmask (255.255.255.0) or wildcard (0.0.0.255)
  const n = parseIPv4(m); if (n == null) return null;
  const b = n.toString(2).padStart(32, '0');
  if (/^1*0*$/.test(b)) return { p: b.indexOf('0') < 0 ? 32 : b.indexOf('0') };
  if (/^0*1*$/.test(b)) return { p: b.indexOf('1') < 0 ? 32 : b.indexOf('1'), wildcard: true };
  return null;
}

// "10.1.2.3/24", "10.1.2.3 255.255.255.0", "10.1.2.3 0.0.0.255", "2001:db8::/32", bare IP (= host route)
function parseCIDR(s){
  s = String(s).trim().replace(/\s+/g, ' ');
  let m = s.match(/^([^\s\/]+)\s*\/\s*(\d{1,3})$/), ip, p;
  if (m) { ip = parseAny(m[1]); p = +m[2]; }
  else if ((m = s.match(/^(\S+)\s+(\d+\.\d+\.\d+\.\d+)$/))) { ip = parseAny(m[1]); const r = maskToPrefix(m[2]); if (!r) return null; p = r.p; }
  else { ip = parseAny(s); p = ip ? bitsOf(ip.v) : null; }
  if (!ip || p == null || p > bitsOf(ip.v)) return null;
  const mask = maskOf(p, ip.v);
  const net = ip.n & mask, last = net | (allOf(ip.v) ^ mask);
  return { ...ip, p, mask, net, last, size: blockSize(p, ip.v) };
}

// usable host addresses in a block (IPv4 drops network + broadcast except /31 and /32)
function usableHosts(p, v){ if (v === 6) return blockSize(p, v); return p === 32 ? 1n : p === 31 ? 2n : blockSize(p, v) - 2n; }
function usableRange(net, p, v){
  const last = net + blockSize(p, v) - 1n;
  return v === 4 && p < 31 ? [net + 1n, last - 1n] : [net, last];
}
// smallest prefix whose usable host count is >= n
function prefixForHosts(n, v){ n = BigInt(n); for (let p = bitsOf(v); p >= 0; p--) if (usableHosts(p, v) >= n) return p; return null; }

/* ---------- ranges ---------- */
// Lines of CIDRs, masks, single IPs or "a - b" ranges. Returns { out: [{v, s, e, line}], bad: [line] }
function parseRanges(text){
  const out = [], bad = [];
  for (let line of String(text).split(/\n|,/)) {
    line = line.replace(/#.*/, '').trim(); if (!line) continue;
    const m = line.match(/^(\S+)\s*-\s*(\S+)$/);
    if (m) { const a = parseAny(m[1]), b = parseAny(m[2]); if (a && b && a.v === b.v && a.n <= b.n) { out.push({ v: a.v, s: a.n, e: b.n, line }); continue; } }
    const c = parseCIDR(line); if (c) out.push({ v: c.v, s: c.net, e: c.last, line }); else bad.push(line);
  }
  return { out, bad };
}
const cmpBig = (a, b) => a < b ? -1 : a > b ? 1 : 0;
function mergeRanges(list){
  const res = [];
  for (const v of [4, 6]) {
    const r = list.filter(x => x.v === v).sort((a, b) => cmpBig(a.s, b.s)), merged = [];
    for (const x of r) { const L = merged.at(-1); if (L && x.s <= L.e + 1n) { if (x.e > L.e) L.e = x.e; } else merged.push({ v, s: x.s, e: x.e }); }
    res.push(...merged);
  }
  return res;
}
// smallest exact set of CIDR blocks covering [s, e]
function rangeToBlocks(s, e, v){
  const B = bitsOf(v), res = [];
  while (s <= e) {
    let p = B;
    while (p > 0) { const blk = 1n << BigInt(B - p + 1); if (s % blk === 0n && s + blk - 1n <= e) p--; else break; }
    res.push({ net: s, p, v }); s += 1n << BigInt(B - p);
  }
  return res;
}
const rangeToCidrs = (s, e, v) => rangeToBlocks(s, e, v).map(b => cidrStr(b.net, b.p, v));
function aggregateRanges(list){ return mergeRanges(list).flatMap(r => rangeToCidrs(r.s, r.e, r.v)); }
// base minus cuts, both as range lists; returns merged ranges
function subtractRanges(base, cuts){
  let cur = mergeRanges(base);
  for (const c of mergeRanges(cuts)) {
    const next = [];
    for (const r of cur) {
      if (r.v !== c.v || c.e < r.s || c.s > r.e) { next.push(r); continue; }
      if (c.s > r.s) next.push({ v: r.v, s: r.s, e: c.s - 1n });
      if (c.e < r.e) next.push({ v: r.v, s: c.e + 1n, e: r.e });
    }
    cur = next;
  }
  return cur;
}

/* ---------- VLSM ----------
   reqs: [{ name, hosts }]. Allocates largest-first, sequentially from the start of the parent —
   descending block sizes keep every allocation naturally aligned. */
function vlsmAllocate(parent, reqs){
  const v = parent.v, rows = reqs.map((r, i) => ({ ...r, i, p: prefixForHosts(r.hosts, v) }));
  rows.sort((a, b) => a.p - b.p || a.i - b.i);
  let cursor = parent.net; const end = parent.last;
  for (const r of rows) {
    if (r.p == null || r.p < parent.p) { r.fits = false; continue; }
    const size = blockSize(r.p, v);
    if (cursor + size - 1n > end) { r.fits = false; continue; }
    r.fits = true; r.net = cursor; r.last = cursor + size - 1n; cursor += size;
  }
  const used = rows.filter(r => r.fits).map(r => ({ v, s: r.net, e: r.last }));
  const free = subtractRanges([{ v, s: parent.net, e: parent.last }], used).flatMap(r => rangeToBlocks(r.s, r.e, v));
  return { rows, free };
}
