/* Minimal in-browser packet capture engine: pcap / pcapng parsing, protocol decoding,
   flow reassembly and analyses (scans, DNS/DGA, ICMP channels, HTTP, credentials).
   Depends on: common.js (fmtIPv6, parseIPv4…), decoders.js (asLatin, findFlags, entropy, inflate…) */

/* ---------- container parsing ---------- */
function parseCapture(buf){
  const dv = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const m = dv.getUint32(0, false);
  if (m === 0x0a0d0d0a) return parsePcapng(buf, dv);
  if ([0xa1b2c3d4, 0xd4c3b2a1, 0xa1b23c4d, 0x4d3cb2a1].includes(m)) return parsePcap(buf, dv);
  throw new Error('Not a pcap / pcapng file (unknown magic ' + m.toString(16) + ')');
}
function parsePcap(buf, dv){
  const m = dv.getUint32(0, false), le = m === 0xd4c3b2a1 || m === 0x4d3cb2a1, ns = m === 0xa1b23c4d || m === 0x4d3cb2a1;
  const link = dv.getUint32(20, le), out = [];
  let o = 24;
  while (o + 16 <= buf.length) {
    const sec = dv.getUint32(o, le), frac = dv.getUint32(o + 4, le), incl = dv.getUint32(o + 8, le), orig = dv.getUint32(o + 12, le);
    if (o + 16 + incl > buf.length) break;
    out.push({ ts: sec + frac / (ns ? 1e9 : 1e6), link, len: orig, data: buf.subarray(o + 16, o + 16 + incl) });
    o += 16 + incl;
  }
  return { format: `pcap${ns ? ' (ns)' : ''}`, links: [link], packets: out };
}
function parsePcapng(buf, dv){
  const out = [], ifaces = []; let le = true, o = 0, shb = {};
  while (o + 12 <= buf.length) {
    let type = dv.getUint32(o, le);
    if (type === 0x0a0d0d0a || dv.getUint32(o, false) === 0x0a0d0d0a) {
      const bom = dv.getUint32(o + 8, true); le = bom === 0x1a2b3c4d; type = 0x0a0d0d0a; ifaces.length = 0;
      const len = dv.getUint32(o + 4, le);
      shb = parseOpts(buf, dv, o + 24, o + len - 4, le); o += len; continue;
    }
    const len = dv.getUint32(o + 4, le);
    if (len < 12 || o + len > buf.length) break;
    if (type === 1) {           // Interface Description Block
      const link = dv.getUint16(o + 8, le), opts = parseOpts(buf, dv, o + 16, o + len - 4, le);
      let res = 1e-6; if (opts[9]) { const v = opts[9][0]; res = v & 0x80 ? Math.pow(2, -(v & 0x7f)) : Math.pow(10, -v); }
      ifaces.push({ link, res, name: opts[2] ? asLatin(opts[2]) : '' });
    } else if (type === 6) {    // Enhanced Packet Block
      const id = dv.getUint32(o + 8, le), hi = dv.getUint32(o + 12, le), lo = dv.getUint32(o + 16, le), cap = dv.getUint32(o + 20, le), orig = dv.getUint32(o + 24, le);
      const ifc = ifaces[id] || { link: 1, res: 1e-6 };
      out.push({ ts: (hi * 4294967296 + lo) * ifc.res, link: ifc.link, len: orig, data: buf.subarray(o + 28, o + 28 + cap), iface: id });
    } else if (type === 3) {    // Simple Packet Block
      const orig = dv.getUint32(o + 8, le), ifc = ifaces[0] || { link: 1 };
      out.push({ ts: 0, link: ifc.link, len: orig, data: buf.subarray(o + 12, o + 12 + Math.min(orig, len - 16)) });
    } else if (type === 2) {    // obsolete Packet Block
      const id = dv.getUint16(o + 8, le), hi = dv.getUint32(o + 12, le), lo = dv.getUint32(o + 16, le), cap = dv.getUint32(o + 20, le), orig = dv.getUint32(o + 24, le);
      const ifc = ifaces[id] || { link: 1, res: 1e-6 };
      out.push({ ts: (hi * 4294967296 + lo) * ifc.res, link: ifc.link, len: orig, data: buf.subarray(o + 28, o + 28 + cap) });
    }
    o += len;
  }
  const app = shb[4] ? asLatin(shb[4]) : '', os = shb[3] ? asLatin(shb[3]) : '', hw = shb[2] ? asLatin(shb[2]) : '';
  return { format: 'pcapng', links: [...new Set(ifaces.map(i => i.link))], packets: out, capInfo: { app, os, hw, ifaces: ifaces.map(i => i.name).filter(Boolean) } };
}
function parseOpts(buf, dv, o, end, le){
  const r = {};
  while (o + 4 <= end) { const code = dv.getUint16(o, le), l = dv.getUint16(o + 2, le); if (code === 0) break; r[code] = buf.subarray(o + 4, o + 4 + l); o += 4 + ((l + 3) & ~3); }
  return r;
}

/* ---------- protocol decoding ---------- */
const ipv4s = (b, o) => `${b[o]}.${b[o + 1]}.${b[o + 2]}.${b[o + 3]}`;
const ipv6s = (b, o) => { let n = 0n; for (let i = 0; i < 16; i++) n = (n << 8n) | BigInt(b[o + i]); return fmtIPv6(n); };
const macs = (b, o) => [...b.subarray(o, o + 6)].map(x => x.toString(16).padStart(2, '0')).join(':');
const u16 = (b, o) => (b[o] << 8) | b[o + 1];
const u32b = (b, o) => ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0;
const TCPF = ['F', 'S', 'R', 'P', 'A', 'U', 'E', 'C'];
const PORTNAMES = {20:'ftp-data',21:'ftp',22:'ssh',23:'telnet',25:'smtp',53:'dns',67:'dhcp',68:'dhcp',69:'tftp',80:'http',88:'kerberos',110:'pop3',123:'ntp',135:'msrpc',137:'netbios-ns',138:'netbios-dgm',139:'netbios-ssn',143:'imap',161:'snmp',162:'snmptrap',389:'ldap',443:'https',445:'smb',465:'smtps',514:'syslog',587:'submission',636:'ldaps',853:'dns-over-tls',993:'imaps',995:'pop3s',1080:'socks',1433:'mssql',1521:'oracle',1883:'mqtt',1900:'ssdp',2049:'nfs',3306:'mysql',3389:'rdp',4444:'metasploit?',5060:'sip',5353:'mdns',5432:'postgres',5555:'adb',5900:'vnc',5985:'winrm',6379:'redis',6667:'irc',8000:'http-alt',8080:'http-proxy',8443:'https-alt',8888:'http-alt',9001:'tor?',9200:'elasticsearch',27017:'mongodb'};
const ICMPT = {0:'echo reply',3:'dest unreachable',5:'redirect',8:'echo request',11:'time exceeded',13:'timestamp',30:'traceroute'};

function decodePacket(p){
  const b = p.data; let o = 0, eth = 0;
  try {
    switch (p.link) {
      case 1: p.srcMac = macs(b, 6); p.dstMac = macs(b, 0); eth = u16(b, 12); o = 14;
        while (eth === 0x8100 || eth === 0x88a8) { p.vlan = u16(b, o) & 0xfff; eth = u16(b, o + 2); o += 4; } break;
      case 0: case 108: { const fam = b[0] || b[3]; eth = fam === 2 ? 0x0800 : [24, 28, 30, 10].includes(fam) ? 0x86dd : 0; o = 4; break; }
      case 101: case 12: case 14: eth = (b[0] >> 4) === 6 ? 0x86dd : 0x0800; o = 0; break;
      case 228: eth = 0x0800; break; case 229: eth = 0x86dd; break;
      case 113: eth = u16(b, 14); o = 16; break;
      case 276: eth = u16(b, 0); o = 20; break;
      default: p.proto = 'link ' + p.link; p.info = `Unsupported link type ${p.link}`; return p;
    }
    if (eth === 0x0806) return decodeARP(p, b, o);
    if (eth === 0x0800) { const ihl = (b[o] & 15) * 4, tot = u16(b, o + 2); p.ipv = 4; p.src = ipv4s(b, o + 12); p.dst = ipv4s(b, o + 16); p.ttl = b[o + 8]; p.ipid = u16(b, o + 4); p.l4 = b[o + 9];
      const frag = u16(b, o + 6); p.fragOff = (frag & 0x1fff) * 8; p.mf = !!(frag & 0x2000);
      const end = Math.min(b.length, o + (tot || b.length - o)); return decodeL4(p, b.subarray(0, end), o + ihl); }
    if (eth === 0x86dd) { p.ipv = 6; p.src = ipv6s(b, o + 8); p.dst = ipv6s(b, o + 24); p.ttl = b[o + 7]; let nh = b[o + 6], q = o + 40;
      const plen = u16(b, o + 4);
      while ([0, 43, 60, 51].includes(nh) && q + 8 <= b.length) { const n2 = b[q]; q += nh === 51 ? (b[q + 1] + 2) * 4 : (b[q + 1] + 1) * 8; nh = n2; }
      if (nh === 44) { nh = b[q]; q += 8; }
      p.l4 = nh; return decodeL4(p, b.subarray(0, Math.min(b.length, o + 40 + plen)), q); }
    p.proto = 'eth 0x' + eth.toString(16); p.info = `Ethertype 0x${eth.toString(16)}`;
  } catch (e) { p.proto = p.proto || 'malformed'; p.info = 'Malformed: ' + e.message; }
  return p;
}
function decodeARP(p, b, o){
  const op = u16(b, o + 6); p.proto = 'ARP';
  p.src = ipv4s(b, o + 14); p.dst = ipv4s(b, o + 24); p.arpOp = op; p.arpMac = macs(b, o + 8);
  p.info = op === 1 ? `Who has ${p.dst}? Tell ${p.src}` : op === 2 ? `${p.src} is at ${p.arpMac}` : `ARP op ${op}`;
  return p;
}
function decodeL4(p, b, o){
  if (p.fragOff) { p.proto = `IPv${p.ipv} fragment`; p.info = `Fragment offset ${p.fragOff}`; p.payload = b.subarray(o); return p; }
  if (p.l4 === 6) {
    const off = (b[o + 12] >> 4) * 4, fl = b[o + 13] | ((b[o + 12] & 1) << 8);
    p.proto = 'TCP'; p.sport = u16(b, o); p.dport = u16(b, o + 2); p.seq = u32b(b, o + 4); p.ack = u32b(b, o + 8); p.flags = fl & 0xff; p.win = u16(b, o + 14);
    p.fstr = TCPF.filter((_, i) => fl & (1 << i)).join('') || '0';
    p.payload = b.subarray(o + off);
    if (off > 20) p.tcpOpts = b.subarray(o + 20, o + off);
    p.info = `${p.sport} → ${p.dport} [${p.fstr}] seq=${p.seq}${p.flags & 16 ? ' ack=' + p.ack : ''} win=${p.win}${p.payload.length ? ' len=' + p.payload.length : ''}`;
    appLayer(p);
  } else if (p.l4 === 17) {
    p.proto = 'UDP'; p.sport = u16(b, o); p.dport = u16(b, o + 2); p.payload = b.subarray(o + 8, Math.min(b.length, o + Math.max(8, u16(b, o + 4))));
    p.info = `${p.sport} → ${p.dport} len=${p.payload.length}`;
    appLayer(p);
  } else if (p.l4 === 1 || p.l4 === 58) {
    p.proto = p.l4 === 1 ? 'ICMP' : 'ICMPv6'; p.icmpType = b[o]; p.icmpCode = b[o + 1];
    const echo = p.l4 === 1 ? [0, 8].includes(p.icmpType) : [128, 129].includes(p.icmpType);
    if (echo) { p.icmpId = u16(b, o + 4); p.icmpSeq = u16(b, o + 6); }
    p.payload = b.subarray(o + 8);
    const tn = p.l4 === 1 ? ICMPT[p.icmpType] : { 128: 'echo request', 129: 'echo reply', 133: 'router solicit', 134: 'router advert', 135: 'neighbor solicit', 136: 'neighbor advert', 1: 'dest unreachable' }[p.icmpType];
    p.isEchoReq = p.l4 === 1 ? p.icmpType === 8 : p.icmpType === 128;
    p.isEchoRep = p.l4 === 1 ? p.icmpType === 0 : p.icmpType === 129;
    p.info = `${tn || 'type ' + p.icmpType}${p.icmpCode ? ' code ' + p.icmpCode : ''}${echo ? ` id=${p.icmpId} seq=${p.icmpSeq}` : ''}${p.payload.length ? ' len=' + p.payload.length : ''}`;
    if (p.payload.length && printableRatio(p.payload) > 0.8 && !(p.icmpType === 3 || p.icmpType === 11)) p.info += ` “${safeText(p.payload, 40)}”`;
  } else { p.proto = { 2: 'IGMP', 47: 'GRE', 50: 'ESP', 51: 'AH', 89: 'OSPF', 103: 'PIM', 112: 'VRRP', 132: 'SCTP' }[p.l4] || `IP proto ${p.l4}`; p.payload = b.subarray(o); p.info = p.proto; }
  return p;
}
function appLayer(p){
  const pl = p.payload, ports = [p.sport, p.dport];
  if (ports.includes(53) || ports.includes(5353) || ports.includes(5355)) {
    const d = parseDNS(p.proto === 'TCP' && pl.length > 2 ? pl.subarray(2) : pl);
    if (d) { p.dns = d; p.app = ports.includes(5353) ? 'mDNS' : ports.includes(5355) ? 'LLMNR' : 'DNS';
      p.info = d.qr ? `Response ${d.rcodeName} ${d.qname || ''} ${d.answers.map(a => a.type + ' ' + a.data).slice(0, 3).join(', ')}` : `Query ${d.qtypeName} ${d.qname || ''}`; return; }
  }
  if (!pl || !pl.length) return;
  if (p.proto === 'TCP' && pl[0] === 0x16 && pl[1] === 3 && pl[5] === 1) { const sni = tlsSNI(pl); p.app = 'TLS'; p.sni = sni; p.info = `TLS ClientHello${sni ? ' SNI=' + sni : ''}`; return; }
  if (p.proto === 'TCP' && pl[0] >= 0x14 && pl[0] <= 0x17 && pl[1] === 3) { p.app = 'TLS'; p.info = { 0x14: 'TLS ChangeCipherSpec', 0x15: 'TLS Alert', 0x16: 'TLS Handshake', 0x17: 'TLS Application Data' }[pl[0]]; return; }
  const head = asLatin(pl.subarray(0, 200));
  let m;
  if ((m = head.match(/^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT) (\S+) HTTP\/\d/))) { p.app = 'HTTP'; const host = (head.match(/\r\nHost: *([^\r\n]+)/i) || [])[1] || ''; p.info = `${m[1]} ${host}${m[2]}`; return; }
  if ((m = head.match(/^HTTP\/\d(?:\.\d)? (\d{3}[^\r\n]*)/))) { p.app = 'HTTP'; p.info = `HTTP ${m[1]}`; return; }
  if (/^SSH-\d/.test(head)) { p.app = 'SSH'; p.info = head.split(/\r?\n/)[0]; return; }
  if (ports.includes(21) && /^[A-Z]{3,4}( |\r)|^\d{3}[ -]/.test(head)) { p.app = 'FTP'; p.info = 'FTP ' + head.split(/\r?\n/)[0]; return; }
  if (ports.some(x => [25, 587, 110, 143, 23].includes(x)) && printableRatio(pl) > 0.9) { p.app = { 25: 'SMTP', 587: 'SMTP', 110: 'POP3', 143: 'IMAP', 23: 'Telnet' }[ports.find(x => [25, 587, 110, 143, 23].includes(x))]; p.info = p.app + ' ' + safeText(pl, 60).split('\n')[0]; return; }
  if (p.proto === 'UDP' && ports.includes(123)) { p.app = 'NTP'; return; }
  if (p.proto === 'UDP' && (ports.includes(67) || ports.includes(68))) { p.app = 'DHCP'; return; }
  if (printableRatio(pl) > 0.85) p.info += ` “${safeText(pl, 50).replace(/\n/g, '⏎')}”`;
}

/* ---------- DNS ---------- */
const QTYPES = {1:'A',2:'NS',5:'CNAME',6:'SOA',12:'PTR',15:'MX',16:'TXT',28:'AAAA',33:'SRV',35:'NAPTR',43:'DS',48:'DNSKEY',64:'SVCB',65:'HTTPS',99:'SPF',255:'ANY',257:'CAA',10:'NULL'};
const RCODES = {0:'NOERROR',1:'FORMERR',2:'SERVFAIL',3:'NXDOMAIN',4:'NOTIMP',5:'REFUSED'};
function dnsName(b, off){
  const labels = []; let pos = off, end = -1, jumps = 0;
  while (pos < b.length) {
    const l = b[pos];
    if (l === 0) { pos++; break; }
    if ((l & 0xc0) === 0xc0) { if (end < 0) end = pos + 2; pos = ((l & 0x3f) << 8) | b[pos + 1]; if (++jumps > 30) break; continue; }
    if (l > 63) throw new Error('bad label');
    labels.push(asLatin(b.subarray(pos + 1, pos + 1 + l))); pos += 1 + l;
  }
  return [labels.join('.'), end < 0 ? pos : end];
}
function parseDNS(b){
  if (!b || b.length < 12) return null;
  try {
    const id = u16(b, 0), fl = u16(b, 2), qd = u16(b, 4), an = u16(b, 6), ns = u16(b, 8), ar = u16(b, 10);
    if (qd > 20 || an > 200) return null;
    const d = { id, qr: !!(fl & 0x8000), rcode: fl & 15, rcodeName: RCODES[fl & 15] || 'rcode ' + (fl & 15), questions: [], answers: [] };
    let o = 12;
    for (let i = 0; i < qd; i++) { const [n, e] = dnsName(b, o); const t = u16(b, e); d.questions.push({ name: n, type: QTYPES[t] || t }); o = e + 4; }
    for (let i = 0; i < an + ns + ar && o < b.length; i++) {
      const [n, e] = dnsName(b, o); const t = u16(b, e), ttl = u32b(b, e + 4), rl = u16(b, e + 8), rd = e + 10; let data = '';
      if (t === 1 && rl === 4) data = ipv4s(b, rd);
      else if (t === 28 && rl === 16) data = ipv6s(b, rd);
      else if ([2, 5, 12].includes(t)) data = dnsName(b, rd)[0];
      else if (t === 15) data = u16(b, rd) + ' ' + dnsName(b, rd + 2)[0];
      else if (t === 16) { let q = rd; const parts = []; while (q < rd + rl) { const l = b[q]; parts.push(asLatin(b.subarray(q + 1, q + 1 + l))); q += 1 + l; } data = parts.join(''); }
      else data = toHex(b.subarray(rd, rd + Math.min(rl, 64)));
      if (i < an) d.answers.push({ name: n, type: QTYPES[t] || t, ttl, data });
      o = rd + rl;
    }
    d.qname = d.questions[0]?.name; d.qtypeName = d.questions[0]?.type;
    return d;
  } catch { return null; }
}
function tlsSNI(b){
  try {
    let o = 5 + 4 + 2 + 32; o += 1 + b[o]; o += 2 + u16(b, o); o += 1 + b[o];
    const end = o + 2 + u16(b, o); o += 2;
    while (o + 4 <= end && o + 4 <= b.length) { const t = u16(b, o), l = u16(b, o + 2); if (t === 0) { const nl = u16(b, o + 7); return asLatin(b.subarray(o + 9, o + 9 + nl)); } o += 4 + l; }
  } catch {}
  return null;
}

/* ---------- flows & reassembly ---------- */
function buildFlows(P){
  const flows = new Map();
  for (const p of P) {
    if (!p.src || p.sport == null) continue;
    const a = `${p.src}|${p.sport}`, b = `${p.dst}|${p.dport}`, key = `${p.proto}:${a < b ? a + '~' + b : b + '~' + a}`;
    let f = flows.get(key);
    if (!f) {
      // client = sender of first pure SYN, else lower-numbered (ephemeral → service) heuristic
      const synFromSrc = p.proto === 'TCP' && p.fstr === 'S';
      const srcIsClient = synFromSrc || !(p.proto === 'TCP' && p.fstr === 'SA') && (p.sport > p.dport || p.sport >= 1024 && p.dport < 1024);
      f = { key, proto: p.proto, cli: srcIsClient ? p.src : p.dst, cport: srcIsClient ? p.sport : p.dport, srv: srcIsClient ? p.dst : p.src, sport: srcIsClient ? p.dport : p.sport, pkts: [], bytes: 0, first: p.ts, last: p.ts, app: null };
      flows.set(key, f);
    }
    f.pkts.push(p); f.bytes += p.len; f.last = p.ts; if (p.app && !f.app) f.app = p.app; p.flow = f;
  }
  return [...flows.values()];
}
function reassemble(f, fromClient){
  const segs = f.pkts.filter(p => p.payload?.length && (p.src === (fromClient ? f.cli : f.srv)) && (p.sport === (fromClient ? f.cport : f.sport)));
  if (f.proto !== 'TCP') return concatBytes(segs.map(p => p.payload));
  segs.sort((a, b) => a.seq - b.seq);
  const parts = []; let next = null;
  for (const s of segs) {
    let d = s.payload;
    if (next !== null && s.seq < next) { if (next - s.seq >= d.length) continue; d = d.subarray(next - s.seq); }   // retransmission / overlap
    parts.push(d); next = (next === null ? s.seq : Math.max(next, s.seq)) + d.length;
  }
  return concatBytes(parts);
}
function concatBytes(arr){ const n = arr.reduce((a, b) => a + b.length, 0), o = new Uint8Array(n); let i = 0; for (const a of arr) { o.set(a, i); i += a.length; } return o; }
/* interleaved conversation (chronological chunks, for "follow stream") */
function conversation(f){
  const out = [];
  for (const p of f.pkts) { if (!p.payload?.length) continue; const c = p.src === f.cli && p.sport === f.cport; const last = out.at(-1); if (last && last.c === c) last.parts.push(p.payload); else out.push({ c, parts: [p.payload] }); }
  return out.map(x => ({ c: x.c, data: concatBytes(x.parts) }));
}

/* ---------- HTTP ---------- */
async function httpObjects(f){
  const req = asLatin(reassemble(f, true)), resB = reassemble(f, false), objs = [];
  const reqs = [...req.matchAll(/(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH) (\S+) HTTP\/[\d.]+\r?\n([\s\S]*?)\r?\n\r?\n/g)].map(m => ({ method: m[1], uri: m[2], headers: m[3], idx: m.index, host: (m[3].match(/^Host: *(.+)$/mi) || [])[1]?.trim() || f.srv, body: '' }));
  reqs.forEach((r, i) => { const cl = +((r.headers.match(/^Content-Length: *(\d+)/mi) || [])[1] || 0); const start = req.indexOf('\n\r\n', r.idx) + 3; if (cl) r.body = req.slice(start, start + cl); r.auth = (r.headers.match(/^Authorization: *(.+)$/mi) || [])[1]; r.cookie = (r.headers.match(/^Cookie: *(.+)$/mi) || [])[1]; r.ua = (r.headers.match(/^User-Agent: *(.+)$/mi) || [])[1]; });
  let o = 0, ri = 0; const s = asLatin(resB);
  while (o < resB.length) {
    const st = s.indexOf('HTTP/', o); if (st < 0) break;
    const he = s.indexOf('\r\n\r\n', st); if (he < 0) break;
    const head = s.slice(st, he), status = (head.match(/^HTTP\/[\d.]+ (\d{3}[^\r\n]*)/) || [])[1] || '?';
    const H = k => (head.match(new RegExp('^' + k + ': *([^\\r\\n]+)', 'mi')) || [])[1];
    let body, end;
    const bs = he + 4;
    if (/chunked/i.test(H('Transfer-Encoding') || '')) {
      const parts = []; let q = bs;
      for (;;) { const le = s.indexOf('\r\n', q); if (le < 0) break; const n = parseInt(s.slice(q, le), 16); if (isNaN(n)) break; if (n === 0) { q = le + 4; break; } parts.push(resB.subarray(le + 2, le + 2 + n)); q = le + 2 + n + 2; }
      body = concatBytes(parts); end = q;
    } else if (H('Content-Length') != null) { const n = +H('Content-Length'); body = resB.subarray(bs, bs + n); end = bs + n; }
    else { const nx = s.indexOf('HTTP/1.', bs); end = nx > 0 ? nx : resB.length; body = resB.subarray(bs, end); }
    const enc = (H('Content-Encoding') || '').toLowerCase();
    if (body.length && (enc.includes('gzip') || enc.includes('deflate'))) { try { body = await inflate(body, enc.includes('gzip') ? 'gzip' : 'deflate'); } catch {} }
    const r = reqs[ri++] || {};
    objs.push({ status, ctype: H('Content-Type') || '', server: H('Server'), body, method: r.method, uri: r.uri, host: r.host, setCookie: H('Set-Cookie'), location: H('Location') });
    o = Math.max(end, st + 5);
  }
  return { reqs, objs };
}

/* ---------- analyses ---------- */
function analyzeScans(P){
  const pairs = new Map();
  for (const p of P) {
    if (p.proto === 'TCP') {
      const k = p.src + '>' + p.dst;
      if (!pairs.has(k)) pairs.set(k, { src: p.src, dst: p.dst, probes: new Map(), flagsSeen: new Map(), udp: new Set() });
      const e = pairs.get(k);
      if (!(p.flags & 0x10) || p.fstr === 'A') { e.probes.set(p.dport, (e.probes.get(p.dport) || 0) + 1); e.flagsSeen.set(p.fstr, (e.flagsSeen.get(p.fstr) || 0) + 1); if (!e.order) e.order = []; if (!e.probes.get(p.dport) || e.probes.get(p.dport) === 1) e.order.push(p.dport); }
    } else if (p.proto === 'UDP' && p.sport > p.dport) {   // probes go from a high source port to the service port; skip replies
      const k = p.src + '>' + p.dst;
      if (!pairs.has(k)) pairs.set(k, { src: p.src, dst: p.dst, probes: new Map(), flagsSeen: new Map(), udp: new Set() });
      pairs.get(k).udp.add(p.dport);
    }
  }
  const scans = [];
  for (const e of pairs.values()) {
    const tcpPorts = e.probes.size, udpPorts = e.udp.size;
    if (tcpPorts < 15 && udpPorts < 15) continue;
    const back = pairs.get(e.dst + '>' + e.src);
    const res = { src: e.src, dst: e.dst, ports: tcpPorts, open: [], closed: 0, filtered: 0, type: '', nmap: '', notes: [] };
    if (tcpPorts >= 15) {
      const fs = e.flagsSeen; const top = [...fs.entries()].sort((a, b) => b[1] - a[1])[0][0];
      // responses from target
      const resp = P.filter(p => p.proto === 'TCP' && p.src === e.dst && p.dst === e.src);
      const sa = new Set(resp.filter(p => p.fstr === 'SA').map(p => p.sport));
      const rst = new Set(resp.filter(p => p.flags & 4).map(p => p.sport));
      const answered = new Set(resp.map(p => p.sport));
      const icmpUnreach = P.filter(p => p.proto === 'ICMP' && p.src === e.dst && p.icmpType === 3).length;
      if (top === 'S') {
        const completed = [...sa].filter(port => P.some(p => p.proto === 'TCP' && p.src === e.src && p.dst === e.dst && p.dport === port && p.fstr === 'A'));
        const rstOnly = [...sa].filter(port => P.some(p => p.proto === 'TCP' && p.src === e.src && p.dst === e.dst && p.dport === port && p.fstr === 'R'));
        if (completed.length && completed.length >= rstOnly.length) { res.type = 'TCP Connect scan'; res.nmap = '-sT'; res.notes.push('Open ports complete the 3-way handshake (SYN → SYN-ACK → ACK) before RST — full connect() scan.'); }
        else if (sa.size) { res.type = 'TCP SYN (half-open / stealth) scan'; res.nmap = '-sS'; res.notes.push('Open ports are answered with a bare RST instead of ACK — half-open SYN scan.'); }
        else { res.type = 'TCP SYN or Connect scan (no open ports seen)'; res.nmap = '-sS / -sT'; }
        res.open = [...sa].sort((a, b) => a - b); res.closed = [...rst].filter(x => !sa.has(x)).length;
        res.filtered = tcpPorts - answered.size;
      } else {
        const map = { F: ['FIN scan', '-sF'], '0': ['NULL scan', '-sN'], FPU: ['Xmas scan', '-sX'], A: ['ACK scan (firewall mapping)', '-sA'], FA: ['Maimon scan', '-sM'] };
        const t = map[top] || [`Unusual-flag scan (${top})`, '--scanflags'];
        res.type = t[0]; res.nmap = t[1];
        if (top === 'A') { res.notes.push('RST replies = unfiltered, no reply = filtered. ACK scans do not reveal open ports.'); res.unfiltered = rst.size; }
        else { const open = [...e.probes.keys()].filter(port => !rst.has(port)); res.open = open.sort((a, b) => a - b); res.notes.push('Ports without an RST reply are open|filtered.'); res.closed = rst.size; }
      }
      if (icmpUnreach) res.notes.push(`${icmpUnreach} ICMP unreachable replies (filtered ports).`);
      const ord = e.order || [];
      const sorted = ord.length > 20 && ord.every((v, i) => !i || v >= ord[i - 1]);
      res.notes.push(sorted ? 'Ports probed in sequential order — nmap randomizes by default, so this suggests -r or a custom scanner.' : 'Ports probed in randomized order (nmap default).');
      const syn = P.find(p => p.proto === 'TCP' && p.src === e.src && p.dst === e.dst && p.fstr === 'S');
      if (syn) {
        const optLen = syn.tcpOpts?.length || 0;
        if (syn.win === 1024 && optLen <= 4) res.notes.push('Window 1024 with minimal TCP options — classic nmap raw-packet SYN probe.');
        else if (optLen >= 16) res.notes.push(`Full OS TCP options (win ${syn.win}, TTL ${syn.ttl}) — probes created by the OS stack (connect()), not raw packets.`);
      }
      const durs = P.filter(p => p.proto === 'TCP' && p.src === e.src && p.dst === e.dst).map(p => p.ts);
      res.duration = Math.max(...durs) - Math.min(...durs);
    }
    if (udpPorts >= 15) { res.udpPorts = udpPorts; if (!res.type) { res.type = 'UDP scan'; res.nmap = '-sU'; } else res.notes.push(`Also ${udpPorts} UDP ports probed (-sU).`); }
    scans.push(res);
  }
  // ping sweeps
  const sweeps = new Map();
  for (const p of P) if (p.isEchoReq) { if (!sweeps.has(p.src)) sweeps.set(p.src, new Set()); sweeps.get(p.src).add(p.dst); }
  const pingSweeps = [...sweeps.entries()].filter(([, s]) => s.size >= 10).map(([src, s]) => ({ src, targets: s.size, alive: new Set(P.filter(p => p.isEchoRep && p.dst === src).map(p => p.src)).size }));
  // ARP sweeps
  const arp = new Map(); for (const p of P) if (p.proto === 'ARP' && p.arpOp === 1) { if (!arp.has(p.src)) arp.set(p.src, new Set()); arp.get(p.src).add(p.dst); }
  const arpSweeps = [...arp.entries()].filter(([, s]) => s.size >= 10).map(([src, s]) => ({ src, targets: s.size }));
  return { scans: scans.sort((a, b) => b.ports - a.ports), pingSweeps, arpSweeps };
}

function labelEntropy(l){ if (!l) return 0; const f = {}; for (const c of l) f[c] = (f[c] || 0) + 1; return Object.values(f).reduce((h, v) => { const p = v / l.length; return h - p * Math.log2(p); }, 0); }
function regDomain(n){ const p = n.replace(/\.$/, '').split('.'); const two = new Set(['co.uk','com.au','com.ph','com.br','co.jp','com.cn','net.ph','org.ph','gov.ph','edu.ph','co.in','com.sg']); return p.length > 2 && two.has(p.slice(-2).join('.')) ? p.slice(-3).join('.') : p.slice(-2).join('.'); }
function analyzeDNS(P){
  const q = [], byHost = new Map(), resp = new Map();
  for (const p of P) {
    if (!p.dns) continue;
    const d = p.dns;
    if (!d.qr) { q.push({ p, name: d.qname, type: d.qtypeName }); if (!byHost.has(p.src)) byHost.set(p.src, { host: p.src, q: 0, nx: 0, ok: 0, names: new Set(), resolvers: new Set() }); const h = byHost.get(p.src); h.q++; h.names.add(d.qname); h.resolvers.add(p.dst); }
    else { const k = p.dst + '|' + d.id + '|' + d.qname; resp.set(k, { p, d }); const h = byHost.get(p.dst); if (h) { if (d.rcode === 3) h.nx++; else if (d.rcode === 0) h.ok++; } }
  }
  const names = new Map();
  for (const x of q) { if (!names.has(x.name)) names.set(x.name, { name: x.name, type: x.type, count: 0, hosts: new Set(), answers: new Set(), rcode: null }); const n = names.get(x.name); n.count++; n.hosts.add(x.p.src); }
  for (const { p, d } of resp.values()) { const n = names.get(d.qname); if (n) { n.rcode = d.rcodeName; d.answers.forEach(a => n.answers.add(`${a.type} ${a.data}`)); } }
  for (const n of names.values()) {
    const first = (n.name || '').split('.')[0] || '';
    n.entropy = labelEntropy(first); n.len = first.length;
    n.digits = (first.match(/\d/g) || []).length;
    n.dgaScore = (n.entropy > 3.3 ? 1 : 0) + (n.len >= 10 ? 1 : 0) + (n.digits >= 2 ? 1 : 0) + (n.rcode === 'NXDOMAIN' ? 1 : 0);
    n.longLabel = Math.max(0, ...(n.name || '').split('.').map(l => l.length));
  }
  const hosts = [...byHost.values()].map(h => ({ ...h, nxRate: h.q ? h.nx / h.q : 0, uniq: h.names.size }));
  const medianQ = hosts.map(h => h.q).sort((a, b) => a - b)[Math.floor(hosts.length / 2)] || 0;
  const suspects = hosts.filter(h => h.q >= 30 && h.nxRate > 0.5 && h.q > medianQ * 3);
  // resolved names queried by DGA suspects that succeeded
  const dgaHits = suspects.flatMap(h => [...names.values()].filter(n => n.hosts.has(h.host) && n.rcode === 'NOERROR' && n.answers.size));
  // tunneling: many unique subdomains under one parent, or long labels
  const parents = new Map(); for (const n of names.values()) { const r = regDomain(n.name || ''); if (!parents.has(r)) parents.set(r, { domain: r, subs: new Set(), maxLabel: 0, types: new Set() }); const e = parents.get(r); e.subs.add(n.name); e.maxLabel = Math.max(e.maxLabel, n.longLabel); e.types.add(n.type); }
  const tunnels = [...parents.values()].filter(e => e.subs.size >= 15 && e.maxLabel >= 20 || e.maxLabel >= 40).map(e => ({ ...e, subs: [...e.subs] }));
  return { queries: q, names: [...names.values()], hosts: hosts.sort((a, b) => b.q - a.q), suspects, dgaHits, tunnels };
}

function isStdPing(b){
  if (asLatin(b.subarray(0, 23)) === 'abcdefghijklmnopqrstuvw') return true;          // Windows ping
  if (b.length >= 24) { let inc = 0; for (let i = 9; i < b.length; i++) if (b[i] === ((b[i - 1] + 1) & 255)) inc++; if (inc > (b.length - 9) * 0.6) return true; } // Linux/BSD ping
  return false;
}
function analyzeICMP(P){
  const echo = P.filter(p => (p.isEchoReq || p.isEchoRep) && p.payload?.length);
  const req = echo.filter(p => p.isEchoReq);
  const odd = req.filter(p => !isStdPing(p.payload));
  return { echo, req, odd, sizes: [...new Set(req.map(p => p.payload.length))], covert: odd.length > 0 };
}

function findCreds(P, flows){
  const out = [];
  const add = (proto, f, user, pass, extra = '') => out.push({ proto, cli: f.cli, srv: `${f.srv}:${f.sport}`, user, pass, extra });
  for (const f of flows) {
    if (f.proto !== 'TCP') continue;
    const c = asLatin(reassemble(f, true));
    if (!c) continue;
    let m;
    if (f.sport === 21 || /^USER /m.test(c)) { const u = (c.match(/^USER (.+?)\r?$/m) || [])[1], pw = (c.match(/^PASS (.+?)\r?$/m) || [])[1]; if (u || pw) add('FTP', f, u, pw); }
    if (f.sport === 110 || f.sport === 143) { if ((m = c.match(/^USER (.+?)\r?\n[\s\S]*?^PASS (.+?)\r?$/m))) add('POP3', f, m[1], m[2]); if ((m = c.match(/LOGIN "?([^\s"]+)"? "?([^\r\n"]+)"?/i))) add('IMAP', f, m[1], m[2]); }
    if ([25, 587, 465].includes(f.sport) || /AUTH (LOGIN|PLAIN)/i.test(c)) {
      if ((m = c.match(/AUTH PLAIN ([A-Za-z0-9+/=]+)/i))) { try { const s = atob(m[1]).split('\0'); add('SMTP AUTH PLAIN', f, s[1], s[2]); } catch {} }
      if ((m = c.match(/AUTH LOGIN\r?\n([A-Za-z0-9+/=]+)\r?\n([A-Za-z0-9+/=]+)/i))) { try { add('SMTP AUTH LOGIN', f, atob(m[1]), atob(m[2])); } catch {} }
    }
    if (f.sport === 23) { const s = c.replace(/\xff[\xfb-\xfe]./g, '').replace(/\xff\xfa[\s\S]*?\xff\xf0/g, ''); add('Telnet (raw keystrokes)', f, '', '', safeText(te.encode(s), 200)); }
    for (const mm of c.matchAll(/^Authorization: *Basic ([A-Za-z0-9+/=]+)/gmi)) { try { const [u, ...pw] = atob(mm[1]).split(':'); add('HTTP Basic', f, u, pw.join(':')); } catch {} }
    for (const mm of c.matchAll(/^Authorization: *Bearer ([^\r\n]+)/gmi)) add('HTTP Bearer token', f, '', '', mm[1].slice(0, 200));
    for (const mm of c.matchAll(/^POST (\S+) HTTP[\s\S]*?\r\n\r\n([^\r\n]{0,600})/gm)) { const body = mm[2]; if (/(pass|pwd|user|login|email|token)/i.test(body)) { const params = new URLSearchParams(body); const u = [...params].find(([k]) => /user|login|email|name/i.test(k))?.[1], pw = [...params].find(([k]) => /pass|pwd/i.test(k))?.[1]; add('HTTP POST form', f, u, pw, `${mm[1]}  ${body.slice(0, 160)}`); } }
  }
  // SNMP community strings (v1/v2c)
  for (const p of P) if (p.proto === 'UDP' && (p.dport === 161 || p.dport === 162) && p.payload?.[0] === 0x30) { try { const b = p.payload; let o = 2; if (b[1] & 0x80) o += b[1] & 0x7f; o += 3; if (b[o] === 4) { const l = b[o + 1]; const comm = asLatin(b.subarray(o + 2, o + 2 + l)); out.push({ proto: 'SNMP community', cli: p.src, srv: `${p.dst}:${p.dport}`, user: '', pass: comm, extra: '' }); } } catch {} }
  return out.filter((x, i, a) => a.findIndex(y => y.proto === x.proto && y.user === x.user && y.pass === x.pass && y.srv === x.srv) === i);
}

/* ---------- carving inside streams ---------- */
const CARVE_SIGS = [['PNG', 'png', [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a]], ['JPEG', 'jpg', [0xff, 0xd8, 0xff]], ['GIF', 'gif', [0x47, 0x49, 0x46, 0x38]], ['ZIP', 'zip', [0x50, 0x4b, 0x03, 0x04]], ['PDF', 'pdf', [0x25, 0x50, 0x44, 0x46, 0x2d]], ['GZIP', 'gz', [0x1f, 0x8b, 0x08]], ['ELF', 'elf', [0x7f, 0x45, 0x4c, 0x46]], ['PE/MZ', 'exe', [0x4d, 0x5a, 0x90, 0x00]], ['7z', '7z', [0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c]], ['RAR', 'rar', [0x52, 0x61, 0x72, 0x21, 0x1a, 0x07]], ['SQLite', 'sqlite', [0x53, 0x51, 0x4c, 0x69, 0x74, 0x65, 0x20, 0x66]]];
function carve(bytes){
  const hits = [];
  for (let i = 0; i < bytes.length; i++) for (const [name, ext, sig] of CARVE_SIGS) { if (bytes[i] !== sig[0]) continue; let ok = true; for (let j = 1; j < sig.length; j++) if (bytes[i + j] !== sig[j]) { ok = false; break; } if (ok) hits.push({ off: i, name, ext }); }
  return hits;
}

/* ---------- fragment assembly ----------
   Given payload strings in capture order, find a piece that starts a "name{" pattern, keep following pieces that look like
   the same token (no spaces / hyphens — filler is usually "status-ok" style words) up to the piece containing "}". */
const FRAG_OK = /^[A-Za-z0-9_!@#$%^&*+.,:;?=~'{}]+$/;
function assembleFragments(pieces){
  const uniq = [...new Set(pieces.filter(Boolean))];
  const si = uniq.findIndex(x => /[A-Za-z0-9_]{2,24}\{/.test(x));
  if (si < 0) return null;
  const start = uniq[si].slice(uniq[si].search(/[A-Za-z0-9_]{2,24}\{/));
  if (start.includes('}')) return { text: start.slice(0, start.indexOf('}') + 1), used: [si] };
  let text = start; const used = [si];
  for (let i = si + 1; i < uniq.length; i++) {
    const x = uniq[i];
    if (x.includes('}')) { const end = x.slice(0, x.indexOf('}') + 1); if (FRAG_OK.test(end)) { text += end; used.push(i); return { text, used, uniq }; } continue; }
    if (FRAG_OK.test(x) && x.length <= 64) { text += x; used.push(i); }
  }
  return null;
}
