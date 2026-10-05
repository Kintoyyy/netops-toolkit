/* Shared helpers for NetOps Toolkit pages */
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const sleep = ms => new Promise(r => setTimeout(r, ms));

async function copyText(text, btn){
  try { await navigator.clipboard.writeText(text); }
  catch { const t = document.createElement('textarea'); t.value = text; document.body.appendChild(t); t.select(); document.execCommand('copy'); t.remove(); }
  if (btn) { const o = btn.textContent; btn.textContent = 'Copied ✓'; setTimeout(() => btn.textContent = o, 1200); }
}
function download(name, text, type = 'text/plain'){
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([text], {type}));
  a.download = name; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}
function toCSV(rows){ return rows.map(r => r.map(v => `"${String(v ?? '').replace(/"/g, '""')}"`).join(',')).join('\n'); }
function getParam(k){ return new URLSearchParams(location.search).get(k); }
function setParam(k, v){ const u = new URL(location.href); v ? u.searchParams.set(k, v) : u.searchParams.delete(k); history.replaceState(null, '', u); }
function fmtDate(d){ if (!d) return '—'; const x = new Date(d); return isNaN(x) ? String(d) : x.toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC'); }
function daysBetween(a, b){ return Math.round((new Date(b) - new Date(a)) / 864e5); }
function cleanHost(s){
  return String(s || '').trim().toLowerCase()
    .replace(/^[a-z][a-z0-9+.-]*:\/\//, '').replace(/^[^@\/]*@/, '').split(/[\/?#\s]/)[0]
    .replace(/:\d+$/, '').replace(/\.$/, '').replace(/\[\.\]|\(\.\)|\{\.\}/g, '.');
}

/* ---------- IP helpers ---------- */
function parseIPv4(s){
  const m = String(s).trim().match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return null;
  const o = m.slice(1).map(Number);
  if (o.some(x => x > 255)) return null;
  return ((o[0] << 24) >>> 0) + (o[1] << 16) + (o[2] << 8) + o[3];
}
function fmtIPv4(n){ return [24, 16, 8, 0].map(s => (n >>> s) & 255).join('.'); }
function parseIPv6(s){
  s = String(s).trim().replace(/^\[|\]$/g, '').split('%')[0];
  if (!s.includes(':')) return null;
  const m4 = s.match(/(\d+\.\d+\.\d+\.\d+)$/);
  if (m4) { const v = parseIPv4(m4[1]); if (v == null) return null; s = s.slice(0, -m4[1].length) + (v >>> 16).toString(16) + ':' + (v & 0xffff).toString(16); }
  const dbl = s.split('::'); if (dbl.length > 2) return null;
  const head = dbl[0] ? dbl[0].split(':') : [];
  const tail = dbl.length === 2 && dbl[1] ? dbl[1].split(':') : [];
  const fill = 8 - head.length - tail.length;
  if (dbl.length === 1 && head.length !== 8) return null;
  if (dbl.length === 2 && fill < 1) return null;
  const g = [...head, ...(dbl.length === 2 ? Array(fill).fill('0') : []), ...tail];
  if (g.length !== 8 || g.some(x => !/^[0-9a-f]{1,4}$/i.test(x))) return null;
  return g.reduce((a, x) => (a << 16n) + BigInt(parseInt(x, 16)), 0n);
}
function ipv6Groups(n){ const g = []; for (let i = 7; i >= 0; i--) g.push(Number((n >> BigInt(i * 16)) & 0xffffn)); return g; }
function fmtIPv6(n){
  const g = ipv6Groups(n).map(x => x.toString(16));
  let bs = -1, bl = 0;
  for (let i = 0; i < 8;) { if (g[i] === '0') { let j = i; while (j < 8 && g[j] === '0') j++; if (j - i > bl && j - i > 1) { bs = i; bl = j - i; } i = j; } else i++; }
  if (bs < 0) return g.join(':');
  return g.slice(0, bs).join(':') + '::' + g.slice(bs + bl).join(':');
}
function fullIPv6(n){ return ipv6Groups(n).map(x => x.toString(16).padStart(4, '0')).join(':'); }
function ipKind(s){ return parseIPv4(s) != null ? 4 : parseIPv6(s) != null ? 6 : 0; }
function ptrName(ip){
  if (parseIPv4(ip) != null) return ip.trim().split('.').reverse().join('.') + '.in-addr.arpa';
  const v6 = parseIPv6(ip);
  if (v6 != null) return v6.toString(16).padStart(32, '0').split('').reverse().join('.') + '.ip6.arpa';
  return null;
}
const V4_SPECIAL = [
  ['0.0.0.0/8','"This" network'],['10.0.0.0/8','Private (RFC 1918)'],['100.64.0.0/10','CGNAT shared space (RFC 6598)'],
  ['127.0.0.0/8','Loopback'],['169.254.0.0/16','Link-local (APIPA)'],['172.16.0.0/12','Private (RFC 1918)'],
  ['192.0.0.0/24','IETF protocol assignments'],['192.0.2.0/24','Documentation (TEST-NET-1)'],['192.88.99.0/24','6to4 relay anycast (deprecated)'],
  ['192.168.0.0/16','Private (RFC 1918)'],['198.18.0.0/15','Benchmarking (RFC 2544)'],['198.51.100.0/24','Documentation (TEST-NET-2)'],
  ['203.0.113.0/24','Documentation (TEST-NET-3)'],['224.0.0.0/4','Multicast'],['240.0.0.0/4','Reserved (Class E)'],['255.255.255.255/32','Limited broadcast'],
];
function v4Special(n){
  for (const [c, label] of V4_SPECIAL) {
    const [ip, p] = c.split('/'); const mask = p == 0 ? 0 : (0xffffffff << (32 - p)) >>> 0;
    if (((n & mask) >>> 0) === parseIPv4(ip)) return label;
  }
  return null;
}
function v6Special(n){
  const top = n >> 112n, g = ipv6Groups(n);
  if (n === 0n) return 'Unspecified';
  if (n === 1n) return 'Loopback';
  if ((n >> 32n) === 0xffffn) return 'IPv4-mapped';
  if ((top & 0xffc0n) === 0xfe80n) return 'Link-local';
  if ((top & 0xfe00n) === 0xfc00n) return 'Unique local (ULA)';
  if ((top & 0xff00n) === 0xff00n) return 'Multicast';
  if (g[0] === 0x2001 && g[1] === 0x0db8) return 'Documentation';
  if (g[0] === 0x2002) return '6to4';
  if (g[0] === 0x2001 && g[1] === 0) return 'Teredo';
  if (g[0] === 0x64 && g[1] === 0xff9b) return 'NAT64 well-known prefix';
  if ((top & 0xe000n) === 0x2000n) return 'Global unicast';
  return null;
}

/* ---------- DNS over HTTPS ---------- */
const DOH = { cloudflare: 'https://cloudflare-dns.com/dns-query', google: 'https://dns.google/resolve' };
const RRTYPE = {1:'A',2:'NS',5:'CNAME',6:'SOA',12:'PTR',13:'HINFO',15:'MX',16:'TXT',28:'AAAA',29:'LOC',33:'SRV',35:'NAPTR',39:'DNAME',43:'DS',46:'RRSIG',47:'NSEC',48:'DNSKEY',50:'NSEC3',52:'TLSA',64:'SVCB',65:'HTTPS',99:'SPF',257:'CAA'};
const RCODE = {0:'NOERROR',1:'FORMERR',2:'SERVFAIL',3:'NXDOMAIN',4:'NOTIMP',5:'REFUSED'};
async function doh(name, type = 'A', provider = 'cloudflare'){
  const u = new URL(DOH[provider]);
  u.searchParams.set('name', name); u.searchParams.set('type', type);
  const t0 = performance.now();
  const r = await fetch(u, { headers: { accept: 'application/dns-json' } });
  if (!r.ok) throw new Error(`${provider} DoH returned HTTP ${r.status}`);
  const j = await r.json(); j._ms = Math.round(performance.now() - t0); return j;
}
async function dohTxt(name, provider = 'cloudflare'){
  const j = await doh(name, 'TXT', provider);
  return (j.Answer || []).filter(a => a.type === 16).map(a => txtJoin(a.data));
}
function txtJoin(data){
  const parts = String(data).match(/"((?:[^"\\]|\\.)*)"/g);
  return parts ? parts.map(p => p.slice(1, -1).replace(/\\"/g, '"').replace(/\\\\/g, '\\')).join('') : String(data);
}

/* ---------- theme ---------- */
(function(){
  const btn = document.getElementById('themeBtn');
  if (!btn) return;
  if (!btn.innerHTML.trim()) btn.innerHTML = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align:-3px"><circle cx="12" cy="12" r="9"/><path d="M12 3a9 9 0 0 1 0 18z" fill="currentColor"/></svg> Theme';
  btn.addEventListener('click', () => {
    const r = document.documentElement;
    const dark = r.dataset.theme ? r.dataset.theme === 'dark' : matchMedia('(prefers-color-scheme: dark)').matches;
    r.dataset.theme = dark ? 'light' : 'dark';
  });
})();
