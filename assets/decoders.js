/* Shared decoding helpers: byte parsing, encodings, scoring, pattern highlighting */
const te = new TextEncoder();
const tdLatin = new TextDecoder('latin1');
const tdUtf8 = new TextDecoder('utf-8', { fatal: false });

const FLAG_DEFAULT = '[A-Za-z][A-Za-z0-9_\\-]{1,23}\\{[\\w\\-!@#$%&*+.,:;?=~\'^]{2,200}\\}';
function flagRegex(){
  let src = FLAG_DEFAULT;
  try { const s = localStorage.getItem('flagre'); if (s) src = s; } catch {}
  try { return new RegExp(src, 'g'); } catch { return new RegExp(FLAG_DEFAULT, 'g'); }
}
function setFlagRegex(src){ try { localStorage.setItem('flagre', src); } catch {} }
function findFlags(s){ return [...new Set(String(s).match(flagRegex()) || [])]; }
function hlFlags(s){
  const re = flagRegex(); let out = '', last = 0, m;
  while ((m = re.exec(s))) { out += esc(s.slice(last, m.index)) + `<mark>${esc(m[0])}</mark>`; last = m.index + m[0].length; if (!m[0].length) re.lastIndex++; }
  return out + esc(s.slice(last));
}

/* ---------- bytes <-> strings ---------- */
const toHex = (b, sep = '') => [...b].map(x => x.toString(16).padStart(2, '0')).join(sep);
function bytesToB64(b){ let s = ''; for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode.apply(null, b.subarray(i, i + 0x8000)); return btoa(s); }
function b64ToBytes(s){ s = s.replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/'); if (/[^A-Za-z0-9+/=]/.test(s)) throw new Error('bad base64'); s = s.replace(/=+$/, ''); if (s.length % 4 === 1) throw new Error('bad base64'); while (s.length % 4) s += '='; return Uint8Array.from(atob(s), c => c.charCodeAt(0)); }
function hexToBytes(s){ const h = s.replace(/0x|\\x|[\s:,\-]/gi, ''); if (!/^([0-9a-f]{2})*$/i.test(h) || !h) throw new Error('bad hex'); return new Uint8Array(h.match(/../g).map(x => parseInt(x, 16))); }
function binToBytes(s){ const b = s.replace(/[^01]/g, ''); if (!b || b.length % 8) throw new Error('bad binary'); return new Uint8Array(b.match(/.{8}/g).map(x => parseInt(x, 2))); }
function decToBytes(s){ const n = s.trim().split(/[^0-9]+/).filter(Boolean).map(Number); if (!n.length || n.some(x => x > 255)) throw new Error('bad decimal'); return new Uint8Array(n); }
function octToBytes(s){ const n = s.trim().split(/[^0-7]+/).filter(Boolean).map(x => parseInt(x, 8)); if (!n.length || n.some(x => x > 255)) throw new Error('bad octal'); return new Uint8Array(n); }
function parseBytes(str, mode){
  switch (mode) {
    case 'hex': return hexToBytes(str);
    case 'base64': return b64ToBytes(str);
    case 'dec': return decToBytes(str);
    case 'bin': return binToBytes(str);
    default: return te.encode(str);
  }
}
const asText = b => tdUtf8.decode(b);
const asLatin = b => tdLatin.decode(b);
function printableRatio(b){ if (!b.length) return 0; let p = 0; for (const x of b) if ((x >= 32 && x < 127) || x === 9 || x === 10 || x === 13) p++; return p / b.length; }
function safeText(b, max = 4000){ let s = ''; const n = Math.min(b.length, max); for (let i = 0; i < n; i++) { const x = b[i]; s += (x >= 32 && x < 127) || x === 10 || x === 9 ? String.fromCharCode(x) : '·'; } return s + (b.length > max ? '…' : ''); }
function hexdump(b, start = 0, len = 512){
  const out = []; const end = Math.min(b.length, start + len);
  for (let o = start; o < end; o += 16) {
    const row = b.subarray(o, Math.min(o + 16, end));
    const hx = [...row].map(x => x.toString(16).padStart(2, '0')).join(' ').padEnd(47, ' ');
    out.push(o.toString(16).padStart(8, '0') + '  ' + hx.slice(0, 23) + ' ' + hx.slice(24) + '  |' + [...row].map(x => x >= 32 && x < 127 ? String.fromCharCode(x) : '.').join('') + '|');
  }
  return out.join('\n');
}
function entropy(b){ if (!b.length) return 0; const f = new Uint32Array(256); for (const x of b) f[x]++; let h = 0; for (const c of f) if (c) { const p = c / b.length; h -= p * Math.log2(p); } return h; }
function downloadBytes(name, bytes){ const a = document.createElement('a'); a.href = URL.createObjectURL(new Blob([bytes])); a.download = name; a.click(); setTimeout(() => URL.revokeObjectURL(a.href), 1000); }

/* ---------- English scoring ---------- */
const EN_FREQ = {a:8.2,b:1.5,c:2.8,d:4.3,e:12.7,f:2.2,g:2.0,h:6.1,i:7.0,j:.15,k:.77,l:4.0,m:2.4,n:6.7,o:7.5,p:1.9,q:.1,r:6.0,s:6.3,t:9.1,u:2.8,v:1.0,w:2.4,x:.15,y:2.0,z:.07,' ':13};
const BIGRAMS = new Set('th he in er an re on at en nd ti es or te of ed is it al ar st to nt ng se ha as ou io le ve co me de hi ri ro ic ne ea ra ce li ch ll be ma si om ur'.split(' '));
function englishScore(s){
  if (!s.length) return -99; let sc = 0, bg = 0, letters = 0;
  for (let i = 0; i < s.length; i++) {
    const ch = s[i], c = ch.charCodeAt(0), l = ch.toLowerCase();
    if (EN_FREQ[l] != null) { sc += EN_FREQ[l]; if (l !== ' ') letters++; }
    else if (c >= 48 && c <= 57) sc += 1;
    else if (c >= 32 && c < 127) sc += .3;
    else if (c === 10 || c === 13 || c === 9) sc += .5;
    else sc -= 15;
    if (i && BIGRAMS.has((s[i - 1] + ch).toLowerCase())) bg++;
  }
  return sc / s.length + (letters > 1 ? 25 * bg / letters : 0) + flagBonus(s);
}
function flagBonus(s){ return findFlags(s).length ? 30 : 0; }
function bytesScore(b){ return englishScore(asLatin(b)); }
// unigram-only score, for scoring non-contiguous columns (e.g. repeating-key XOR)
function charScore(b){ let sc = 0; for (const x of b) { const l = String.fromCharCode(x).toLowerCase(); sc += EN_FREQ[l] != null ? EN_FREQ[l] : (x >= 32 && x < 127) ? .3 : (x === 10 || x === 13 || x === 9) ? .5 : -15; } return b.length ? sc / b.length : -99; }

/* ---------- extra encodings ---------- */
function b32ToBytes(s){
  const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; s = s.toUpperCase().replace(/[\s=]/g, '');
  if (!s || /[^A-Z2-7]/.test(s)) throw new Error('bad base32');
  let bits = 0, val = 0; const out = [];
  for (const c of s) { val = (val << 5) | A.indexOf(c); bits += 5; if (bits >= 8) { out.push((val >>> (bits - 8)) & 255); bits -= 8; } }
  return new Uint8Array(out);
}
function b58ToBytes(s){
  const A = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'; s = s.trim();
  if (!s || /[^1-9A-HJ-NP-Za-km-z]/.test(s)) throw new Error('bad base58');
  let n = 0n; for (const c of s) n = n * 58n + BigInt(A.indexOf(c));
  const out = []; while (n > 0n) { out.unshift(Number(n & 255n)); n >>= 8n; }
  for (const c of s) { if (c === '1') out.unshift(0); else break; }
  return new Uint8Array(out);
}
function a85ToBytes(s){
  s = s.trim().replace(/^<~/, '').replace(/~>$/, '').replace(/\s/g, '').replace(/z/g, '!!!!!');
  if (!s || /[^!-u]/.test(s)) throw new Error('bad ascii85');
  const out = [], pad = (5 - s.length % 5) % 5; s += 'u'.repeat(pad);
  for (let i = 0; i < s.length; i += 5) { let v = 0; for (let j = 0; j < 5; j++) v = v * 85 + (s.charCodeAt(i + j) - 33); out.push((v >>> 24) & 255, (v >>> 16) & 255, (v >>> 8) & 255, v & 255); }
  return new Uint8Array(out.slice(0, out.length - pad));
}
const MORSE = {'.-':'A','-...':'B','-.-.':'C','-..':'D','.':'E','..-.':'F','--.':'G','....':'H','..':'I','.---':'J','-.-':'K','.-..':'L','--':'M','-.':'N','---':'O','.--.':'P','--.-':'Q','.-.':'R','...':'S','-':'T','..-':'U','...-':'V','.--':'W','-..-':'X','-.--':'Y','--..':'Z','-----':'0','.----':'1','..---':'2','...--':'3','....-':'4','.....':'5','-....':'6','--...':'7','---..':'8','----.':'9','.-.-.-':'.','--..--':',','..--..':'?','-.-.--':'!','-..-.':'/','-.--.':'(','-.--.-':')','.-...':'&','---...':':','-.-.-.':';','-...-':'=','.-.-.':'+','-....-':'-','..--.-':'_','.-..-.':'"','.--.-.':'@','-.--.-.':'{','.----.':"'"};
function morseDecode(s){
  const t = s.trim().replace(/[–—_]/g, '-').replace(/[·•]/g, '.');
  if (!/^[.\-\s\/|]+$/.test(t)) throw new Error('not morse');
  return t.split(/\s*[\/|]\s*|\s{2,}/).map(w => w.split(/\s+/).map(c => MORSE[c] ?? '?').join('')).join(' ');
}
const rot = (s, n) => s.replace(/[a-z]/gi, c => { const b = c <= 'Z' ? 65 : 97; return String.fromCharCode((c.charCodeAt(0) - b + n + 26) % 26 + b); });
const rot47 = s => s.replace(/[!-~]/g, c => String.fromCharCode(33 + (c.charCodeAt(0) - 33 + 47) % 94));
const atbash = s => s.replace(/[a-z]/gi, c => { const b = c <= 'Z' ? 65 : 97; return String.fromCharCode(25 - (c.charCodeAt(0) - b) + b); });

async function inflate(bytes, fmt){
  const ds = new DecompressionStream(fmt);
  const out = new Response(new Blob([bytes]).stream().pipeThrough(ds));
  return new Uint8Array(await out.arrayBuffer());
}

/* ---------- highlight-pattern setting widget (any element with id="flagre") ---------- */
document.addEventListener('DOMContentLoaded', () => {
  const el = document.getElementById('flagre'); if (!el) return;
  el.value = flagRegex().source;
  el.addEventListener('change', () => { try { new RegExp(el.value); setFlagRegex(el.value); el.style.borderColor = ''; el.dispatchEvent(new Event('flagchange', { bubbles: true })); } catch { el.style.borderColor = 'var(--bad)'; } });
});
const FLAG_BOX = `<label class="small" style="margin:0">Highlight regex</label><input type="text" id="flagre" class="mono" style="width:280px" title="Saved in this browser">`;
