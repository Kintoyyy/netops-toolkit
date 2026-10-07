/* First-visit disclaimer: a modal the visitor must accept before using the toolkit.
   Acceptance lives in localStorage under "netops-consent" (outside the "netops:" history keys, so clearing
   history never re-prompts). Bump VERSION when the disclaimer changes materially to ask again.
   Skipped inside iframes (split view panes — the outer page asks) and on the disclaimer page itself. */
(function(){
  const KEY = 'netops-consent', VERSION = 1;
  const read = () => { try { const v = JSON.parse(localStorage.getItem(KEY)); return v && v.v >= VERSION ? v : null; } catch { return null; } };
  let memo = null;   // when storage is blocked, remember for this page only
  const accept = () => { memo = { v: VERSION, t: Date.now() }; try { localStorage.setItem(KEY, JSON.stringify(memo)); } catch {} document.dispatchEvent(new CustomEvent('netops-consent')); };
  const withdraw = () => { memo = null; try { localStorage.removeItem(KEY); } catch {} document.dispatchEvent(new CustomEvent('netops-consent')); };
  const root = new URL('../', document.currentScript?.src || location.href);
  window.NetopsConsent = { accepted: () => read() || memo, accept, withdraw, url: new URL('disclaimer/', root).href };
  if (window.top !== window.self || document.documentElement.hasAttribute('data-consent-page') || read()) return;

  const CSS = `
.nc-back{position:fixed;inset:0;z-index:1000;display:grid;place-items:center;padding:16px;background:rgba(10,12,16,.55);backdrop-filter:blur(3px)}
.nc-modal{width:min(520px,100%);max-height:calc(100vh - 32px);overflow:auto;background:var(--panel,#fff);color:var(--text,#1b1f24);border:1px solid var(--border,#dde1e6);border-radius:14px;padding:22px 22px 18px;box-shadow:0 24px 60px rgba(0,0,0,.3);font:14px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
.nc-modal h2{margin:0 0 6px;font-size:19px;display:flex;align-items:center;gap:10px}
.nc-modal h2 svg{flex:none;color:var(--accent,#2457d6)}
.nc-modal p{margin:0 0 10px}
.nc-modal ul{margin:0 0 4px;padding-left:20px;display:grid;gap:6px}
.nc-foot{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-top:16px;padding-top:14px;border-top:1px solid var(--border,#dde1e6)}
.nc-foot a{color:var(--accent,#2457d6);font-size:13px}
.nc-foot button{background:var(--accent,#2457d6);color:var(--accent-ink,#fff);border:1px solid var(--accent,#2457d6);border-radius:8px;padding:9px 16px;font:600 14px system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;cursor:pointer}
.nc-foot button:hover{filter:brightness(1.05)}`;
  function show(){
    if (read() || document.querySelector('.nc-back')) return;
    document.head.appendChild(Object.assign(document.createElement('style'), { textContent: CSS }));
    const back = document.createElement('div'); back.className = 'nc-back';
    back.innerHTML = `<div class="nc-modal" role="dialog" aria-modal="true" aria-labelledby="ncTitle" aria-describedby="ncBody">
      <h2 id="ncTitle"><svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>Before you start</h2>
      <div id="ncBody">
        <p>NetOps Toolkit is <b>free and open source</b> under the MIT License — anyone can use it, with no sign-up.</p>
        <ul>
          <li>It's provided <b>as is</b>, without warranty of any kind. Results can be wrong, so check them before applying them to a live network.</li>
          <li>The authors and contributors are <b>not liable</b> for any damage, outage, data loss or other harm that comes from using it.</li>
          <li>Use the security and OSINT tools only on systems and data you're <b>authorized</b> to analyze.</li>
          <li>Online tools send what you look up to public services (DNS, RDAP, RIPEstat…); offline tools keep everything in your browser.</li>
        </ul>
      </div>
      <div class="nc-foot"><a href="${window.NetopsConsent.url}" target="_blank" rel="noopener">Read the full disclaimer ↗</a><button type="button" id="ncAccept">I understand and accept</button></div>
    </div>`;
    // everything behind the dialog becomes inert (no focus, no clicks, hidden from screen readers) until accepted
    const behind = [...document.body.children].filter(el => !el.inert);
    behind.forEach(el => el.inert = true);
    const prevOverflow = document.documentElement.style.overflow; document.documentElement.style.overflow = 'hidden';
    document.body.appendChild(back);
    const close = () => { back.remove(); behind.forEach(el => el.inert = false); document.documentElement.style.overflow = prevOverflow; };
    back.querySelector('#ncAccept').onclick = () => { accept(); close(); };
    back.querySelector('#ncAccept').focus();
    addEventListener('storage', e => { if (e.key === KEY && read()) close(); });   // accepted on the disclaimer page in another tab
  }
  if (document.body) show(); else document.addEventListener('DOMContentLoaded', show);
})();
