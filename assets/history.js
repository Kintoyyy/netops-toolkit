/* Recently used tools + per-tool input history for NetOps Toolkit pages.
   Everything lives in this browser's localStorage under "netops:" — nothing is sent anywhere.
   On tool pages: restores the last inputs, records each run (primary button / Enter), adds a History menu.
   Opt out per field, container or button with data-nosave. Pages can keep extra state via NetopsHistory.state()
   and name their history entries by setting NetopsHistory.labeler = root => 'label'. */
(function(){
  const P = 'netops:', MAX_HIST = 12, MAX_ENTRY = 30000, MAX_FIELD = 100000;
  const get = (k, d) => { try { const v = localStorage.getItem(P + k); return v == null ? d : JSON.parse(v); } catch { return d; } };
  function put(k, v){
    try { localStorage.setItem(P + k, JSON.stringify(v)); return true; }
    catch { return Array.isArray(v) && v.length > 1 ? put(k, v.slice(0, Math.ceil(v.length / 2))) : false; }   // over quota: keep the newest half
  }
  const del = k => { try { localStorage.removeItem(P + k); } catch {} };
  const enabled = () => get('remember', true) !== false;
  function clearAll(){ try { Object.keys(localStorage).filter(k => k.startsWith(P)).forEach(k => localStorage.removeItem(k)); } catch {} }
  const h = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  function ago(t){
    const s = (Date.now() - t) / 1000;
    return s < 60 ? 'just now' : s < 3600 ? `${Math.floor(s / 60)}m ago` : s < 86400 ? `${Math.floor(s / 3600)}h ago` : s < 7 * 86400 ? `${Math.floor(s / 86400)}d ago` : new Date(t).toLocaleDateString();
  }
  const slug = (location.pathname.match(/\/tools\/([^/]+)\/(?:index\.html)?$/) || [])[1] || null;
  window.NetopsHistory = {
    recent: () => get('recent', []), entries: s => get('hist:' + s, []), ago, enabled,
    clearRecent: () => del('recent'),
    kv: (k, v) => v === undefined ? get(k, null) : enabled() && put(k, v),   // free-form state, honours the remember switch
    state: v => slug ? window.NetopsHistory.kv('state:' + slug, v) : null,   // per-tool state
  };
  if (!slug) return;

  const DRAFT = 'draft:' + slug, HIST = 'hist:' + slug;
  const SEL = 'textarea, select, input:not([type]), input[type=text], input[type=number], input[type=url], input[type=checkbox], input[type=radio]';
  const TEXT = 'textarea, input:not([type]), input[type=text], input[type=number], input[type=url]';
  const BASE = new Map();   // value each field had once the tool finished initialising
  const fields = root => [...root.querySelectorAll(SEL)].filter(el => el.id && !el.disabled && !el.readOnly && !el.closest('[data-nosave]'));
  const val = el => /^(checkbox|radio)$/.test(el.type) ? el.checked : el.value;
  function base(el){
    if (BASE.has(el)) return BASE.get(el);
    if (/^(checkbox|radio)$/.test(el.type)) return el.defaultChecked;
    if (el.tagName === 'SELECT') return ([...el.options].find(o => o.defaultSelected) || el.options[0])?.value ?? '';
    return el.defaultValue;
  }
  const changed = root => Object.fromEntries(fields(root).filter(el => val(el) !== base(el)).map(el => [el.id, val(el)]));
  function apply(f, root, reset){   // reset: fields missing from f go back to their initial value
    const touched = [];
    for (const el of fields(root)) {
      const v = Object.hasOwn(f, el.id) ? f[el.id] : reset ? base(el) : undefined;
      if (v === undefined || v === val(el)) continue;
      if (el.tagName === 'SELECT' && ![...el.options].some(o => o.value === v)) continue;
      if (typeof v === 'boolean') el.checked = v; else el.value = v;
      touched.push(el);
    }
    // input (not change) events: tools use them for live previews/counters, never for network calls
    touched.filter(el => el.matches(TEXT)).forEach(el => el.dispatchEvent(new Event('input', { bubbles: true })));
  }
  function label(f, root){
    const s = Object.entries(f).find(([id, v]) => typeof v === 'string' && v.trim() && document.getElementById(id)?.matches(TEXT))?.[1]
      || fields(root).filter(el => el.matches(TEXT)).map(el => el.value).find(v => v.trim());
    if (!s) return null;
    const lines = s.trim().split(/\r?\n/).filter(l => l.trim());
    return { text: lines[0].trim().replace(/\s+/g, ' ').slice(0, 120), more: lines.length - 1 };
  }

  /* ---------- draft: last inputs, restored on the next visit ---------- */
  function saveDraft(){
    if (!enabled()) return;
    const f = changed(document);
    for (const k in f) if (typeof f[k] === 'string' && f[k].length > MAX_FIELD) delete f[k];
    if (Object.keys(f).length) put(DRAFT, f); else del(DRAFT);
  }

  /* ---------- history: one entry per run ---------- */
  function record(root, how){
    if (!enabled()) return;
    const f = changed(root), custom = window.NetopsHistory.labeler?.(root);   // a page may name its own entries
    const lb = typeof custom === 'string' && custom.trim() ? { text: custom.trim().slice(0, 120), more: 0 } : label(f, root);
    if (!lb || !Object.keys(f).length || JSON.stringify(f).length > MAX_ENTRY) return;
    const tab = root !== document && root.id?.startsWith('pane-') ? root.id.slice(5) : null;
    const tabName = tab && document.querySelector(`#tabs .tab[data-t="${CSS.escape(tab)}"]`)?.firstChild?.textContent?.trim();
    const sig = JSON.stringify([tab, f]), e = { t: Date.now(), label: lb.text, f, ...how };
    if (lb.more) e.more = lb.more;
    if (tab) Object.assign(e, { tab, tabName });
    put(HIST, [e, ...get(HIST, []).filter(x => JSON.stringify([x.tab || null, x.f]) !== sig)].slice(0, MAX_HIST));
    if (pop && !pop.hidden) renderPop();
  }
  function restore(e){
    if (!e) return;
    if (e.tab) document.querySelector(`#tabs .tab[data-t="${CSS.escape(e.tab)}"]`)?.click();
    const root = (e.tab && document.getElementById('pane-' + e.tab)) || document;
    apply(e.f, root, true); close();
    const b = (e.btn && document.getElementById(e.btn)) || (!e.key && root.querySelector('button.primary:not([data-nosave])')), k = e.key && document.getElementById(e.key);
    if (k) k.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', ctrlKey: !!e.ctrl, bubbles: true }));
    else if (b) b.click();
    else record(root, {});
    saveDraft();
  }

  /* ---------- History menu ---------- */
  const CSS_TEXT = `
.nh-actions{position:relative;display:flex;gap:8px;align-items:flex-start}
.nh-pop{position:absolute;top:calc(100% + 6px);right:0;z-index:50;width:min(380px,calc(100vw - 32px));max-height:70vh;overflow:auto;background:var(--panel);color:var(--text);border:1px solid var(--border);border-radius:10px;box-shadow:0 10px 30px rgba(0,0,0,.18);padding:8px;font-size:13px}
.nh-head{display:flex;justify-content:space-between;align-items:baseline;gap:8px;padding:4px 6px 8px}
.nh-muted{color:var(--muted);font-size:12px}
.nh-item{display:flex;border-radius:7px}
.nh-item:hover{background:var(--code-bg)}
.nh-pop .nh-run{flex:1;min-width:0;display:flex;flex-direction:column;gap:1px;text-align:left;background:none;border:0;border-radius:7px;padding:6px;color:inherit;font:inherit;cursor:pointer}
.nh-label{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12.5px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.nh-pop .nh-del{background:none;border:0;color:var(--muted);font-size:17px;line-height:1;padding:0 9px;cursor:pointer}
.nh-pop .nh-del:hover{color:var(--text)}
.nh-empty{margin:4px 6px 8px}
.nh-sec{margin:10px 6px 6px;color:var(--muted);font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.04em}
.nh-tools{display:flex;flex-wrap:wrap;gap:6px;padding:0 6px}
.nh-tools a{border:1px solid var(--border);border-radius:999px;padding:3px 10px;color:var(--text);text-decoration:none;font-size:12.5px}
.nh-tools a:hover{border-color:var(--accent);color:var(--accent)}
.nh-foot{display:flex;justify-content:space-between;align-items:center;gap:8px;border-top:1px solid var(--border);margin-top:10px;padding:8px 6px 2px}
.nh-foot label{display:inline-flex;gap:6px;align-items:center;cursor:pointer}
.nh-pop .nh-clear{font-size:12px;padding:3px 10px}`;
  const ICON = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="vertical-align:-3px"><path d="M3 12a9 9 0 1 0 2.6-6.4L3 8"/><path d="M3 3v5h5M12 7v5l3 2"/></svg>';
  let pop, btn, wrap;
  function renderPop(){
    const list = get(HIST, []), rec = get('recent', []).filter(r => r.slug !== slug).slice(0, 6), on = enabled();
    pop.innerHTML = `<div class="nh-head"><b>Recent inputs</b><span class="nh-muted">saved in this browser only</span></div>
      ${list.length ? list.map((e, i) => `<div class="nh-item"><button type="button" class="nh-run" data-i="${i}" title="Restore and run again"><span class="nh-label">${h(e.label)}</span><span class="nh-muted">${e.tabName ? h(e.tabName) + ' · ' : ''}${e.more ? `+${e.more} line${e.more > 1 ? 's' : ''} · ` : ''}${ago(e.t)}</span></button><button type="button" class="nh-del" data-del="${i}" title="Remove" aria-label="Remove">×</button></div>`).join('')
        : `<p class="nh-muted nh-empty">${on ? 'Nothing yet — inputs you run here will show up here.' : 'History is off.'}</p>`}
      ${rec.length ? `<div class="nh-sec">Recent tools</div><div class="nh-tools">${rec.map(r => `<a href="../${encodeURIComponent(r.slug)}/">${h(r.title)}</a>`).join('')}</div>` : ''}
      <div class="nh-foot"><label class="nh-muted"><input type="checkbox" class="nh-on"${on ? ' checked' : ''}> Remember inputs &amp; recent tools</label>${list.length ? '<button type="button" class="nh-clear">Clear</button>' : ''}</div>`;
  }
  function open(){
    renderPop(); pop.hidden = false; btn.setAttribute('aria-expanded', 'true');
    const left = wrap.getBoundingClientRect().right < pop.offsetWidth + 16;   // header wrapped onto its own line on narrow screens
    pop.style.left = left ? '0' : 'auto'; pop.style.right = left ? 'auto' : '0';
  }
  function close(){ if (pop && !pop.hidden) { pop.hidden = true; btn.setAttribute('aria-expanded', 'false'); } }
  function buildUI(){
    const theme = document.getElementById('themeBtn'); if (!theme) return;
    document.head.appendChild(Object.assign(document.createElement('style'), { textContent: CSS_TEXT }));
    wrap = document.createElement('div'); wrap.className = 'nh-actions'; wrap.dataset.nosave = '';
    wrap.innerHTML = `<button type="button" id="nhBtn" title="Recent inputs and tools" aria-haspopup="true" aria-expanded="false">${ICON} History</button><div class="nh-pop" role="dialog" aria-label="Recent inputs" hidden></div>`;
    theme.replaceWith(wrap); wrap.appendChild(theme);
    btn = wrap.firstElementChild; pop = wrap.querySelector('.nh-pop');
    btn.onclick = () => pop.hidden ? open() : close();
    pop.addEventListener('click', e => {
      const run = e.target.closest('[data-i]'), rm = e.target.closest('[data-del]');
      if (rm) { const l = get(HIST, []); l.splice(+rm.dataset.del, 1); l.length ? put(HIST, l) : del(HIST); renderPop(); }
      else if (run) restore(get(HIST, [])[+run.dataset.i]);
      else if (e.target.closest('.nh-clear')) { del(HIST); del(DRAFT); renderPop(); }
    });
    pop.addEventListener('change', e => {
      if (!e.target.matches('.nh-on')) return;
      if (e.target.checked) put('remember', true); else { clearAll(); put('remember', false); }
      renderPop();
    });
    document.addEventListener('click', e => { if (!pop.hidden && !e.composedPath().includes(wrap)) close(); });
    document.addEventListener('keydown', e => { if (e.key === 'Escape' && !pop.hidden) { close(); btn.focus(); } });
  }

  /* ---------- wiring ---------- */
  function init(){
    const params = [...new URLSearchParams(location.search).keys()].filter(k => k !== 'tab');
    if (!params.length) fields(document).forEach(el => BASE.set(el, val(el)));   // with ?q= links, compare against the HTML defaults instead
    buildUI();
    const live = !document.querySelector('button.primary:not([data-nosave])');   // tools that update as you type have no run button
    document.addEventListener('click', e => {
      const b = e.target.closest?.('button.primary'); if (!b || b.closest('[data-nosave]')) return;
      record(b.closest('.pane') || document, b.id ? { btn: b.id } : {});
    }, true);
    document.addEventListener('keydown', e => {
      const el = e.target;
      if (e.key !== 'Enter' || e.isComposing || !el.id || !el.matches?.(TEXT) || el.closest('[data-nosave]')) return;
      const ta = el.tagName === 'TEXTAREA'; if (ta && !(e.ctrlKey || e.metaKey)) return;
      record(el.closest('.pane') || document, ta ? { key: el.id, ctrl: true } : { key: el.id });
    }, true);
    let dt, lt;
    const later = () => { clearTimeout(dt); dt = setTimeout(saveDraft, 400); };
    document.addEventListener('input', later, true); document.addEventListener('change', later, true);
    if (live) document.addEventListener('change', e => { if (e.target.id && e.target.matches?.(TEXT)) { clearTimeout(lt); lt = setTimeout(() => record(e.target.closest('.pane') || document, {}), 300); } }, true);
    addEventListener('pagehide', () => { saveDraft(); if (live) record(document, {}); });
    document.addEventListener('visibilitychange', () => document.visibilityState === 'hidden' && saveDraft());
    if (!enabled()) return;
    put('recent', [{ slug, title: document.title.replace(/\s*·\s*NetOps Toolkit\s*$/, ''), t: Date.now() }, ...get('recent', []).filter(r => r.slug !== slug)].slice(0, 12));
    if (params.length) record(document.querySelector('.pane:not([hidden])') || document, {});
    else { const d = get(DRAFT, null); if (d) apply(d, document, false); }
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init); else init();
})();
