/* CONDA dashboard — JS murni, tanpa pustaka/CDN (harus jalan offline).
 *
 * Dua mode memakai kode render yang sama:
 *   live   : WebSocket /ws ke server (docs/protokol.md §4)
 *   replay : memutar ulang rekaman JSONL pesan WebSocket (§7), mis. di GitHub Pages
 * Pilih dengan ?mode=live|replay (default: replay di github.io / file://, selain itu live).
 *
 * KEAMANAN: SSID/alamat berasal dari udara (bisa dibuat penyerang), jadi semua teks
 * dimasukkan lewat textContent / createTextNode — tidak pernah innerHTML.
 */
'use strict';

/* ======================================================================
 * Konstanta & utilitas
 * ==================================================================== */
const SEV = {
  critical: { label: 'KRITIS', rank: 3, badge: 'b-crit' },
  high:     { label: 'TINGGI', rank: 2, badge: 'b-high' },
  medium:   { label: 'SEDANG', rank: 1, badge: 'b-warn' },
  low:      { label: 'INFO',   rank: 0, badge: 'b-low' },
};
const STATE_LABEL = { ok: 'Normal', warn: 'WASPADA', alert: 'BAHAYA', lost: 'HILANG', unknown: 'Menunggu laporan' };
const AP_STATUS = { official: 'Resmi', unknown: 'Tak dikenal', suspect: 'Mencurigakan' };
const AP_STATUS_RANK = { suspect: 0, unknown: 1, official: 2 };
const STALE_AFTER_S = 60;
const MAX_FEED = 200;

const params = new URLSearchParams(location.search);
const MODE = params.get('mode') ||
  ((/\.github\.io$/.test(location.hostname) || location.protocol === 'file:') ? 'replay' : 'live');
const REPLAY_FILE = params.get('file') || 'demo.jsonl';

const $ = (id) => document.getElementById(id);
const SVGNS = 'http://www.w3.org/2000/svg';

function h(tag, props, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v === false || v == null) continue;
    if (k === 'class') el.className = v;
    else if (k === 'text') el.textContent = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const kid of kids.flat()) if (kid != null) el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  return el;
}
function s(tag, attrs, ...kids) {
  const el = document.createElementNS(SVGNS, tag);
  for (const [k, v] of Object.entries(attrs || {})) if (v != null) el.setAttribute(k, v);
  for (const kid of kids.flat()) if (kid != null) el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  return el;
}
function store(key, val) {
  try { if (val === undefined) return localStorage.getItem(key); localStorage.setItem(key, val); } catch (e) { return null; }
}
const pad2 = (n) => String(n).padStart(2, '0');
function fmtClock(ts) { const d = new Date(ts * 1000); return pad2(d.getHours()) + ':' + pad2(d.getMinutes()) + ':' + pad2(d.getSeconds()); }
function fmtDur(sec) { sec = Math.max(0, Math.floor(sec)); return pad2(Math.floor(sec / 60)) + ':' + pad2(sec % 60); }
function ago(sec) {
  if (sec == null || isNaN(sec)) return '—';
  sec = Math.max(0, Math.floor(sec));
  if (sec < 5) return 'baru saja';
  if (sec < 60) return sec + ' dtk lalu';
  if (sec < 3600) return Math.floor(sec / 60) + ' mnt lalu';
  return Math.floor(sec / 3600) + ' jam lalu';
}

/* ======================================================================
 * State
 * ==================================================================== */
const S = { nodes: new Map(), aps: new Map(), ble: new Map(), alerts: [], floorplan: null, skew: 0, whitelist: [] };
const isOfficialBssid = (b) => S.whitelist.some((w) => w.bssids.includes(b));
let SILENT = false;                        // true saat memuat ulang state (seek/snapshot): tanpa bunyi & flash

/** "Sekarang" menurut sistem: jam browser + selisih ke server (live) atau jam rekaman (replay). */
function clockNow() {
  if (MODE === 'replay') return R.baseTs + R.pos;
  return Date.now() / 1000 + S.skew;
}

function resetState() {
  S.nodes.clear(); S.aps.clear(); S.ble.clear(); S.alerts = [];
  feedEls.clear(); $('feed').replaceChildren();
  apRows.clear(); $('apTable').tBodies[0].replaceChildren();
  bleRows.clear(); $('bleTable').tBodies[0].replaceChildren();
  hideBanner();
}

/** Satu pintu untuk semua pesan server (live maupun replay). */
function apply(msg) {
  switch (msg.t) {
    case 'snapshot': {
      resetState();
      if (MODE === 'live') S.skew = (msg.server_ts || 0) - Date.now() / 1000;
      S.floorplan = msg.floorplan;
      S.whitelist = msg.whitelist || [];
      for (const n of msg.nodes) S.nodes.set(n.node, n);
      for (const a of msg.aps) S.aps.set(a.bssid, a);
      for (const b of msg.ble) S.ble.set(b.addr, b);
      S.alerts = msg.alerts.slice();                      // terbaru lebih dulu
      buildPlan(); dirty.plan = dirty.stats = dirty.aps = dirty.ble = true;
      rebuildFeed();
      break;
    }
    case 'node_status': {
      const { t, ...n } = msg; S.nodes.set(n.node, n);
      dirty.plan = dirty.stats = true; break;
    }
    case 'ap_update': { const { t, ...a } = msg; S.aps.set(a.bssid, a); dirty.aps = dirty.stats = true; break; }
    case 'ble_update': { const { t, ...b } = msg; S.ble.set(b.addr, b); dirty.ble = dirty.stats = true; break; }
    case 'alert': {
      const { t, ...a } = msg;
      if (S.alerts.some((x) => x.id === a.id)) break;
      S.alerts.unshift(a);
      if (S.alerts.length > MAX_FEED) S.alerts.length = MAX_FEED;
      addAlertEl(a, true, true);
      dirty.stats = true;
      onNewAlert(a);
      break;
    }
    case 'alert_ack': {
      const a = S.alerts.find((x) => x.id === msg.id);
      if (a) { a.acked = true; updateAlertEl(a); dirty.stats = true; }
      break;
    }
    case 'config_changed': S.whitelist = msg.whitelist || []; for (const tr of apRows.values()) tr.children[3].dataset.st = ''; dirty.aps = true; toast('Whitelist diperbarui'); break;
    default: break;
  }
  schedule();
}

/* ======================================================================
 * Render (dikelompokkan per rAF)
 * ==================================================================== */
const dirty = { plan: false, stats: false, aps: false, ble: false };
let rafPending = false;
function schedule() {                      // setTimeout (bukan rAF) agar tetap diperbarui di tab latar
  if (rafPending) return;
  rafPending = true;
  setTimeout(() => {
    rafPending = false;
    if (dirty.plan) { updatePlan(); dirty.plan = false; }
    if (dirty.stats) { renderStats(); dirty.stats = false; }
    if (dirty.aps) { renderAps(); dirty.aps = false; }
    if (dirty.ble) { renderBle(); dirty.ble = false; }
  }, 50);
}

/* ---------- denah ---------- */
const nodeEls = new Map();
function buildPlan() {
  const fp = S.floorplan;
  const host = $('plan');
  host.replaceChildren();
  nodeEls.clear();
  if (!fp) return;
  const svg = s('svg', { viewBox: `0 0 ${fp.width} ${fp.height}`, role: 'img', 'aria-label': 'Denah area dan status node' });
  if (fp.image) svg.append(s('image', { href: fp.image, x: 0, y: 0, width: fp.width, height: fp.height, opacity: 0.55 }));
  for (const r of fp.rooms || []) {
    svg.append(s('rect', { class: 'room', x: r.x, y: r.y, width: r.w, height: r.h, rx: 8 }));
    svg.append(s('text', { class: 'room-label', x: r.x + 10, y: r.y + 20 }, r.name));
  }
  for (const n of S.nodes.values()) {
    if (n.x == null) continue;
    const g = s('g', { class: 'node s-unknown', transform: `translate(${n.x} ${n.y})` });
    const title = s('title', {}, '');
    const pulse = s('circle', { class: 'pulse', r: 16 });
    const core = s('circle', { class: 'core', r: 16 });
    const nid = s('text', { class: 'nid' }, n.node);
    const nname = s('text', { class: 'nname', y: 34 }, n.name || n.node);
    const nstate = s('text', { class: 'nstate', y: 49 }, '');
    g.append(title, pulse, core, nid, nname, nstate);
    svg.append(g);
    nodeEls.set(n.node, { g, title, nstate });
  }
  host.append(svg);
  updatePlan();
}
function updatePlan() {
  const now = clockNow();
  for (const [id, n] of S.nodes) {
    const e = nodeEls.get(id);
    if (!e) continue;
    e.g.setAttribute('class', 'node s-' + n.state);
    const seen = n.last_seen != null ? ago(now - n.last_seen) : 'belum pernah';
    e.nstate.textContent = STATE_LABEL[n.state] + (n.state === 'unknown' ? '' : ' · ' + seen);
    e.title.textContent = `${id} ${n.name || ''}\nStatus: ${STATE_LABEL[n.state]}\nTerakhir melapor: ${seen}` +
      (n.uptime_s != null ? `\nUptime: ${fmtDur(n.uptime_s)}` : '') + (n.heap_kb != null ? `\nHeap bebas: ${n.heap_kb} KB` : '');
    e.nstate.dataset.last = n.last_seen != null ? n.last_seen : '';
  }
}

/* ---------- ringkasan ---------- */
function renderStats() {
  const nodes = [...S.nodes.values()];
  const okN = nodes.filter((n) => n.state === 'ok' || n.state === 'warn' || n.state === 'alert').length;
  const lost = nodes.filter((n) => n.state === 'lost').length;
  const unacked = S.alerts.filter((a) => !a.acked && a.severity !== 'low');
  const crit = unacked.filter((a) => a.severity === 'critical' || a.severity === 'high').length;
  const apBad = [...S.aps.values()].filter((a) => a.status !== 'official' && now() - a.last_seen < STALE_AFTER_S).length;
  const apSus = [...S.aps.values()].filter((a) => a.status === 'suspect').length;
  const trk = [...S.ble.values()].filter((b) => b.foreign && now() - b.last_seen < STALE_AFTER_S).length;

  const tiles = [
    { cls: lost ? 'bad' : 'ok', v: `${okN}/${nodes.length}`, l: lost ? `Node aktif · ${lost} hilang` : 'Node aktif' },
    { cls: crit ? 'bad' : unacked.length ? 'warn' : 'ok', v: unacked.length, l: crit ? `Alert belum dilihat · ${crit} berbahaya` : 'Alert belum dilihat' },
    { cls: apSus ? 'bad' : 'ok', v: apSus, l: apBad ? `AP mencurigakan · ${apBad} tak resmi terlihat` : 'AP mencurigakan' },
    { cls: trk ? 'warn' : 'ok', v: trk, l: 'Pelacak BLE asing aktif' },
  ];
  $('stats').replaceChildren(...tiles.map((t) => h('div', { class: 'stat ' + t.cls }, h('div', { class: 'v', text: t.v }), h('div', { class: 'l', text: t.l }))));

  $('unacked').textContent = unacked.length ? `${unacked.length} belum dilihat` : 'semua sudah dilihat';
  const crits = unacked.filter((a) => a.severity === 'critical').length;
  document.title = (crits ? `(${crits}!) ` : '') + 'CONDA — Pemantau Ancaman Wi-Fi & BLE';
}
const now = () => clockNow();

/* ---------- tabel berkunci (baris dipakai ulang agar klik tombol tidak hilang saat data masuk) ---------- */
function syncRows(tbody, rowsMap, items, keyOf, create, update, sorter, emptyText) {
  const wanted = new Set();
  for (const it of items) {
    const k = keyOf(it);
    wanted.add(k);
    let tr = rowsMap.get(k);
    if (!tr) { tr = create(it); rowsMap.set(k, tr); }
    update(tr, it);
  }
  for (const [k, tr] of rowsMap) if (!wanted.has(k)) { tr.remove(); rowsMap.delete(k); }
  items.sort(sorter);
  items.forEach((it, i) => {
    const tr = rowsMap.get(keyOf(it));
    const current = tbody.children[i];
    if (current !== tr) tbody.insertBefore(tr, current || null);
  });
  const emptyEl = tbody.querySelector('.empty-row');
  if (!items.length && !emptyEl) tbody.append(h('tr', { class: 'empty-row' }, h('td', { colspan: 8, text: emptyText })));
  if (items.length && emptyEl) emptyEl.remove();
}

const apRows = new Map();
function renderAps() {
  const items = [...S.aps.values()];
  $('apCount').textContent = `${items.length} terlihat · ${items.filter((a) => a.status !== 'official').length} tidak resmi`;
  syncRows($('apTable').tBodies[0], apRows, items, (a) => a.bssid, createApRow, updateApRow,
    (a, b) => (AP_STATUS_RANK[a.status] - AP_STATUS_RANK[b.status]) || (a.ssid || '~').localeCompare(b.ssid || '~') || a.bssid.localeCompare(b.bssid),
    'Belum ada AP terdeteksi.');
}
function createApRow(a) {
  const tr = h('tr', {}, h('td'), h('td', { class: 'mono' }), h('td', { class: 'mono' }), h('td'), h('td', { class: 'actions' }));
  tr.dataset.bssid = a.bssid;
  return tr;
}
function twoLine(top, bottom, topClass) {
  return [h('div', { class: topClass || 'l1', text: top }), h('div', { class: 'l2 mono', text: bottom })];
}
function updateApRow(tr, a) {
  const c = tr.children;
  tr.className = 'st-' + a.status;
  tr.dataset.last = a.last_seen;
  const hidden = a.hidden || !a.ssid;
  c[0].replaceChildren(...twoLine(hidden ? '(tersembunyi)' : a.ssid, a.bssid, hidden ? 'l1 ssid-hidden' : 'l1'));
  c[1].replaceChildren(h('span', { text: 'Kanal ' + a.ch + ' · ' }), h('span', { class: a.sec === 'OPEN' ? 'sec-open' : '', text: a.sec }));
  c[2].replaceChildren(h('div', { class: 'l1', text: `${a.rssi_best} dBm · ${a.node_best}` }),
    h('div', { class: 'l2', 'data-ago': a.last_seen, text: ago(clockNow() - a.last_seen) }));
  if (c[3].dataset.st !== a.status) {
    c[3].dataset.st = a.status;
    c[3].replaceChildren(h('span', { class: 'badge b-' + a.status, text: AP_STATUS[a.status] }));
    c[4].replaceChildren(...(a.status === 'official' || isOfficialBssid(a.bssid) ? [] : [
      h('button', { type: 'button', class: 'btn btn-sm btn-ok', 'data-act': 'promote', 'data-bssid': a.bssid, text: 'Jadikan resmi' }),
      h('button', { type: 'button', class: 'btn btn-sm', 'data-act': 'ignore', 'data-bssid': a.bssid, text: 'Abaikan' }),
    ]));
  }
}

const bleRows = new Map();
function renderBle() {
  const items = [...S.ble.values()];
  $('bleCount').textContent = items.length ? `${items.filter((b) => b.foreign).length} asing` : '';
  syncRows($('bleTable').tBodies[0], bleRows, items, (b) => b.addr,
    () => h('tr', {}, h('td'), h('td'), h('td'), h('td', { class: 'mono' })),
    (tr, b) => {
      const c = tr.children;
      tr.className = b.foreign ? 'st-suspect' : 'st-official';
      tr.dataset.last = b.last_seen;
      c[0].replaceChildren(...twoLine(b.label || b.kind, b.addr));
      c[1].replaceChildren(h('span', { class: 'badge ' + (b.foreign ? 'b-suspect' : 'b-official'), text: b.foreign ? 'Asing' : 'Dikenal' }));
      c[2].replaceChildren(h('div', { class: 'l1', text: `${b.rssi_best} dBm · ${b.node_best}` }),
        h('div', { class: 'l2', 'data-ago': b.last_seen, text: ago(clockNow() - b.last_seen) }));
      c[3].textContent = b.reports + '×';
    },
    (a, b) => (b.last_seen || 0) - (a.last_seen || 0) || a.addr.localeCompare(b.addr),
    'Belum ada perangkat berformat pelacak terdeteksi.');
}

/* ---------- feed alert ---------- */
const feedEls = new Map();
function rebuildFeed() {
  $('feed').replaceChildren(); feedEls.clear();
  for (const a of S.alerts) addAlertEl(a, false, false);          // terbaru lebih dulu
  $('feedEmpty').classList.toggle('hidden', S.alerts.length > 0);
  dirty.stats = true;
}
function addAlertEl(a, prepend, fresh) {
  const sev = SEV[a.severity] || SEV.low;
  const ackBtn = h('button', { type: 'button', class: 'btn btn-sm', 'data-act': 'ack', 'data-id': a.id, text: 'Tandai dilihat' });
  const li = h('li', { class: `alert sev-${a.severity}${fresh && !SILENT ? ' fresh' : ''}`, 'data-id': a.id },
    h('div', { class: 'a-head' },
      h('span', { class: 'badge ' + sev.badge, text: sev.label }),
      h('span', { class: 'rule', text: a.rule }),
      h('time', { text: fmtClock(a.ts), title: new Date(a.ts * 1000).toLocaleString() })),
    h('div', { class: 'a-title', text: a.title }),
    h('div', { class: 'a-detail', text: a.detail }),
    h('div', { class: 'a-foot' },
      h('span', { text: a.node ? 'Node ' + a.node : '' }),
      a.severity === 'low' ? null : ackBtn));
  feedEls.set(a.id, li);
  if (prepend) $('feed').prepend(li); else $('feed').append(li);
  while ($('feed').children.length > MAX_FEED) { const last = $('feed').lastElementChild; feedEls.delete(Number(last.dataset.id)); last.remove(); }
  $('feedEmpty').classList.add('hidden');
  updateAlertEl(a);
}
function updateAlertEl(a) {
  const li = feedEls.get(a.id);
  if (!li) return;
  li.classList.toggle('acked', !!a.acked);
  const btn = li.querySelector('[data-act="ack"]');
  if (btn) { btn.disabled = !!a.acked; btn.textContent = a.acked ? 'Sudah dilihat' : 'Tandai dilihat'; }
}

/* ======================================================================
 * Alarm suara (WebAudio — tanpa berkas audio, jadi tetap offline)
 * ==================================================================== */
const Snd = {
  ctx: null, on: false, busyUntil: 0, busyRank: -1,
  async enable() {
    try {
      const AC = window.AudioContext || window.webkitAudioContext;
      if (!AC) { toast('Browser ini tidak mendukung audio'); return; }
      if (!this.ctx) this.ctx = new AC();
      await this.ctx.resume();
      this.on = true; store('conda.sound', '1');
      this.play('medium');                                    // bunyi uji
    } catch (e) { toast('Tidak bisa mengaktifkan suara: ' + e.message); }
    renderSoundBtn();
  },
  disable() { this.on = false; store('conda.sound', '0'); renderSoundBtn(); },
  tone(freq, t0, dur, vol, type) {
    const o = this.ctx.createOscillator(), g = this.ctx.createGain();
    o.type = type; o.frequency.setValueAtTime(freq, t0);
    g.gain.setValueAtTime(0.0001, t0);
    g.gain.exponentialRampToValueAtTime(vol, t0 + 0.015);
    g.gain.exponentialRampToValueAtTime(0.0001, t0 + dur);
    o.connect(g); g.connect(this.ctx.destination);
    o.start(t0); o.stop(t0 + dur + 0.03);
  },
  /** critical = sirene 2 nada ±2,2 dtk; high = 3 bip; medium = 1 nada lembut. */
  play(sev) {
    if (!this.on || !this.ctx) return;
    const rank = (SEV[sev] || SEV.low).rank;
    const t = this.ctx.currentTime;
    if (t < this.busyUntil && rank <= this.busyRank) return;   // jangan menimpa bunyi yang sama/lebih penting
    if (sev === 'critical') {
      for (let i = 0; i < 8; i++) this.tone(i % 2 ? 660 : 960, t + i * 0.28, 0.26, 0.22, 'sawtooth');
      this.busyUntil = t + 2.3;
    } else if (sev === 'high') {
      for (let i = 0; i < 3; i++) this.tone(780, t + i * 0.2, 0.14, 0.18, 'square');
      this.busyUntil = t + 0.7;
    } else {
      this.tone(520, t, 0.32, 0.14, 'sine');
      this.busyUntil = t + 0.4;
    }
    this.busyRank = rank;
  },
};
function renderSoundBtn() {
  const b = $('soundBtn');
  b.classList.toggle('sound-on', Snd.on);
  b.classList.toggle('sound-needs', !Snd.on && store('conda.sound') !== '0');
  b.textContent = Snd.on ? 'Suara: aktif (klik untuk bisukan)' : 'Suara: aktifkan';
}

function onNewAlert(a) {
  if (SILENT || a.severity === 'low') return;
  Snd.play(a.severity);
  if (a.severity === 'critical' || a.severity === 'high') showBanner(a);
}

/* ---------- banner & toast ---------- */
let bannerTimer = null;
function showBanner(a) {
  const b = $('banner');
  b.className = 'banner sev-' + a.severity;
  b.textContent = `${SEV[a.severity].label} · ${a.title} — ${a.detail}`;
  clearTimeout(bannerTimer);
  bannerTimer = setTimeout(hideBanner, 12000);
}
function hideBanner() { clearTimeout(bannerTimer); $('banner').className = 'banner hidden'; }
let toastTimer = null;
function toast(msg) {
  const t = $('toast');
  t.textContent = msg; t.classList.remove('hidden');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.add('hidden'), 3500);
}

/* ======================================================================
 * Aksi operator
 * ==================================================================== */
async function api(path, body) {
  if (MODE === 'replay') { toast('Mode replay: aksi tidak dijalankan (hanya demonstrasi tampilan)'); return false; }
  try {
    const r = await fetch(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: body ? JSON.stringify(body) : undefined });
    if (!r.ok) { let d = ''; try { d = (await r.json()).detail; } catch (e) { /* abaikan */ } toast('Gagal: ' + (d || r.status)); return false; }
    return true;
  } catch (e) { toast('Server tidak terjangkau'); return false; }
}

document.addEventListener('click', async (ev) => {
  const btn = ev.target.closest('button[data-act]');
  if (!btn) return;
  const act = btn.dataset.act;
  if (act === 'ack') {
    const id = Number(btn.dataset.id);
    if (MODE === 'replay') { const a = S.alerts.find((x) => x.id === id); if (a) { a.acked = true; updateAlertEl(a); dirty.stats = true; schedule(); } return; }
    await api(`/api/alerts/${id}/ack`);                          // server menyiarkan alert_ack
  } else if (act === 'promote') {
    const ap = S.aps.get(btn.dataset.bssid);
    if (!ap) return;
    const warn = ap.status === 'suspect'
      ? `PERINGATAN: AP ini ditandai MENCURIGAKAN.\nMenjadikannya resmi berarti melegitimasi AP tersebut dan menghentikan alert-nya.\n\n`
      : '';
    if (!confirm(`${warn}Jadikan resmi?\n\nSSID  : ${ap.ssid || '(tersembunyi)'}\nBSSID : ${ap.bssid}\nKeamanan: ${ap.sec}\n\nPerubahan ditulis ke config/whitelist.json.`)) return;
    if (!ap.ssid) { toast('AP tersembunyi tidak bisa dijadikan resmi tanpa SSID'); return; }
    if (await api('/api/whitelist/promote', { bssid: ap.bssid, ssid: ap.ssid, security: [ap.sec] })) toast('AP dijadikan resmi');
  } else if (act === 'ignore') {
    const ap = S.aps.get(btn.dataset.bssid);
    if (!ap) return;
    if (!confirm(`Abaikan AP ini?\n\n${ap.ssid || '(tersembunyi)'} · ${ap.bssid}\n\nAP tidak lagi dilaporkan sebagai rogue AP.`)) return;
    if (await api('/api/whitelist/ignore', { bssid: ap.bssid })) toast('AP diabaikan');
  }
});

$('clearBtn').addEventListener('click', async () => { if (await api('/api/alarm/clear')) toast('Alarm node dipadamkan'); });
$('soundBtn').addEventListener('click', () => (Snd.on ? Snd.disable() : Snd.enable()));
// Kebijakan autoplay: konteks audio baru boleh dibuat setelah gestur. Bila pengguna pernah mengaktifkan
// suara, aktifkan lagi diam-diam pada klik pertama di halaman.
document.addEventListener('pointerdown', () => { if (!Snd.on && store('conda.sound') === '1') Snd.enable().then(() => { /* bunyi uji sekali */ }); }, { once: true });

/* ======================================================================
 * Mode live: WebSocket
 * ==================================================================== */
function setConn(kind, text) {
  const p = $('connPill');
  p.className = 'pill pill-' + kind; p.textContent = text;
}
let wsDelay = 1000, wsFailures = 0;
function connectLive() {
  const url = (location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host + '/ws';
  let ws;
  try { ws = new WebSocket(url); } catch (e) { setConn('down', 'Gagal membuka WebSocket'); return; }
  setConn('wait', 'Menghubungkan…');
  ws.onopen = () => { wsDelay = 1000; wsFailures = 0; setConn('ok', 'Terhubung ke server'); };
  ws.onmessage = (e) => {
    let msg; try { msg = JSON.parse(e.data); } catch (err) { return; }
    SILENT = msg.t === 'snapshot';
    try { apply(msg); } finally { SILENT = false; }
  };
  ws.onclose = () => {
    wsFailures++;
    setConn('down', 'Terputus — mencoba lagi…');
    if (wsFailures >= 3 && !$('banner').dataset.shown) {
      $('banner').dataset.shown = '1';
      const b = $('banner');
      b.className = 'banner info';
      b.replaceChildren('Server tidak terjangkau. Tidak punya server/ESP32? ', h('a', { href: '?mode=replay', style: 'color:inherit;text-decoration:underline', text: 'Buka mode replay' }), '.');
    }
    setTimeout(connectLive, wsDelay);
    wsDelay = Math.min(wsDelay * 1.6, 8000);
  };
  ws.onerror = () => ws.close();
}

/* ======================================================================
 * Mode replay: memutar rekaman JSONL
 * ==================================================================== */
const R = { events: [], idx: 0, pos: 0, duration: 0, baseTs: 0, playing: true, speed: 1, last: 0, loaded: false };

async function loadReplay() {
  setConn('wait', 'Memuat rekaman…');
  const candidates = ['samples/' + REPLAY_FILE, '../data/samples/' + REPLAY_FILE, 'data/samples/' + REPLAY_FILE];
  let text = null;
  for (const url of candidates) {
    try { const r = await fetch(url); if (r.ok) { text = await r.text(); break; } } catch (e) { /* coba berikutnya */ }
  }
  if (text === null) { setConn('down', 'Rekaman tidak ditemukan'); toast('Berkas rekaman ' + REPLAY_FILE + ' tidak ditemukan'); return; }
  R.events = text.split('\n').filter(Boolean).map((l) => JSON.parse(l)).sort((a, b) => a.at - b.at);
  R.duration = R.events.length ? R.events[R.events.length - 1].at : 0;
  const snap = R.events.find((e) => e.t === 'snapshot');
  R.baseTs = snap ? snap.server_ts : Date.now() / 1000;
  buildTicks();
  R.loaded = true;
  setConn('ok', `Replay: ${REPLAY_FILE} · ${R.events.length} event`);
  seek(0);
  R.last = performance.now();
  setInterval(replayTick, 100);
}
function replayTick() {
  if (!R.loaded) return;
  const t = performance.now();
  const dt = (t - R.last) / 1000; R.last = t;
  if (R.playing) R.pos = Math.min(R.duration, R.pos + dt * R.speed);
  while (R.idx < R.events.length && R.events[R.idx].at <= R.pos) apply(R.events[R.idx++]);
  if (R.playing && R.pos >= R.duration) { seek(0); return; }       // ulang otomatis
  if (!scrubbing) $('scrub').value = R.duration ? Math.round((R.pos / R.duration) * 1000) : 0;
  $('replayTime').textContent = `${fmtDur(R.pos)} / ${fmtDur(R.duration)}`;
}
function seek(pos) {
  R.pos = Math.max(0, Math.min(R.duration, pos));
  R.idx = 0;
  SILENT = true;
  try { while (R.idx < R.events.length && R.events[R.idx].at <= R.pos) apply(R.events[R.idx++]); }
  finally { SILENT = false; }
  if (R.idx === 0) resetState();
}
function buildTicks() {
  const box = $('ticks'); box.replaceChildren();
  const color = { critical: 'var(--crit)', high: 'var(--high)', medium: 'var(--med)' };
  for (const e of R.events) {
    if (e.t !== 'alert' || !color[e.severity] || !R.duration) continue;
    const i = h('i', { title: `${fmtDur(e.at)} · ${e.title}` });
    i.style.left = (e.at / R.duration) * 100 + '%'; i.style.background = color[e.severity];
    box.append(i);
  }
}
let scrubbing = false;
$('scrub').addEventListener('pointerdown', () => { scrubbing = true; });
$('scrub').addEventListener('pointerup', () => { scrubbing = false; });
$('scrub').addEventListener('input', (e) => seek((Number(e.target.value) / 1000) * R.duration));
$('playBtn').addEventListener('click', () => { R.playing = !R.playing; $('playBtn').textContent = R.playing ? 'Jeda' : 'Putar'; });
$('speedSel').addEventListener('change', (e) => { R.speed = Number(e.target.value); });

/* ======================================================================
 * Awal
 * ==================================================================== */
function tickUi() {
  const n = clockNow();
  $('clock').textContent = fmtClock(n);
  for (const el of document.querySelectorAll('[data-ago]')) el.textContent = ago(n - Number(el.dataset.ago));
  for (const tr of document.querySelectorAll('tr[data-last]')) tr.classList.toggle('stale', n - Number(tr.dataset.last) > STALE_AFTER_S);
  updatePlan();
  dirty.stats = true; schedule();
}

(function init() {
  $('modeBadge').textContent = MODE === 'replay' ? 'REPLAY' : 'LIVE';
  $('modeBadge').classList.toggle('replay', MODE === 'replay');
  renderSoundBtn();
  if (MODE === 'replay') {
    $('replayBar').classList.remove('hidden');
    $('clearBtn').disabled = true;
    $('clearBtn').title = 'Tidak tersedia di mode replay';
    loadReplay();
  } else {
    connectLive();
  }
  setInterval(tickUi, 1000);
  tickUi();
})();
