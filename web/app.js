'use strict';

// ----------------------------------------------------------------- 基础
let TOKEN = localStorage.getItem('pihy2_token') || '';
let STATE = { nodes: [], rules: [], settings: {}, webui: {}, active: '' };
let DELAYS = {};
let rulesDirty = false;          // 路由有未保存修改时为 true
let toastTimer = null;

async function api(method, path, body) {
  // X-Requested-With：服务端对无 Origin 的请求要求该自定义头（CSRF 纵深防御，见 webui._guard_write）
  const opt = { method, headers: { 'X-Requested-With': 'pihy2' } };
  if (TOKEN) opt.headers['Authorization'] = 'Bearer ' + TOKEN;
  if (body !== undefined) { opt.headers['Content-Type'] = 'application/json'; opt.body = JSON.stringify(body); }
  let r;
  try { r = await fetch(path, opt); }
  catch (e) { return { ok: false, error: '网络错误' }; }   // 不抛：避免各 await 处未捕获的 promise 拒绝
  if (r.status === 401) {           // token 失效/服务端重启：清掉并回到登录（返回而非抛，调用方按 !ok 处理）
    TOKEN = ''; localStorage.removeItem('pihy2_token'); showLogin();
    return { ok: false, _unauth: true, error: '未登录' };
  }
  return await r.json().catch(() => ({}));
}

function el(id) { return document.getElementById(id); }
function esc(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }

function toast(msg, kind) {
  const t = el('toast');
  t.textContent = msg; t.className = 'toast ' + (kind || '');
  if (toastTimer) clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.add('hidden'), 2800);
}
// 统一处理“写操作”结果：成功提示 okMsg，失败显示后端 error
function done(r, okMsg) {
  const ok = r && r.ok;
  toast(ok ? okMsg : ('失败：' + ((r && (r.error || r.message)) || '请重试')), ok ? 'ok' : 'err');
  return ok;
}

// ----------------------------------------------------------------- 鉴权
async function boot() {
  const info = await fetch('/api/authinfo').then(r => r.json()).catch(() => ({ need_auth: false }));
  if (info.need_auth && !TOKEN) { showLogin(); return; }
  try {
    if (await loadState()) { showApp(); refreshStatus(); }
  } catch (e) { /* 401 已弹出登录框 */ }
}
function showLogin() { stopTraffic(); el('login').classList.remove('hidden'); el('app').classList.add('hidden'); }
function showApp() { el('login').classList.add('hidden'); el('app').classList.remove('hidden'); }

async function doLogin(e) {
  e.preventDefault();
  const pw = el('login-pw').value;
  const r = await fetch('/api/login', { method: 'POST', headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'pihy2' }, body: JSON.stringify({ password: pw }) }).then(r => r.json()).catch(() => ({}));
  if (r.ok) { TOKEN = r.token; localStorage.setItem('pihy2_token', TOKEN); el('login-pw').value = ''; el('login-err').textContent = ''; await loadState(); showApp(); refreshStatus(); }
  else { el('login-err').textContent = r.error || '密码错误'; }
}

async function loadState() {
  const s = await api('GET', '/api/state');
  if (!s.ok) return false;
  // 保住未保存的路由/预设/兜底策略编辑，避免被后台 loadState 覆盖丢失
  const keepRules = rulesDirty ? STATE.rules : null;
  const keepPresets = rulesDirty ? ((STATE.settings || {}).presets || []) : null;
  const keepFinal = rulesDirty ? ((STATE.settings || {}).final) : null;
  STATE = s;
  if (keepRules) STATE.rules = keepRules;
  if (keepPresets) { if (!STATE.settings) STATE.settings = {}; STATE.settings.presets = keepPresets; }
  if (keepFinal) { if (!STATE.settings) STATE.settings = {}; STATE.settings.final = keepFinal; }
  renderNodes(); renderRules(); renderSettings(); renderSubs();
  return true;
}

// ----------------------------------------------------------------- 订阅
function renderSubs() {
  const box = el('sub-list'); if (!box) return;
  const subs = STATE.subscriptions || [];
  box.innerHTML = subs.length ? subs.map(s => `
    <div class="node" style="padding:8px 12px">
      <div class="info"><div class="name">${esc(s.name)}</div>
        <div class="addr">${esc(s.url)}</div>
        <div class="muted small">节点 ${s.count || 0} · 更新于 ${esc(s.updated || '从未')}</div>
        ${s.last_error ? `<div class="muted small" style="color:var(--err-text)">上次失败：${esc(s.last_error)}</div>` : ''}</div>
      <button class="btn small" onclick="updateSub('${s.id}')">更新</button>
      <button class="btn small danger" onclick="delSub('${s.id}')">删除</button>
    </div>`).join('') : '<p class="muted small">暂无订阅。粘贴订阅链接，会定时自动更新节点。</p>';
  if (el('sub-interval')) el('sub-interval').value = STATE.sub_interval_hours || 12;
}
async function addSub() {
  const url = el('sub-url').value.trim();
  if (!url) { toast('请填订阅链接', 'err'); return; }
  toast('正在拉取订阅…');
  const r = await api('POST', '/api/subs', { url, name: el('sub-name').value.trim() });
  // /api/subs 即便拉取/解析失败也返回 ok:true（仅 count=0）——成功提示须以 count 为准（BUG-8）
  if (r.ok && r.count) { el('sub-url').value = ''; el('sub-name').value = ''; await loadState(); toast(`订阅已添加，${r.count} 个节点已生效`, 'ok'); }
  else if (r.ok) { await loadState(); toast('订阅已添加，但未解析到节点：' + ((r.errors || []).slice(0, 2).join('；') || '请检查链接或格式'), 'err'); }
  else toast('添加失败：' + (r.error || ''), 'err');
}
// /api/subs/update 恒返回 ok:true，逐订阅失败被服务端吞掉——“已生效”只在确有节点更新时才说（FRONT-2）
function reportSubUpdate(r, prefix) {
  if (r.ok && r.count) toast(`${prefix} ${r.count} 个节点并生效`, 'ok');
  else if (r.ok) toast('未更新到新节点，请检查订阅链接是否可访问', 'err');
  else toast('更新失败：' + (r.error || ''), 'err');
}
async function updateSub(id) {
  toast('更新中…');
  const r = await api('POST', '/api/subs/update', { id });
  await loadState(); reportSubUpdate(r, '已更新');
}
async function updateAllSubs() {
  if (!(STATE.subscriptions || []).length) { toast('没有订阅', 'err'); return; }
  toast('更新中…');
  const r = await api('POST', '/api/subs/update', { id: 'all' });
  await loadState(); reportSubUpdate(r, '已更新共');
}
async function delSub(id) {
  // 名字从 STATE 查，不拼进内联事件，避免订阅名里的引号造成存储型 XSS
  const sub = (STATE.subscriptions || []).find(x => x.id === id);
  if (!confirm(`删除订阅「${sub ? sub.name : id}」及其节点？`)) return;
  const r = await api('DELETE', '/api/subs/' + id);
  await loadState(); done(r, '已删除，记得“应用配置”');
}
async function saveSubInterval() {
  const h = parseInt(el('sub-interval').value) || 12;
  const r = await api('PUT', '/api/settings', { settings: {}, sub_interval_hours: h });
  done(r, '已保存，自动更新间隔已生效');
}

// ----------------------------------------------------------------- 标签页
function switchTab(name) {
  // 离开“路由”页且有未保存修改时提醒，避免静默丢失
  const leavingRules = !el('tab-rules').classList.contains('hidden') && name !== 'rules';
  if (leavingRules && rulesDirty) {
    if (!confirm('路由有未保存的修改，切走后仍会保留但不会生效。继续切换？')) return;
  }
  document.querySelectorAll('.tab').forEach(t => t.classList.toggle('active', t.dataset.tab === name));
  document.querySelectorAll('.tab-pane').forEach(p => p.classList.add('hidden'));
  el('tab-' + name).classList.remove('hidden');
  if (name === 'traffic') startTraffic(); else stopTraffic();   // 仅在流量页轮询
}

// ----------------------------------------------------------------- 状态栏
async function refreshStatus() {
  const s = await api('GET', '/api/status').catch(() => ({}));
  if (!s.ok) return;
  const m = el('st-mihomo');
  const active = (s.mihomo && s.mihomo.active) || '未知';
  const running = active === 'active';
  m.textContent = 'mihomo: ' + (running ? '运行中' : active);
  m.className = 'pill ' + (running ? 'ok' : 'bad');
  el('st-ip').textContent = '出口IP: ' + (s.ip || '—');
  const wb = el('warn-banner');                    // CONFLICT-5：把 DNS/VPN 冲突告警显示出来（含定时器 apply 检测到的）
  if (wb) {
    const ws = s.warnings || [];
    wb.innerHTML = ws.map(w => `<div>⚠️ ${esc(w)}</div>`).join('');
    wb.classList.toggle('hidden', !ws.length);
  }
}

let applying = false;
async function applyConfig() {
  if (applying) return;            // 防重复点击
  applying = true;
  toast('正在校验并应用…');
  try {
    const r = await api('POST', '/api/apply');
    toast(r.message || (r.ok ? '已应用' : '失败'), r.ok ? 'ok' : 'err');
    if (r.ok) setTimeout(refreshStatus, 1500);
  } finally { applying = false; }
}

// ----------------------------------------------------------------- 节点
// undefined=未测；null/<=0=测过但超时；其余=毫秒
function delayClass(d) { return d === undefined ? '' : (d === null || d <= 0) ? 'bad' : d < 300 ? 'good' : d < 800 ? 'mid' : 'bad'; }
function delayText(d) { return d === undefined ? '' : (d === null || d <= 0) ? '超时' : d + 'ms'; }

function renderNodes() {
  el('node-count').textContent = `（${STATE.nodes.length}）`;
  const list = el('node-list');
  if (!STATE.nodes.length) { list.innerHTML = '<p class="muted">还没有节点，点击右上角“添加节点”，把 hy2 链接粘贴进去即可。</p>'; return; }
  list.innerHTML = STATE.nodes.map(n => {
    const active = n.id === STATE.active;
    const tags = [esc((n.type || 'hysteria2').toUpperCase())];
    if (n.dialer_proxy) {
      const f = (STATE.nodes || []).find(x => x.id === n.dialer_proxy);
      tags.push('链式→' + esc(f ? f.name : '前置缺失'));
    }
    if (n.network && n.network !== 'tcp') tags.push(esc(n.network));
    if (n.reality_pbk) tags.push('reality');
    if (n.sub) { const s = (STATE.subscriptions || []).find(x => x.id === n.sub); tags.push('订阅:' + esc(s ? s.name : n.sub)); }
    if (n.obfs) tags.push('混淆:' + esc(n.obfs));
    if (n.ports) tags.push('端口跳跃:' + esc(n.ports));
    if (n.skip_cert_verify) tags.push('跳过证书校验');
    const d = DELAYS[n.id];
    return `<div class="node ${active ? 'active' : ''}" draggable="true" data-id="${n.id}">
      <div class="dot" title="设为当前出口" onclick="setActive('${n.id}')"></div>
      <div class="info">
        <div class="name">${esc(n.name)}</div>
        <div class="addr">${esc(n.server)}:${esc(n.port)}</div>
        ${tags.length ? `<div class="tags">${tags.map(t => `<span class="tag">${t}</span>`).join('')}</div>` : ''}
      </div>
      <div class="delay ${delayClass(d)}">${delayText(d)}</div>
      <button class="btn small" title="上移" onclick="moveNode('${n.id}',-1)">↑</button>
      <button class="btn small" title="下移" onclick="moveNode('${n.id}',1)">↓</button>
      <button class="btn small" onclick="editNode('${n.id}')">编辑</button>
      <button class="btn small danger" onclick="deleteNode('${n.id}')">删除</button>
    </div>`;
  }).join('');
  enableDragOrder();
}

// 上移/下移（触屏也能用，弥补 HTML5 拖拽在移动端不触发）
async function moveNode(id, dir) {
  const ids = STATE.nodes.map(n => n.id);
  const i = ids.indexOf(id), j = i + dir;
  if (i < 0 || j < 0 || j >= ids.length) return;
  ids.splice(j, 0, ids.splice(i, 1)[0]);
  STATE.nodes.sort((a, b) => ids.indexOf(a.id) - ids.indexOf(b.id));
  renderNodes();
  const r = await api('POST', '/api/nodes/order', { order: ids });
  if (!r.ok) { toast('排序保存失败', 'err'); await loadState(); }   // 失败回滚到服务端真实顺序（FRONT-1）
}

async function setActive(id) {
  const r = await api('POST', '/api/active', { id });
  if (!r.ok) { toast('切换失败：' + (r.error || ''), 'err'); return; }
  STATE.active = id; renderNodes();
  if (r.live) toast('已切换当前节点（已生效）', 'ok');
  else toast('已选为当前节点，点“应用配置并重启”后生效', 'ok');
}

async function deleteNode(id) {
  const n = STATE.nodes.find(x => x.id === id);
  // 该节点若被别的链式出口当前置（dialer_proxy）引用：删除后那些出口在下次应用时会被跳过（不再下发）。
  // 提前列出，避免用户困惑“我加的出口节点怎么没了”。
  const deps = STATE.nodes.filter(x => x.dialer_proxy === id);
  let msg = `删除节点「${n ? n.name : id}」？`;
  if (deps.length) {
    msg += `\n\n注意：它是以下链式出口的前置代理，删除后这些出口将不再生效（节点仍保留在列表，需改选其它前置）：\n`
      + deps.map(x => '· ' + x.name).join('\n');
  }
  if (!confirm(msg)) return;
  const r = await api('DELETE', '/api/nodes/' + id);
  await loadState();
  done(r, '已删除，记得“应用配置”');
}

async function testDelays() {
  toast('测速中…');
  const r = await api('GET', '/api/delays');
  if (r.ok) { DELAYS = r.delays; renderNodes(); toast('测速完成', 'ok'); }
  else toast('测速需要 mihomo 正在运行', 'err');
}

// 添加节点（粘贴链接 -> 预览 -> 确认）
function openAddNodes() {
  el('modal-card').innerHTML = `
    <h3>添加节点</h3>
    <p class="muted small">粘贴一个或多个分享链接（每行一个），或 base64 订阅内容。<br>
      支持 hysteria2 / vless / vmess / trojan / ss / tuic。</p>
    <textarea id="add-text" rows="6" placeholder="hysteria2://...&#10;vless://...&#10;vmess://...&#10;trojan://..."></textarea>
    <div class="bar" style="margin-top:8px"><button class="btn" onclick="previewNodes()">解析预览</button></div>
    <div id="add-preview"></div>
    <div class="modal-actions">
      <button class="btn" onclick="closeModal()">取消</button>
      <button class="btn primary" onclick="commitNodes()">添加</button>
    </div>`;
  el('modal').classList.remove('hidden');
}
async function previewNodes() {
  const r = await api('POST', '/api/parse', { text: el('add-text').value });
  const box = el('add-preview');
  let html = '';
  (r.nodes || []).forEach(n => { html += `<div class="preview-node">✓ <b>${esc(n.name)}</b> — ${esc(n.server)}:${esc(n.port)}${n.obfs ? ' · 混淆' : ''}${n.skip_cert_verify ? ' · 跳过证书' : ''}</div>`; });
  (r.errors || []).forEach(e => { html += `<div class="preview-node" style="color:var(--warn)">${esc(e)}</div>`; });
  box.innerHTML = html || '<p class="muted">无结果</p>';
}
async function commitNodes() {
  const r = await api('POST', '/api/nodes', { text: el('add-text').value });
  if (!r.ok) { toast('添加失败：' + (r.error || ''), 'err'); return; }
  closeModal();
  await loadState();
  const errs = (r.errors || []).length;
  toast(`已添加 ${(r.added || []).length} 个节点${errs ? `（${errs} 行无法解析）` : ''}，记得”应用配置”`, 'ok');
}

// 链式代理：添加 HTTP/SOCKS5 住宅 IP 代理作为「出口」。这类代理国内不可直连，
// 须挂在某个国内可达的普通节点（前置代理）后面经 dialer-proxy 出网。
// 前置下拉只列「自身非链式（无 dialer_proxy）」的节点——既是国内可达的中继，又天然防循环链。
function frontOptions(excludeId, selectedId) {
  const fronts = STATE.nodes.filter(n => n.id !== excludeId && !n.dialer_proxy && n.server);
  if (!fronts.length) return '<option value="">（请先添加一个国内可达的节点作为前置）</option>';
  return '<option value="">-- 选择前置节点 --</option>' +
    fronts.map(n => `<option value="${n.id}" ${n.id === selectedId ? 'selected' : ''}>${esc(n.name)}（${esc((n.type || '').toUpperCase())}）</option>`).join('');
}
function openAddChain() {
  el('modal-card').innerHTML = `
    <h3>添加链式代理 <span class="muted small">出口</span></h3>
    <p class="muted small">录入 HTTP/SOCKS5 住宅 IP 代理作为<b>出口</b>。它从国内不能直连，须挂在下面选的「前置代理」（国内可达的节点）后面链式出网，从而用更干净的 IP 上网。<br>
      <b>注意</b>：树莓派这一端的传输层由「前置代理」的协议决定——选 hy2/tuic 走 UDP，选 vless/vmess/trojan 走 TCP。挂链式出口改变不了前置段的协议（UDP 不会被转成 TCP）。</p>
    <div class="grid">
      <label>名称 <input id="ch-name" type="text" placeholder="如 美国家宽"></label>
      <label>类型
        <select id="ch-type"><option value="socks5">SOCKS5</option><option value="http">HTTP</option></select>
      </label>
      <label>服务器 <input id="ch-server" type="text" placeholder="住宅代理地址"></label>
      <label>端口 <input id="ch-port" type="number" placeholder="1080"></label>
      <label>用户名（可空） <input id="ch-user" type="text"></label>
      <label>密码（可空） <input id="ch-pass" type="text"></label>
    </div>
    <label class="row"><input id="ch-tls" type="checkbox"> 启用 TLS（HTTP/HTTPS 代理可选）</label>
    <label class="row"><input id="ch-skip" type="checkbox" checked> 跳过证书校验</label>
    <label>前置代理（必选 · 国内可达的中继节点）
      <select id="ch-front">${frontOptions(null, null)}</select>
    </label>
    <div class="modal-actions">
      <button class="btn" onclick="closeModal()">取消</button>
      <button class="btn primary" onclick="commitChain()">添加</button>
    </div>`;
  el('modal').classList.remove('hidden');
}
async function commitChain() {
  const front = el('ch-front').value;
  if (!front) { toast('请选择前置代理节点（链式出口必须挂在它后面）', 'err'); return; }
  const server = el('ch-server').value.trim();
  if (!server) { toast('请填服务器地址', 'err'); return; }
  const node = {
    type: el('ch-type').value,
    name: el('ch-name').value.trim() || server,
    server,
    port: parseInt(el('ch-port').value) || 1080,
    username: el('ch-user').value.trim(),
    password: el('ch-pass').value,
    tls: el('ch-tls').checked,
    skip_cert_verify: el('ch-skip').checked,
    dialer_proxy: front,
  };
  const r = await api('POST', '/api/nodes', { node });
  if (!r.ok) { toast('添加失败：' + (r.error || ''), 'err'); return; }
  closeModal(); await loadState();
  toast('已添加链式代理，记得”应用配置”', 'ok');
}

// 编辑节点：按协议显示对应字段
const COMMON = [['name', '名称'], ['server', '服务器'], ['port', '端口', 'number']];
const NET = [['network', '传输(tcp/ws/grpc)'], ['ws_path', 'ws 路径'], ['ws_host', 'ws Host'], ['grpc_service_name', 'grpc 服务名']];
const ALPN = ['alpn', 'ALPN(逗号分隔,如 h3,h2)'];
const FIELDS_BY_TYPE = {
  hysteria2: [...COMMON, ['password', '密码'], ['sni', 'SNI'], ['ports', '端口跳跃(如 443-9000)'],
    ['obfs', '混淆(salamander/空)'], ['obfs_password', '混淆密码'], ['up', '上行(留空默认)'], ['down', '下行(留空默认)'],
    ALPN, ['fingerprint', '证书指纹(64位hex)'], ['pin_sha256', '公钥固定 pinSHA256(仅记录·mihomo 不强制)']],
  vless: [...COMMON, ['uuid', 'UUID'], ['sni', 'SNI'], ['flow', 'flow'], ['client_fingerprint', '指纹(chrome..)'],
    ['reality_pbk', 'reality 公钥'], ['reality_sid', 'reality shortId'], ALPN, ...NET],
  vmess: [...COMMON, ['uuid', 'UUID'], ['alter_id', 'alterId', 'number'], ['cipher', '加密(auto..)'], ['sni', 'SNI'], ALPN, ...NET],
  trojan: [...COMMON, ['password', '密码'], ['sni', 'SNI'], ['client_fingerprint', '指纹'], ALPN, ...NET],
  ss: [...COMMON, ['cipher', '加密方式'], ['password', '密码']],
  tuic: [...COMMON, ['uuid', 'UUID'], ['password', '密码'], ['sni', 'SNI'], ALPN, ['congestion', '拥塞控制(bbr)'], ['udp_relay_mode', 'UDP中继(native)']],
  http: [...COMMON, ['username', '用户名(可空)'], ['password', '密码(可空)'], ['sni', 'SNI(可空)']],
  socks5: [...COMMON, ['username', '用户名(可空)'], ['password', '密码(可空)']],
};
const TLS_TYPES = ['vless', 'vmess', 'trojan', 'http', 'socks5'];
const CHAIN_TYPES = ['http', 'socks5'];
const UDP_TYPES = ['vless', 'vmess', 'trojan', 'ss', 'socks5'];   // hy2/tuic 是 UDP 原生协议，无此开关
function editNode(id) {
  const n = STATE.nodes.find(x => x.id === id); if (!n) return;
  const type = n.type || 'hysteria2';
  const fields = (FIELDS_BY_TYPE[type] || FIELDS_BY_TYPE.hysteria2).map(([k, label, t]) =>
    `<label>${label}<input data-k="${k}" type="${t || 'text'}" value="${esc(n[k] != null ? n[k] : '')}"></label>`).join('');
  const tlsBox = TLS_TYPES.includes(type) ? `<label class="row"><input id="ed-tls" type="checkbox" ${n.tls ? 'checked' : ''}> 启用 TLS</label>` : '';
  const udpBox = UDP_TYPES.includes(type) ? `<label class="row"><input id="ed-udp" type="checkbox" ${n.udp !== false ? 'checked' : ''}> 启用 UDP 中继（关掉则该节点只转 TCP；全局“强制 TCP”会覆盖此项）</label>` : '';
  const fopenBox = type === 'hysteria2' ? `<label class="row"><input id="ed-fopen" type="checkbox" ${n.fast_open ? 'checked' : ''}> fast-open</label>` : '';
  const chainBox = CHAIN_TYPES.includes(type)
    ? `<label>前置代理（必选 · 国内可达的中继节点）<select id="ed-front">${frontOptions(id, n.dialer_proxy)}</select></label>`
    : '';
  el('modal-card').innerHTML = `
    <h3>编辑节点 <span class="muted small">${esc(type.toUpperCase())}</span></h3>
    <div class="grid">${fields}</div>
    <label class="row"><input id="ed-skip" type="checkbox" ${n.skip_cert_verify ? 'checked' : ''}> 跳过证书校验 (insecure)</label>
    ${tlsBox}${udpBox}${fopenBox}${chainBox}
    <div class="modal-actions">
      <button class="btn" onclick="closeModal()">取消</button>
      <button class="btn primary" onclick="saveNode('${id}')">保存</button>
    </div>`;
  el('modal').classList.remove('hidden');
}
const SUPPORTED_NET = ['', 'tcp', 'ws', 'grpc', 'httpupgrade'];
async function saveNode(id) {
  const patch = {};
  const inputs = [...el('modal-card').querySelectorAll('input[data-k]')];
  // 传输类型只支持这些；h2/http/quic 写进去会被静默当 tcp 连而失败，提前拦下并提示
  const netI = inputs.find(i => i.dataset.k === 'network');
  if (netI && !SUPPORTED_NET.includes(netI.value.trim().toLowerCase())) {
    toast('传输只支持 tcp/ws/grpc/httpupgrade', 'err'); return;
  }
  inputs.forEach(i => {
    const k = i.dataset.k;
    const v = i.value;
    if (k === 'port' || k === 'alter_id') { patch[k] = parseInt(v) || (k === 'port' ? 443 : 0); return; }
    if (k === 'alpn') { patch.alpn = v.split(',').map(x => x.trim()).filter(Boolean); return; }
    // 表单内渲染的字段一律回写（含空串），让用户能清空某字段；服务端各 builder 对空值有兜底
    patch[k] = v;
  });
  patch.skip_cert_verify = el('ed-skip').checked;
  if (el('ed-tls')) patch.tls = el('ed-tls').checked;
  if (el('ed-udp')) patch.udp = el('ed-udp').checked;
  if (el('ed-fopen')) patch.fast_open = el('ed-fopen').checked;
  if (el('ed-front')) {
    if (!el('ed-front').value) { toast('链式出口必须选择前置代理', 'err'); return; }
    patch.dialer_proxy = el('ed-front').value;
  }
  const r = await api('PUT', '/api/nodes/' + id, patch);
  closeModal(); await loadState();
  done(r, '已保存，记得“应用配置”');
}
function closeModal() { el('modal').classList.add('hidden'); }

// 拖动排序
let dragId = null;
function enableDragOrder() {
  el('node-list').querySelectorAll('.node').forEach(row => {
    row.addEventListener('dragstart', () => { dragId = row.dataset.id; });
    row.addEventListener('dragover', e => e.preventDefault());
    row.addEventListener('drop', async e => {
      e.preventDefault();
      const ids = STATE.nodes.map(n => n.id);
      const from = ids.indexOf(dragId), to = ids.indexOf(row.dataset.id);
      if (from < 0 || to < 0 || from === to) return;
      ids.splice(to, 0, ids.splice(from, 1)[0]);
      STATE.nodes.sort((a, b) => ids.indexOf(a.id) - ids.indexOf(b.id));
      renderNodes();
      const r = await api('POST', '/api/nodes/order', { order: ids });
      if (!r.ok) { toast('排序保存失败', 'err'); await loadState(); }   // 失败回滚（FRONT-1）
    });
  });
}

// ----------------------------------------------------------------- 路由规则
const RULE_TYPES = [['auto', '自动判别'], ['domain-suffix', '域名后缀'], ['domain', '精确域名'],
  ['domain-keyword', '关键词'], ['domain-wildcard', '通配符'], ['ip-cidr', 'IP段'], ['geoip', 'GEOIP'],
  ['geosite', 'GEOSITE'], ['process-name', '进程名']];

// 与服务端 config_gen.classify_rule 保持一致，确保“生成规则”预览即最终结果
// 前导零（如 010.0.0.1）被 Python ipaddress 视为非法，前端也一并拒绝以对齐判别
// 校验 IPv4(/掩码)：4 段 0-255、无前导零；掩码 0-32。与 Python ipaddress 边界对齐
function isIPv4(v) {
  const parts = v.split('/'); if (parts.length > 2) return false;
  const p = parts[0].split('.');
  if (!(p.length === 4 && p.every(o => /^\d+$/.test(o) && +o <= 255 && (o === '0' || o[0] !== '0')))) return false;
  return parts[1] === undefined || (/^\d+$/.test(parts[1]) && +parts[1] <= 32);
}
// 校验 IPv6(/掩码)：最多一个 '::'，否则需正好 8 段；掩码 0-128。拒绝 dead:beef 这类不完整地址
function isIPv6(v) {
  const parts = v.split('/'); if (parts.length > 2) return false;
  if (parts[1] !== undefined && !(/^\d+$/.test(parts[1]) && +parts[1] <= 128)) return false;
  const h = parts[0];
  // 允许 '.'：覆盖 IPv4-mapped/嵌入式 IPv6（如 ::ffff:1.2.3.4），与服务端 ipaddress 一致
  if (!h.includes(':') || !/^[0-9a-fA-F:.]+$/.test(h)) return false;
  if (h.split('::').length > 2) return false;
  // DC-8：每个 hextet 必须是 1-4 位十六进制；嵌入式 IPv4 只允许出现在最后一段。
  // 否则 12345::1 / 1.2.3.4.5::1 这类会被前端判为合法、预览成 IP-CIDR，但服务端 ipaddress 拒绝、整条规则被悄悄丢弃。
  const segs = h.split(':');
  for (let i = 0; i < segs.length; i++) {
    const s = segs[i];
    if (s === '') continue;                       // '::' 产生的空段
    if (s.includes('.')) { if (i !== segs.length - 1 || !isIPv4(s)) return false; }
    else if (!/^[0-9a-fA-F]{1,4}$/.test(s)) return false;
  }
  // 嵌入式 IPv4 段计 2 个 hextet：完整形式 0:0:0:0:0:ffff:1.2.3.4 共 8 个 hextet（与服务端 ipaddress 一致，
  // 不再因无 '::' 的内嵌 IPv4 形式被前端误判为非法）
  const hextets = segs.reduce((n, s) => n + (s === '' ? 0 : (s.includes('.') ? 2 : 1)), 0);
  return h.includes('::') ? hextets <= 7 : hextets === 8;
}
function classifyRule(value, rtype) {
  value = (value || '').trim(); rtype = (rtype || 'auto').toLowerCase();
  const mb = value.match(/^\[([0-9a-fA-F:]+)\](\/\d+)?$/);   // 先剥 [..] IPv6 字面量（与服务端一致）
  if (mb) value = mb[1] + (mb[2] || '');
  if (value.includes('%')) {                                 // 去 IPv6 zone-id（%eth0）——仅当剥后确为 IP 才剥，
    const z = value.replace(/%[^/]+/, '');                   // 与服务端 classify_rule 一致，避免误伤含 '%' 的域名/关键词
    if (isIPv4(z) || isIPv6(z)) value = z;
  }
  const map = { domain: 'DOMAIN', 'domain-suffix': 'DOMAIN-SUFFIX', suffix: 'DOMAIN-SUFFIX', 'domain-keyword': 'DOMAIN-KEYWORD', keyword: 'DOMAIN-KEYWORD', 'domain-wildcard': 'DOMAIN-WILDCARD', wildcard: 'DOMAIN-WILDCARD', 'ip-cidr': 'IP-CIDR', ip: 'IP-CIDR', geoip: 'GEOIP', geosite: 'GEOSITE', 'process-name': 'PROCESS-NAME' };
  if (rtype !== 'auto' && map[rtype]) {       // 已知显式类型
    let kind = map[rtype];
    if (kind === 'IP-CIDR') {
      // 显式 IP 但取值非法：服务端会直接丢弃该规则，预览如实提示而非伪装成有效 IP-CIDR
      if (!(isIPv4(value) || isIPv6(value))) return ['(非法 IP/CIDR · 会被忽略)', value];
      if (!value.includes('/')) value += isIPv6(value) ? '/128' : '/32';
    }
    return [kind, value];
  }
  // auto（未知显式类型也回退到此，和服务端一致）
  if (isIPv4(value) || isIPv6(value)) { if (!value.includes('/')) value += isIPv6(value) ? '/128' : '/32'; return ['IP-CIDR', value]; }
  // 与服务端 classify_rule 对齐（STYLE-1）：*.cn -> DOMAIN-SUFFIX,cn；剥前缀后为空(*.)或仍含通配(*.*) -> 通配字面量
  if (value.startsWith('*.')) {
    const sub = value.slice(2);
    if (sub && !sub.includes('*') && !sub.includes('?')) return ['DOMAIN-SUFFIX', sub];
    return ['DOMAIN-WILDCARD', value];
  }
  if (value.includes('*') || value.includes('?')) return ['DOMAIN-WILDCARD', value];
  if (value.startsWith('.')) { const sub = value.slice(1); return sub ? ['DOMAIN-SUFFIX', sub] : ['(空值·会被忽略)', value]; }
  if (!value) return ['(空值·会被忽略)', value];
  if (value.includes('.')) return ['DOMAIN-SUFFIX', value];
  return ['DOMAIN-KEYWORD', value];
}
function genRule(r) {
  if (!(r.value || '').trim()) return '';
  const [kind, val] = classifyRule(r.value, r.type);
  if (kind.startsWith('(')) return kind;        // 标记类（非法 IP / 空值·会被忽略）直接显示，不拼成假规则
  const nosuf = kind === 'IP-CIDR' ? ',no-resolve' : '';
  // 指定节点（高级分流：该域名走某节点，如住宅/前置）。前端预览用原始 name；
  // 实际配置用去重后的显示名（重名时可能略有不同，以"预览生成的配置"为准）。
  if ((r.policy || '').toUpperCase() === 'NODE' || r.node) {
    const n = (STATE.nodes || []).find(x => x.id === r.node);
    return n ? `${kind},${val},${n.name}${nosuf}` : `${kind},${val},(节点缺失·会被忽略)${nosuf}`;
  }
  const policy = (r.policy || 'PROXY').toUpperCase();
  return `${kind},${val},${policy}${nosuf}`;
}

function nodeLabel(n) {
  const chain = n.dialer_proxy ? ' · 链式' : '';
  return (n.name || n.id) + ' (' + (n.type || 'hy2').toUpperCase() + chain + ')';
}
function nodeTargetOptions(selectedId) {
  if (!(STATE.nodes || []).length) return '<option value="">（请先添加节点）</option>';
  return '<option value="">— 选择节点 —</option>' +
    STATE.nodes.map(n => `<option value="${esc(n.id)}" ${n.id === selectedId ? 'selected' : ''}>${esc(nodeLabel(n))}</option>`).join('');
}
function ruleRowHtml(r, i) {
  const typeOpts = RULE_TYPES.map(([v, t]) => `<option value="${v}" ${r.type === v ? 'selected' : ''}>${t}</option>`).join('');
  const policy = (r.policy || 'PROXY').toUpperCase();
  const isNode = policy === 'NODE';
  const gen = genRule(r);
  return `<div class="rule-row" data-i="${i}">
    <input value="${esc(r.value)}" oninput="ruleEdited(${i},'value',this.value)" placeholder="*.cn / github.com / 1.2.3.0/24">
    <select onchange="ruleEdited(${i},'type',this.value)">${typeOpts}</select>
    <select onchange="ruleEdited(${i},'policy',this.value)">
      <option value="PROXY" ${policy === 'PROXY' ? 'selected' : ''}>代理</option>
      <option value="DIRECT" ${policy === 'DIRECT' ? 'selected' : ''}>直连</option>
      <option value="REJECT" ${policy === 'REJECT' ? 'selected' : ''}>拦截</option>
      <option value="NODE" ${isNode ? 'selected' : ''}>指定节点</option>
    </select>
    ${isNode ? `<select onchange="ruleEdited(${i},'node',this.value)" title="该域名走此节点（链式节点会自动经前置出网）">${nodeTargetOptions(r.node)}</select>` : ''}
    <span class="gen">${esc(gen)}</span>
    <button class="btn small danger" onclick="delRule(${i})">×</button>
  </div>`;
}
function renderRules() {
  el('rule-list').innerHTML = STATE.rules.map((r, i) => ruleRowHtml(r, i)).join('');
  el('final-policy').value = (STATE.settings.final || 'PROXY');
  renderPresets();
}
function renderPresets() {
  const box = el('preset-list'); if (!box) return;
  const on = new Set((STATE.settings || {}).presets || []);
  box.innerHTML = (STATE.preset_catalog || []).map(p =>
    `<label class="row" title="${esc(p.desc)}"><input type="checkbox" class="preset-cb" value="${esc(p.key)}" onchange="presetChanged()" ${on.has(p.key) ? 'checked' : ''}> ${esc(p.name)}</label>`).join('');
}
// 勾选预设即标记“未保存”并同步进 STATE，避免后续 loadState 把勾选覆盖丢失
function presetChanged() {
  rulesDirty = true;
  if (!STATE.settings) STATE.settings = {};
  STATE.settings.presets = [...document.querySelectorAll('.preset-cb:checked')].map(c => c.value);
}
// 兜底策略改动也纳入 dirty 保护，避免后台 loadState 静默丢弃未保存的 final
function finalChanged() {
  rulesDirty = true;
  if (!STATE.settings) STATE.settings = {};
  STATE.settings.final = el('final-policy').value;
}
function ruleEdited(i, key, val) {
  STATE.rules[i][key] = val;
  rulesDirty = true;
  if (key === 'policy') {
    // 切到/离开“指定节点”要增删节点下拉，整行重渲染（下拉切换不涉及文本输入焦点）
    if ((val || '').toUpperCase() === 'NODE' && !STATE.rules[i].node) STATE.rules[i].node = '';
    renderRules();
    return;
  }
  // 仅刷新该行的“生成规则”预览，避免输入时文本输入框丢焦
  const row = el('rule-list').querySelector(`.rule-row[data-i="${i}"] .gen`);
  if (row) row.textContent = genRule(STATE.rules[i]);
}
function addRuleRow() { STATE.rules.push({ value: '', type: 'auto', policy: 'PROXY' }); rulesDirty = true; renderRules(); }
function delRule(i) { STATE.rules.splice(i, 1); rulesDirty = true; renderRules(); }
async function saveRules() {
  const rules = STATE.rules.filter(r => (r.value || '').trim()).map(r => {
    const out = { value: r.value, type: r.type || 'auto', policy: (r.policy || 'PROXY') };
    // 指定节点：带有效 node id 才下发；空/缺则回落 policy（服务端 rule_to_mihomo 也以 node 为准）
    if ((r.policy || '').toUpperCase() === 'NODE' && r.node) out.node = r.node;
    return out;
  });
  const presets = [...document.querySelectorAll('.preset-cb:checked')].map(c => c.value);
  const r1 = await api('PUT', '/api/rules', { rules });
  const r2 = await api('PUT', '/api/settings', { settings: { final: el('final-policy').value, presets } });
  if (r1.ok && r2.ok) { rulesDirty = false; STATE.settings.presets = presets; toast('路由已保存，记得“应用配置”', 'ok'); }
  else toast('保存失败：' + ((r1.error || r2.error) || ''), 'err');
}

// ----------------------------------------------------------------- 设置
function renderSettings() {
  const s = STATE.settings;
  el('set-up').value = parseInt(s.default_up) || 20;
  el('set-down').value = parseInt(s.default_down) || 100;
  el('set-port').value = s.mixed_port || 7890;
  el('set-autointerval').value = s.auto_interval || 300;
  el('set-autotol').value = s.auto_tolerance || 50;
  el('set-keepalive').value = (s.keep_alive_interval ?? 30);
  el('set-tcpconc').checked = s.tcp_concurrent !== false;
  el('set-mux').checked = !!s.mux_enabled;
  el('set-noudp').checked = !!s.disable_proxy_udp;
  el('set-stack').value = s.tun_stack || 'system';
  el('set-log').value = s.log_level || 'warning';
  el('set-ipv6').checked = !!s.ipv6;
  el('set-gateway').checked = !!s.gateway_mode;
  if (el('gw-ip')) el('gw-ip').textContent = location.hostname || '树莓派IP';
  if (el('gw-port')) el('gw-port').textContent = s.mixed_port || 7890;
  el('set-fakeip').value = s.fake_ip_range || '198.18.0.1/16';
  el('set-dns').value = (s.dns_nameservers || []).join('\n');
  el('set-dnscn').value = (s.dns_china || []).join('\n');
  if (el('set-hijack')) el('set-hijack').value = (s.tun_dns_hijack || []).join('\n');     // FEAT-1
  if (el('set-autoredirect')) el('set-autoredirect').checked = s.tun_auto_redirect !== false;
  if (el('set-respectrules')) el('set-respectrules').checked = !!s.dns_respect_rules;
  el('set-mirror').value = s.github_mirror || '';
  el('set-ctrl').value = s.external_controller || '';
  if (el('set-webhook')) el('set-webhook').value = s.webhook_url || '';
  el('web-port').value = (STATE.webui || {}).port || 8088;
  el('web-bind').value = (STATE.webui || {}).bind || '0.0.0.0';
  el('web-pw').value = '';
  if (el('web-pw-clear')) el('web-pw-clear').checked = false;   // FRONT-3：渲染时复位“取消密码”勾选，避免粘连误清密码
  const hint = el('web-pw-hint');
  if (hint) hint.textContent = (STATE.webui || {}).has_password ? '当前已设密码' : '当前未设密码（仅本机可访问）';
}
async function saveSettings() {
  const lines = v => v.split('\n').map(x => x.trim()).filter(Boolean);
  const settings = {
    default_up: (parseInt(el('set-up').value) || 20) + ' Mbps',
    default_down: (parseInt(el('set-down').value) || 100) + ' Mbps',
    mixed_port: parseInt(el('set-port').value) || 7890,
    auto_interval: parseInt(el('set-autointerval').value) || 300,
    auto_tolerance: parseInt(el('set-autotol').value) || 50,
    keep_alive_interval: parseInt(el('set-keepalive').value) || 0,
    tcp_concurrent: el('set-tcpconc').checked,
    mux_enabled: el('set-mux').checked,
    disable_proxy_udp: el('set-noudp').checked,
    tun_stack: el('set-stack').value,
    log_level: el('set-log').value,
    ipv6: el('set-ipv6').checked,
    gateway_mode: el('set-gateway').checked,
    fake_ip_range: el('set-fakeip').value.trim(),
    dns_nameservers: lines(el('set-dns').value),
    dns_china: lines(el('set-dnscn').value),
    // FEAT-1：TUN DNS 劫持目标与 nftables auto-redirect 现可在面板改（清空 hijack=不劫持，与 Pi-hole 共存）
    tun_dns_hijack: el('set-hijack') ? lines(el('set-hijack').value) : (STATE.settings.tun_dns_hijack || ['any:53']),
    tun_auto_redirect: el('set-autoredirect') ? el('set-autoredirect').checked : true,
    dns_respect_rules: el('set-respectrules') ? el('set-respectrules').checked : false,
    github_mirror: el('set-mirror').value.trim(),
    external_controller: el('set-ctrl').value.trim(),
    webhook_url: el('set-webhook') ? el('set-webhook').value.trim() : '',
  };
  const r = await api('PUT', '/api/settings', { settings });
  if (!done(r, '设置已保存，记得“应用配置”')) return;
  await loadState();
}
async function saveWebui() {
  const body = { port: parseInt(el('web-port').value) || 8088, bind: el('web-bind').value.trim() };
  const pw = el('web-pw').value;
  if (el('web-pw-clear').checked) body.password = '';   // 勾选=取消密码
  else if (pw !== '') body.password = pw;                // 否则非空才修改
  const r = await api('PUT', '/api/webui', body);
  if (done(r, '面板设置已保存（端口/地址改动需重启面板服务）')) { el('web-pw').value = ''; el('web-pw-clear').checked = false; await loadState(); }
}
async function logout() {
  await api('POST', '/api/logout').catch(() => {});
  TOKEN = ''; localStorage.removeItem('pihy2_token'); showLogin();
}

// ----------------------------------------------------------------- 工具
async function showConfig() {
  const r = await api('GET', '/api/config');
  const box = el('tools-out'); box.classList.remove('hidden'); box.textContent = r.config || r.error || '';
}
async function exportLinks() {
  const r = await api('GET', '/api/export');
  const box = el('tools-out'); box.classList.remove('hidden'); box.textContent = (r.links || []).join('\n') || '（无节点）';
}
// pihy2 自身系统日志（异常/错误追溯，区别于流量页的 mihomo journal）
async function showSysLogs() {
  const r = await api('GET', '/api/syslogs?n=300');
  const box = el('tools-out'); box.classList.remove('hidden');
  box.textContent = (r.logs || []).join('') || r.error || '（无日志）';
}
async function serviceAction(action) {
  if (action !== 'restart' && !confirm(`确定 ${action} mihomo 服务？`)) return;
  const r = await api('POST', '/api/service', { action });
  if (done(r, '已执行 ' + action)) setTimeout(refreshStatus, 1200);
}

// ----------------------------------------------------------------- 维护 / 自检 / 卸载（FEAT-2/3/4）
const ST_SYM = { ok: '✓', warn: '!', fail: '✗', skip: '–' };
async function runSelfTest() {
  const box = el('selftest-out'); box.classList.remove('hidden');
  box.innerHTML = '<div class="muted small">正在自检…（探测出口 IP 可能需要几秒）</div>';
  const r = await api('POST', '/api/selftest', { probe_ip: true });
  if (!r.ok || !r.result) { box.innerHTML = '<div class="err">自检失败：' + esc((r && (r.error || r.message)) || '请重试') + '</div>'; return; }
  const res = r.result, s = res.summary;
  const rows = (res.checks || []).map(c =>
    `<div class="st-row ${esc(c.status)}"><span class="st-dot">${ST_SYM[c.status] || '?'}</span>` +
    `<span class="st-label">${esc(c.label)}</span>` +
    `<span class="st-detail muted small">${esc(c.detail || '')}</span></div>`).join('');
  box.innerHTML = `<div class="st-summary">通过 ${s.ok} · 警告 ${s.warn} · 失败 ${s.fail} · 跳过 ${s.skip}</div>` + rows;
  toast(res.ok ? '自检通过' : '自检发现问题', res.ok ? 'ok' : 'err');
}
async function restoreDefaults() {
  if (!confirm('把“设置”恢复为出厂默认？\n会重置设置页各项与分流预设、兜底策略；不影响节点、订阅、路由规则与面板密码。\n恢复后需点“应用配置并重启”才生效。')) return;
  const r = await api('POST', '/api/restore-defaults');
  if (done(r, r.message || '已恢复默认设置')) await loadState();
}
// 完整状态备份/恢复（含节点凭据，妥善保管）
async function backupDownload() {
  const r = await fetch('/api/backup', {headers: {'X-Requested-With': 'pihy2', ...(TOKEN ? {Authorization: 'Bearer ' + TOKEN} : {})}});
  if (r.status === 401) { TOKEN = ''; localStorage.removeItem('pihy2_token'); showLogin(); return; }
  const blob = await r.blob();
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob); a.download = 'pihy2-backup.json'; a.click();
  URL.revokeObjectURL(a.href);
  toast('已下载备份', 'ok');
}
async function restoreUpload(e) {
  const file = e.target.files[0];
  if (!file) return;
  if (!confirm('确认用该备份覆盖当前状态？')) { e.target.value = ''; return; }
  let state;
  try { state = JSON.parse(await file.text()); }
  catch (_) { toast('备份文件不是合法 JSON', 'err'); e.target.value = ''; return; }
  const r = await api('POST', '/api/restore', { state });
  if (done(r, '已恢复，记得“应用配置并重启”')) await loadState();
  e.target.value = '';
}
async function doUninstall() {
  const purge = !!(el('uninstall-purge') && el('uninstall-purge').checked);
  const msg = purge
    ? '【高危】将卸载 pihy2，并删除二进制、配置与全部状态（节点 / 订阅 / 设置，不可恢复）。\n\n确定继续？'
    : '将卸载 pihy2（停止并移除 mihomo 与面板服务），保留 /etc/pihy2 状态以便重装。\n\n确定继续？';
  if (!confirm(msg)) return;
  if (purge && !confirm('再次确认：purge 会彻底删除所有节点 / 订阅 / 设置，且无法恢复。仍要继续？')) return;
  const r = await api('POST', '/api/uninstall', { confirm: true, purge: purge });
  if (!r || !r.ok) { toast('失败：' + ((r && (r.error || r.message)) || '请重试'), 'err'); return; }
  stopTraffic();
  // 卸载会停掉面板服务，本页面随即失联——直接替换为终态提示，避免后续请求一片红错
  el('app').innerHTML = '<div style="max-width:560px;margin:80px auto;text-align:center;line-height:1.7" class="muted">' +
    '<h2>pihy2 正在卸载</h2><p>卸载已在后台独立进程执行，本面板随即下线。</p><p>' +
    (purge ? '已选择 <b>purge</b>：二进制、配置与全部状态将一并删除。' : '已保留 <code>/etc/pihy2</code> 状态，可重装恢复。') +
    '</p><p class="small">如需确认结果，可在树莓派上运行 <code>systemctl status mihomo pihy2-web</code>。</p></div>';
}

// ----------------------------------------------------------------- 流量面板
function humanBytes(n) {
  n = n || 0; const u = ['B', 'KB', 'MB', 'GB', 'TB']; let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return (i === 0 ? n : n.toFixed(2)) + u[i];
}
let trafficTimer = null, prevTraffic = null;
async function pollTraffic() {
  const r = await api('GET', '/api/traffic').catch(() => ({}));
  if (!r.ok) return;
  const now = Date.now();
  if (!r.running) { el('traffic-hint').textContent = 'mihomo 未运行或 clash API 不可用。'; return; }
  el('traffic-hint').textContent = '数据每 2 秒刷新。';
  if (prevTraffic) {
    const dt = (now - prevTraffic.t) / 1000 || 1;
    // Math.max(0,…)：mihomo 重启后累计值归零，差值会变负，钳到 0 避免显示负速度
    el('sp-up').textContent = humanBytes(Math.max(0, r.up_total - prevTraffic.up) / dt);
    el('sp-down').textContent = humanBytes(Math.max(0, r.down_total - prevTraffic.down) / dt);
  }
  prevTraffic = { up: r.up_total, down: r.down_total, t: now };
  el('sp-count').textContent = r.count;
  el('sp-upt').textContent = humanBytes(r.up_total);
  el('sp-downt').textContent = humanBytes(r.down_total);
  el('conn-body').innerHTML = (r.conns || []).map(c => `<tr>
    <td>${esc(c.host || c.dest)}</td><td>${esc(c.rule || '')}${c.chain ? ' · ' + esc(c.chain) : ''}</td>
    <td>${esc(c.net)}</td><td>${humanBytes(c.up)}</td><td>${humanBytes(c.down)}</td></tr>`).join('')
    || '<tr><td colspan="5" class="muted">暂无活动连接</td></tr>';
}
function startTraffic() { stopTraffic(); prevTraffic = null; pollTraffic(); trafficTimer = setInterval(pollTraffic, 2000); }
function stopTraffic() { if (trafficTimer) { clearInterval(trafficTimer); trafficTimer = null; } }
async function refreshLogs() {
  const r = await api('GET', '/api/logs');
  el('log-box').textContent = (r.logs || r.error || '（无）');
}
async function closeAllConns() {
  if (!confirm('断开当前全部连接？')) return;
  const r = await api('POST', '/api/connections/close');
  done(r, '已断开'); pollTraffic();
}

// 离开页面时若有未保存的路由修改则提醒
window.addEventListener('beforeunload', (e) => {
  if (rulesDirty) { e.preventDefault(); e.returnValue = ''; }
});

window.addEventListener('DOMContentLoaded', boot);
