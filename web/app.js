'use strict';

// ----------------------------------------------------------------- 基础
let TOKEN = localStorage.getItem('pihy2_token') || '';
let STATE = { nodes: [], rules: [], settings: {}, webui: {}, active: '' };
let DELAYS = {};
let rulesDirty = false;          // 路由有未保存修改时为 true
let toastTimer = null;

async function api(method, path, body) {
  const opt = { method, headers: {} };
  if (TOKEN) opt.headers['Authorization'] = 'Bearer ' + TOKEN;
  if (body !== undefined) { opt.headers['Content-Type'] = 'application/json'; opt.body = JSON.stringify(body); }
  const r = await fetch(path, opt);
  if (r.status === 401) {           // token 失效/服务端重启：清掉并回到登录
    TOKEN = ''; localStorage.removeItem('pihy2_token'); showLogin();
    throw new Error('未登录');
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
  const r = await fetch('/api/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ password: pw }) }).then(r => r.json()).catch(() => ({}));
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
        <div class="muted small">节点 ${s.count || 0} · 更新于 ${esc(s.updated || '从未')}</div></div>
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
  if (r.ok) { el('sub-url').value = ''; el('sub-name').value = ''; await loadState(); toast(`订阅已添加，${r.count || 0} 个节点已生效`, 'ok'); }
  else toast('添加失败：' + (r.error || ''), 'err');
}
async function updateSub(id) {
  toast('更新中…');
  const r = await api('POST', '/api/subs/update', { id });
  await loadState(); done(r, `已更新 ${r.count || 0} 个节点并生效`);
}
async function updateAllSubs() {
  if (!(STATE.subscriptions || []).length) { toast('没有订阅', 'err'); return; }
  toast('更新中…');
  const r = await api('POST', '/api/subs/update', { id: 'all' });
  await loadState(); done(r, `已更新共 ${r.count || 0} 个节点并生效`);
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
  done(r, '已保存（下次部署/重装生效；也可改 systemd timer）');
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
  if (!r.ok) toast('排序保存失败', 'err');
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
  if (!confirm(`删除节点「${n ? n.name : id}」？`)) return;
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
  toast(`已添加 ${(r.added || []).length} 个节点${errs ? `（${errs} 行无法解析）` : ''}，记得“应用配置”`, 'ok');
}

// 编辑节点：按协议显示对应字段
const COMMON = [['name', '名称'], ['server', '服务器'], ['port', '端口', 'number']];
const NET = [['network', '传输(tcp/ws/grpc)'], ['ws_path', 'ws 路径'], ['ws_host', 'ws Host'], ['grpc_service_name', 'grpc 服务名']];
const ALPN = ['alpn', 'ALPN(逗号分隔,如 h3,h2)'];
const FIELDS_BY_TYPE = {
  hysteria2: [...COMMON, ['password', '密码'], ['sni', 'SNI'], ['ports', '端口跳跃(如 443-9000)'],
    ['obfs', '混淆(salamander/空)'], ['obfs_password', '混淆密码'], ['up', '上行(留空默认)'], ['down', '下行(留空默认)'],
    ALPN, ['fingerprint', '证书指纹(64位hex)'], ['pin_sha256', '公钥固定 pinSHA256(可空)']],
  vless: [...COMMON, ['uuid', 'UUID'], ['sni', 'SNI'], ['flow', 'flow'], ['client_fingerprint', '指纹(chrome..)'],
    ['reality_pbk', 'reality 公钥'], ['reality_sid', 'reality shortId'], ALPN, ...NET],
  vmess: [...COMMON, ['uuid', 'UUID'], ['alter_id', 'alterId', 'number'], ['cipher', '加密(auto..)'], ['sni', 'SNI'], ALPN, ...NET],
  trojan: [...COMMON, ['password', '密码'], ['sni', 'SNI'], ['client_fingerprint', '指纹'], ALPN, ...NET],
  ss: [...COMMON, ['cipher', '加密方式'], ['password', '密码']],
  tuic: [...COMMON, ['uuid', 'UUID'], ['password', '密码'], ['sni', 'SNI'], ALPN, ['congestion', '拥塞控制(bbr)'], ['udp_relay_mode', 'UDP中继(native)']],
};
const TLS_TYPES = ['vless', 'vmess', 'trojan'];
function editNode(id) {
  const n = STATE.nodes.find(x => x.id === id); if (!n) return;
  const type = n.type || 'hysteria2';
  const fields = (FIELDS_BY_TYPE[type] || FIELDS_BY_TYPE.hysteria2).map(([k, label, t]) =>
    `<label>${label}<input data-k="${k}" type="${t || 'text'}" value="${esc(n[k] != null ? n[k] : '')}"></label>`).join('');
  const tlsBox = TLS_TYPES.includes(type) ? `<label class="row"><input id="ed-tls" type="checkbox" ${n.tls ? 'checked' : ''}> 启用 TLS</label>` : '';
  const fopenBox = type === 'hysteria2' ? `<label class="row"><input id="ed-fopen" type="checkbox" ${n.fast_open ? 'checked' : ''}> fast-open</label>` : '';
  el('modal-card').innerHTML = `
    <h3>编辑节点 <span class="muted small">${esc(type.toUpperCase())}</span></h3>
    <div class="grid">${fields}</div>
    <label class="row"><input id="ed-skip" type="checkbox" ${n.skip_cert_verify ? 'checked' : ''}> 跳过证书校验 (insecure)</label>
    ${tlsBox}${fopenBox}
    <div class="modal-actions">
      <button class="btn" onclick="closeModal()">取消</button>
      <button class="btn primary" onclick="saveNode('${id}')">保存</button>
    </div>`;
  el('modal').classList.remove('hidden');
}
async function saveNode(id) {
  const patch = {};
  el('modal-card').querySelectorAll('input[data-k]').forEach(i => {
    const k = i.dataset.k;
    const v = i.value;
    if (k === 'port' || k === 'alter_id') { patch[k] = parseInt(v) || (k === 'port' ? 443 : 0); return; }
    if (k === 'alpn') { const arr = v.split(',').map(x => x.trim()).filter(Boolean); if (arr.length) patch.alpn = arr; return; }
    if (v !== '') patch[k] = v;     // 空串不回写，避免把没填的字段污染成 ""（保留原值/类型）
  });
  patch.skip_cert_verify = el('ed-skip').checked;
  if (el('ed-tls')) patch.tls = el('ed-tls').checked;
  if (el('ed-fopen')) patch.fast_open = el('ed-fopen').checked;
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
      await api('POST', '/api/nodes/order', { order: ids });
    });
  });
}

// ----------------------------------------------------------------- 路由规则
const RULE_TYPES = [['auto', '自动判别'], ['domain-suffix', '域名后缀'], ['domain', '精确域名'],
  ['domain-keyword', '关键词'], ['domain-wildcard', '通配符'], ['ip-cidr', 'IP段'], ['geoip', 'GEOIP'], ['geosite', 'GEOSITE']];

// 与服务端 config_gen.classify_rule 保持一致，确保“生成规则”预览即最终结果
// 前导零（如 010.0.0.1）被 Python ipaddress 视为非法，前端也一并拒绝以对齐判别
function isIPv4(v) { const p = v.split('/')[0].split('.'); return p.length === 4 && p.every(o => /^\d+$/.test(o) && +o <= 255 && (o === '0' || o[0] !== '0')); }
function isIPv6(v) { const h = v.split('/')[0]; return h.includes(':') && /^[0-9a-fA-F:]+$/.test(h); }
function classifyRule(value, rtype) {
  value = (value || '').trim(); rtype = (rtype || 'auto').toLowerCase();
  const map = { domain: 'DOMAIN', 'domain-suffix': 'DOMAIN-SUFFIX', suffix: 'DOMAIN-SUFFIX', 'domain-keyword': 'DOMAIN-KEYWORD', keyword: 'DOMAIN-KEYWORD', 'domain-wildcard': 'DOMAIN-WILDCARD', wildcard: 'DOMAIN-WILDCARD', 'ip-cidr': 'IP-CIDR', ip: 'IP-CIDR', geoip: 'GEOIP', geosite: 'GEOSITE', 'process-name': 'PROCESS-NAME' };
  if (rtype !== 'auto' && map[rtype]) {       // 已知显式类型
    let kind = map[rtype];
    // 仅在确为合法 IP 时补 /32//128，与服务端一致（服务端对非法显式 IP 会丢弃该规则）
    if (kind === 'IP-CIDR' && !value.includes('/') && (isIPv4(value) || isIPv6(value)))
      value += isIPv6(value) ? '/128' : '/32';
    return [kind, value];
  }
  // auto（未知显式类型也回退到此，和服务端一致）
  if (isIPv4(value) || isIPv6(value)) { if (!value.includes('/')) value += isIPv6(value) ? '/128' : '/32'; return ['IP-CIDR', value]; }
  if (value.startsWith('*.')) return ['DOMAIN-SUFFIX', value.slice(2)];
  if (value.includes('*') || value.includes('?')) return ['DOMAIN-WILDCARD', value];
  if (value.startsWith('.')) return ['DOMAIN-SUFFIX', value.slice(1)];
  if (value.includes('.')) return ['DOMAIN-SUFFIX', value];
  return ['DOMAIN-KEYWORD', value];
}
function genRule(r) {
  if (!(r.value || '').trim()) return '';
  const [kind, val] = classifyRule(r.value, r.type);
  const policy = (r.policy || 'PROXY').toUpperCase();
  return `${kind},${val},${policy}${kind === 'IP-CIDR' ? ',no-resolve' : ''}`;
}

function ruleRowHtml(r, i) {
  const typeOpts = RULE_TYPES.map(([v, t]) => `<option value="${v}" ${r.type === v ? 'selected' : ''}>${t}</option>`).join('');
  const policy = (r.policy || 'PROXY').toUpperCase();
  const gen = genRule(r);
  return `<div class="rule-row" data-i="${i}">
    <input value="${esc(r.value)}" oninput="ruleEdited(${i},'value',this.value)" placeholder="*.cn / github.com / 1.2.3.0/24">
    <select onchange="ruleEdited(${i},'type',this.value)">${typeOpts}</select>
    <select onchange="ruleEdited(${i},'policy',this.value)">
      <option value="PROXY" ${policy === 'PROXY' ? 'selected' : ''}>代理</option>
      <option value="DIRECT" ${policy === 'DIRECT' ? 'selected' : ''}>直连</option>
      <option value="REJECT" ${policy === 'REJECT' ? 'selected' : ''}>拦截</option>
    </select>
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
  // 仅刷新该行的“生成规则”预览，避免输入时光标丢失
  const row = el('rule-list').querySelector(`.rule-row[data-i="${i}"] .gen`);
  if (row) row.textContent = genRule(STATE.rules[i]);
}
function addRuleRow() { STATE.rules.push({ value: '', type: 'auto', policy: 'PROXY' }); rulesDirty = true; renderRules(); }
function delRule(i) { STATE.rules.splice(i, 1); rulesDirty = true; renderRules(); }
async function saveRules() {
  const rules = STATE.rules.filter(r => (r.value || '').trim());
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
  el('set-stack').value = s.tun_stack || 'system';
  el('set-log').value = s.log_level || 'warning';
  el('set-ipv6').checked = !!s.ipv6;
  el('set-gateway').checked = !!s.gateway_mode;
  if (el('gw-ip')) el('gw-ip').textContent = location.hostname || '树莓派IP';
  if (el('gw-port')) el('gw-port').textContent = s.mixed_port || 7890;
  el('set-fakeip').value = s.fake_ip_range || '198.18.0.1/16';
  el('set-dns').value = (s.dns_nameservers || []).join('\n');
  el('set-dnscn').value = (s.dns_china || []).join('\n');
  el('set-mirror').value = s.github_mirror || '';
  el('set-ctrl').value = s.external_controller || '';
  el('web-port').value = (STATE.webui || {}).port || 8088;
  el('web-bind').value = (STATE.webui || {}).bind || '0.0.0.0';
  el('web-pw').value = '';
  const hint = el('web-pw-hint');
  if (hint) hint.textContent = (STATE.webui || {}).has_password ? '当前已设密码' : '当前未设密码（仅本机可访问）';
}
async function saveSettings() {
  const lines = v => v.split('\n').map(x => x.trim()).filter(Boolean);
  const settings = {
    default_up: el('set-up').value + ' Mbps',
    default_down: el('set-down').value + ' Mbps',
    mixed_port: parseInt(el('set-port').value) || 7890,
    tun_stack: el('set-stack').value,
    log_level: el('set-log').value,
    ipv6: el('set-ipv6').checked,
    gateway_mode: el('set-gateway').checked,
    fake_ip_range: el('set-fakeip').value.trim(),
    dns_nameservers: lines(el('set-dns').value),
    dns_china: lines(el('set-dnscn').value),
    github_mirror: el('set-mirror').value.trim(),
    external_controller: el('set-ctrl').value.trim(),
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
async function serviceAction(action) {
  if (action !== 'restart' && !confirm(`确定 ${action} mihomo 服务？`)) return;
  const r = await api('POST', '/api/service', { action });
  if (done(r, '已执行 ' + action)) setTimeout(refreshStatus, 1200);
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
