'use strict';

// ----------------------------------------------------------------- 基础
let TOKEN = localStorage.getItem('pihy2_token') || '';
let STATE = { nodes: [], rules: [], settings: {}, webui: {}, active: '' };
let DELAYS = {};

async function api(method, path, body) {
  const opt = { method, headers: {} };
  if (TOKEN) opt.headers['Authorization'] = 'Bearer ' + TOKEN;
  if (body !== undefined) { opt.headers['Content-Type'] = 'application/json'; opt.body = JSON.stringify(body); }
  const r = await fetch(path, opt);
  if (r.status === 401) { showLogin(); throw new Error('未登录'); }
  const data = await r.json().catch(() => ({}));
  return data;
}

function el(id) { return document.getElementById(id); }
function esc(s) { return String(s == null ? '' : s).replace(/[&<>"]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c])); }

function toast(msg, kind) {
  const t = el('toast');
  t.textContent = msg; t.className = 'toast ' + (kind || '');
  setTimeout(() => t.classList.add('hidden'), 2600);
}

// ----------------------------------------------------------------- 鉴权
async function boot() {
  const info = await fetch('/api/authinfo').then(r => r.json()).catch(() => ({ need_auth: false }));
  if (info.need_auth && !TOKEN) { showLogin(); return; }
  const ok = await loadState();
  if (ok) { showApp(); refreshStatus(); }
}
function showLogin() { el('login').classList.remove('hidden'); el('app').classList.add('hidden'); }
function showApp() { el('login').classList.add('hidden'); el('app').classList.remove('hidden'); }

async function doLogin(e) {
  e.preventDefault();
  const pw = el('login-pw').value;
  const r = await fetch('/api/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ password: pw }) }).then(r => r.json());
  if (r.ok) { TOKEN = r.token; localStorage.setItem('pihy2_token', TOKEN); await loadState(); showApp(); refreshStatus(); }
  else { el('login-err').textContent = r.error || '密码错误'; }
}

async function loadState() {
  const s = await api('GET', '/api/state');
  if (!s.ok) return false;
  STATE = s;
  renderNodes(); renderRules(); renderSettings();
  return true;
}

// ----------------------------------------------------------------- 标签页
function switchTab(name) {
  document.querySelectorAll('.tab').forEach(t => t.classList.toggle('active', t.dataset.tab === name));
  document.querySelectorAll('.tab-pane').forEach(p => p.classList.add('hidden'));
  el('tab-' + name).classList.remove('hidden');
}

// ----------------------------------------------------------------- 状态栏
async function refreshStatus() {
  const s = await api('GET', '/api/status');
  if (!s.ok) return;
  const m = el('st-mihomo');
  const running = s.mihomo.active === 'active';
  m.textContent = 'mihomo: ' + (running ? '运行中' : s.mihomo.active);
  m.className = 'pill ' + (running ? 'ok' : 'bad');
  el('st-ip').textContent = '出口IP: ' + (s.ip || '—');
}

async function applyConfig() {
  toast('正在校验并应用…');
  const r = await api('POST', '/api/apply');
  toast(r.message || (r.ok ? '已应用' : '失败'), r.ok ? 'ok' : 'err');
  if (r.ok) setTimeout(refreshStatus, 1500);
}

// ----------------------------------------------------------------- 节点
function delayClass(d) { return d == null ? '' : d <= 0 ? 'bad' : d < 300 ? 'good' : d < 800 ? 'mid' : 'bad'; }
function delayText(d) { return d == null ? '' : d <= 0 ? '超时' : d + 'ms'; }

function renderNodes() {
  el('node-count').textContent = `（${STATE.nodes.length}）`;
  const list = el('node-list');
  if (!STATE.nodes.length) { list.innerHTML = '<p class="muted">还没有节点，点击右上角“添加节点”，把 hy2 链接粘贴进去即可。</p>'; return; }
  list.innerHTML = STATE.nodes.map(n => {
    const active = n.id === STATE.active;
    const tags = [];
    if (n.obfs) tags.push('混淆:' + esc(n.obfs));
    if (n.ports) tags.push('端口跳跃:' + esc(n.ports));
    if (n.skip_cert_verify) tags.push('跳过证书校验');
    const d = DELAYS[n.id];
    return `<div class="node ${active ? 'active' : ''}" draggable="true" data-id="${n.id}">
      <div class="dot" title="设为当前出口" onclick="setActive('${n.id}')"></div>
      <div class="info">
        <div class="name">${esc(n.name)}</div>
        <div class="addr">${esc(n.server)}:${n.port}</div>
        ${tags.length ? `<div class="tags">${tags.map(t => `<span class="tag">${t}</span>`).join('')}</div>` : ''}
      </div>
      <div class="delay ${delayClass(d)}">${delayText(d)}</div>
      <button class="btn small" onclick="editNode('${n.id}')">编辑</button>
      <button class="btn small danger" onclick="deleteNode('${n.id}')">删除</button>
    </div>`;
  }).join('');
  enableDragOrder();
}

async function setActive(id) {
  const r = await api('POST', '/api/active', { id });
  STATE.active = id; renderNodes();
  if (r.live) toast('已切换当前节点（已生效）', 'ok');
  else toast('已选为当前节点，点“应用配置并重启”后生效', 'ok');
}

async function deleteNode(id) {
  const n = STATE.nodes.find(x => x.id === id);
  if (!confirm(`删除节点「${n ? n.name : id}」？`)) return;
  await api('DELETE', '/api/nodes/' + id);
  await loadState(); toast('已删除，记得“应用配置”', 'ok');
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
    <p class="muted small">粘贴一个或多个 hy2 链接（每行一个），或 base64 订阅内容。</p>
    <textarea id="add-text" rows="6" placeholder="hysteria2://...&#10;hy2://..."></textarea>
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
  (r.nodes || []).forEach(n => { html += `<div class="preview-node">✓ <b>${esc(n.name)}</b> — ${esc(n.server)}:${n.port}${n.obfs ? ' · 混淆' : ''}${n.skip_cert_verify ? ' · 跳过证书' : ''}</div>`; });
  (r.errors || []).forEach(e => { html += `<div class="preview-node" style="color:var(--warn)">${esc(e)}</div>`; });
  box.innerHTML = html || '<p class="muted">无结果</p>';
}
async function commitNodes() {
  const r = await api('POST', '/api/nodes', { text: el('add-text').value });
  closeModal();
  await loadState();
  toast(`已添加 ${(r.added || []).length} 个节点，记得“应用配置”`, 'ok');
}

// 编辑节点
const NODE_FIELDS = [
  ['name', '名称', 'text'], ['server', '服务器', 'text'], ['port', '端口', 'number'],
  ['password', '密码', 'text'], ['sni', 'SNI', 'text'], ['ports', '端口跳跃(如 443-9000)', 'text'],
  ['obfs', '混淆(salamander 或空)', 'text'], ['obfs_password', '混淆密码', 'text'],
  ['up', '上行(留空用默认)', 'text'], ['down', '下行(留空用默认)', 'text'],
  ['fingerprint', '证书指纹(pinSHA256)', 'text'],
];
function editNode(id) {
  const n = STATE.nodes.find(x => x.id === id); if (!n) return;
  const fields = NODE_FIELDS.map(([k, label, type]) =>
    `<label>${label}<input data-k="${k}" type="${type}" value="${esc(n[k] != null ? n[k] : '')}"></label>`).join('');
  el('modal-card').innerHTML = `
    <h3>编辑节点</h3>
    <div class="grid">${fields}</div>
    <label class="row"><input id="ed-skip" type="checkbox" ${n.skip_cert_verify ? 'checked' : ''}> 跳过证书校验 (insecure)</label>
    <label class="row"><input id="ed-fopen" type="checkbox" ${n.fast_open ? 'checked' : ''}> fast-open</label>
    <div class="modal-actions">
      <button class="btn" onclick="closeModal()">取消</button>
      <button class="btn primary" onclick="saveNode('${id}')">保存</button>
    </div>`;
  el('modal').classList.remove('hidden');
}
async function saveNode(id) {
  const patch = {};
  el('modal-card').querySelectorAll('input[data-k]').forEach(i => {
    let v = i.value;
    if (i.dataset.k === 'port') v = parseInt(v) || 443;
    patch[i.dataset.k] = v;
  });
  patch.skip_cert_verify = el('ed-skip').checked;
  patch.fast_open = el('ed-fopen').checked;
  await api('PUT', '/api/nodes/' + id, patch);
  closeModal(); await loadState(); toast('已保存，记得“应用配置”', 'ok');
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

function classifyRule(value, rtype) {
  value = (value || '').trim(); rtype = (rtype || 'auto').toLowerCase();
  const map = { domain: 'DOMAIN', 'domain-suffix': 'DOMAIN-SUFFIX', 'domain-keyword': 'DOMAIN-KEYWORD', 'domain-wildcard': 'DOMAIN-WILDCARD', 'ip-cidr': 'IP-CIDR', geoip: 'GEOIP', geosite: 'GEOSITE' };
  const isV4 = /^\d{1,3}(\.\d{1,3}){3}(\/\d+)?$/.test(value);
  const isV6 = value.includes(':');
  if (rtype !== 'auto') {
    let kind = map[rtype] || 'DOMAIN-SUFFIX';
    if (kind === 'IP-CIDR' && !value.includes('/')) value += isV6 ? '/128' : '/32';
    return [kind, value];
  }
  if (isV4 || isV6) { if (!value.includes('/')) value += isV6 ? '/128' : '/32'; return ['IP-CIDR', value]; }
  if (value.startsWith('*.')) return ['DOMAIN-SUFFIX', value.slice(2)];
  if (value.includes('*') || value.includes('?')) return ['DOMAIN-WILDCARD', value];
  if (value.startsWith('.')) return ['DOMAIN-SUFFIX', value.slice(1)];
  if (value.includes('.')) return ['DOMAIN-SUFFIX', value];
  return ['DOMAIN-KEYWORD', value];
}

function ruleRowHtml(r, i) {
  const typeOpts = RULE_TYPES.map(([v, t]) => `<option value="${v}" ${r.type === v ? 'selected' : ''}>${t}</option>`).join('');
  const [kind, val] = classifyRule(r.value, r.type);
  const policy = (r.policy || 'PROXY').toUpperCase();
  const gen = r.value ? `${kind},${val},${policy}` : '';
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
}
function ruleEdited(i, key, val) {
  STATE.rules[i][key] = val;
  // 仅刷新该行的“生成规则”预览，避免输入时光标丢失
  const row = el('rule-list').querySelector(`.rule-row[data-i="${i}"] .gen`);
  if (row) { const [k, v] = classifyRule(STATE.rules[i].value, STATE.rules[i].type); row.textContent = STATE.rules[i].value ? `${k},${v},${(STATE.rules[i].policy || 'PROXY').toUpperCase()}` : ''; }
}
function addRuleRow() { STATE.rules.push({ value: '', type: 'auto', policy: 'PROXY' }); renderRules(); }
function delRule(i) { STATE.rules.splice(i, 1); renderRules(); }
async function saveRules() {
  const rules = STATE.rules.filter(r => (r.value || '').trim());
  await api('PUT', '/api/rules', { rules });
  await api('PUT', '/api/settings', { settings: { final: el('final-policy').value } });
  toast('路由已保存，记得“应用配置”', 'ok');
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
  el('set-fakeip').value = s.fake_ip_range || '198.18.0.1/16';
  el('set-dns').value = (s.dns_nameservers || []).join('\n');
  el('set-dnscn').value = (s.dns_china || []).join('\n');
  el('set-mirror').value = s.github_mirror || '';
  el('set-ctrl').value = s.external_controller || '';
  el('web-port').value = STATE.webui.port || 8088;
  el('web-bind').value = STATE.webui.bind || '0.0.0.0';
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
    fake_ip_range: el('set-fakeip').value.trim(),
    dns_nameservers: lines(el('set-dns').value),
    dns_china: lines(el('set-dnscn').value),
    github_mirror: el('set-mirror').value.trim(),
    external_controller: el('set-ctrl').value.trim(),
  };
  await api('PUT', '/api/settings', { settings });
  await loadState();
  toast('设置已保存，记得“应用配置”', 'ok');
}
async function saveWebui() {
  const body = { port: parseInt(el('web-port').value) || 8088, bind: el('web-bind').value.trim() };
  const pw = el('web-pw').value;
  if (pw !== '') body.password = pw;
  await api('PUT', '/api/webui', body);
  toast('面板设置已保存（端口/地址改动需重启面板服务）', 'ok');
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
  await api('POST', '/api/service', { action });
  toast('已执行 ' + action, 'ok'); setTimeout(refreshStatus, 1200);
}

window.addEventListener('DOMContentLoaded', boot);
