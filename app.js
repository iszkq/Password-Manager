(() => {
  "use strict";

  const STORAGE_KEY = "yinbox-vault-v1";
  const KDF_ITERATIONS = 600000;
  const AUTO_LOCK_MS = 5 * 60 * 1000;

  const icons = {
    eye: '<svg viewBox="0 0 24 24"><path d="M2.5 12s3.5-6 9.5-6 9.5 6 9.5 6-3.5 6-9.5 6-9.5-6-9.5-6Z"/><circle cx="12" cy="12" r="2.5"/></svg>',
    eyeOff: '<svg viewBox="0 0 24 24"><path d="m3 3 18 18M10.6 6.2A9.8 9.8 0 0 1 12 6c6 0 9.5 6 9.5 6a17 17 0 0 1-2.1 2.8M6.2 6.2C3.8 7.8 2.5 12 2.5 12s3.5 6 9.5 6c1 0 2-.2 2.8-.5M9.9 9.9a3 3 0 0 0 4.2 4.2"/></svg>',
    grid: '<svg viewBox="0 0 24 24"><rect x="4" y="4" width="6" height="6" rx="1"/><rect x="14" y="4" width="6" height="6" rx="1"/><rect x="4" y="14" width="6" height="6" rx="1"/><rect x="14" y="14" width="6" height="6" rx="1"/></svg>',
    list: '<svg viewBox="0 0 24 24"><path d="M8 6h12M8 12h12M8 18h12"/><circle cx="4" cy="6" r=".5" fill="currentColor"/><circle cx="4" cy="12" r=".5" fill="currentColor"/><circle cx="4" cy="18" r=".5" fill="currentColor"/></svg>',
    key: '<svg viewBox="0 0 24 24"><circle cx="8" cy="15" r="4"/><path d="m11 12 8-8m-2 2 2 2m-5 1 2 2"/></svg>',
    note: '<svg viewBox="0 0 24 24"><path d="M6 3h9l4 4v14H6z"/><path d="M14 3v5h5M9 12h6M9 16h6"/></svg>',
    star: '<svg viewBox="0 0 24 24"><path d="m12 3 2.8 5.7 6.2.9-4.5 4.4 1.1 6.2-5.6-2.9-5.6 2.9 1.1-6.2L3 9.6l6.2-.9L12 3Z"/></svg>',
    download: '<svg viewBox="0 0 24 24"><path d="M12 3v12m-4-4 4 4 4-4M5 20h14"/></svg>',
    upload: '<svg viewBox="0 0 24 24"><path d="M12 16V4m-4 4 4-4 4 4M5 20h14"/></svg>',
    lock: '<svg viewBox="0 0 24 24"><rect x="5" y="10" width="14" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/></svg>',
    menu: '<svg viewBox="0 0 24 24"><path d="M4 7h16M4 12h16M4 17h16"/></svg>',
    search: '<svg viewBox="0 0 24 24"><circle cx="11" cy="11" r="7"/><path d="m20 20-4-4"/></svg>',
    plus: '<svg viewBox="0 0 24 24"><path d="M12 5v14M5 12h14"/></svg>',
    close: '<svg viewBox="0 0 24 24"><path d="m6 6 12 12M18 6 6 18"/></svg>',
    trash: '<svg viewBox="0 0 24 24"><path d="M4 7h16M9 7V4h6v3m3 0-1 14H7L6 7m4 4v6m4-6v6"/></svg>',
    check: '<svg viewBox="0 0 24 24"><path d="m5 12 4 4L19 6"/></svg>',
    copy: '<svg viewBox="0 0 24 24"><rect x="8" y="8" width="11" height="11" rx="2"/><path d="M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h2"/></svg>',
    external: '<svg viewBox="0 0 24 24"><path d="M14 5h5v5M19 5l-8 8M19 13v6H5V5h6"/></svg>'
  };

  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
  const state = {
    key: null,
    data: null,
    envelope: null,
    filter: "all",
    search: "",
    view: "grid",
    detailId: null,
    pendingDeleteId: null,
    autoLockTimer: null,
    failedUnlocks: 0,
    lockUntil: 0,
    toastTimer: null
  };

  function initIcons() {
    $$('[data-icon]').forEach((node) => {
      const icon = icons[node.dataset.icon];
      if (icon) node.innerHTML = icon;
    });
    $$('.password-toggle').forEach((button) => button.innerHTML = icons.eye);
  }

  function bytesToBase64(bytes) {
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary);
  }

  function base64ToBytes(value) {
    const binary = atob(value);
    return Uint8Array.from(binary, (char) => char.charCodeAt(0));
  }

  async function deriveKey(password, salt, iterations = KDF_ITERATIONS) {
    const material = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(password),
      "PBKDF2",
      false,
      ["deriveKey"]
    );
    return crypto.subtle.deriveKey(
      { name: "PBKDF2", hash: "SHA-256", salt, iterations },
      material,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  }

  async function encryptData(data, key) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const plaintext = new TextEncoder().encode(JSON.stringify(data));
    const encrypted = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, plaintext);
    return { iv: bytesToBase64(iv), ciphertext: bytesToBase64(new Uint8Array(encrypted)) };
  }

  async function decryptData(envelope, key) {
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: base64ToBytes(envelope.iv) },
      key,
      base64ToBytes(envelope.ciphertext)
    );
    return JSON.parse(new TextDecoder().decode(plaintext));
  }

  function readEnvelope() {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    try {
      const value = JSON.parse(raw);
      if (value.version !== 1 || !value.salt || !value.iv || !value.ciphertext) throw new Error("bad envelope");
      return value;
    } catch {
      return null;
    }
  }

  async function saveVault() {
    if (!state.key || !state.data || !state.envelope) return;
    state.data.updatedAt = new Date().toISOString();
    const encrypted = await encryptData(state.data, state.key);
    state.envelope = { ...state.envelope, ...encrypted };
    localStorage.setItem(STORAGE_KEY, JSON.stringify(state.envelope));
  }

  function passwordStrength(password) {
    let score = 0;
    if (password.length >= 12) score++;
    if (password.length >= 16) score++;
    if (/[a-z]/.test(password) && /[A-Z]/.test(password)) score++;
    if (/\d/.test(password) && /[^A-Za-z0-9]/.test(password)) score++;
    return Math.min(score, 4);
  }

  function setBusy(button, busy, busyText) {
    if (!button.dataset.label) button.dataset.label = button.textContent.trim();
    button.disabled = busy;
    if (busy) button.textContent = busyText;
    else button.textContent = button.dataset.label;
  }

  async function createVault(password) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const key = await deriveKey(password, salt);
    const now = new Date().toISOString();
    const data = { items: [], createdAt: now, updatedAt: now };
    const encrypted = await encryptData(data, key);
    const envelope = {
      version: 1,
      kdf: "PBKDF2-SHA256",
      iterations: KDF_ITERATIONS,
      salt: bytesToBase64(salt),
      ...encrypted
    };
    localStorage.setItem(STORAGE_KEY, JSON.stringify(envelope));
    state.key = key;
    state.data = data;
    state.envelope = envelope;
  }

  async function unlockVault(password) {
    const envelope = readEnvelope();
    if (!envelope) throw new Error("保险箱数据无效，请导入有效备份");
    const key = await deriveKey(password, base64ToBytes(envelope.salt), envelope.iterations || KDF_ITERATIONS);
    const data = await decryptData(envelope, key);
    if (!data || !Array.isArray(data.items)) throw new Error("保险箱数据格式无效");
    state.key = key;
    state.data = data;
    state.envelope = envelope;
  }

  function showApp() {
    $('#authView').hidden = true;
    $('#appView').hidden = false;
    $('#unlockPassword').value = "";
    state.failedUnlocks = 0;
    renderItems();
    resetAutoLock();
  }

  function lockVault(showMessage = false) {
    state.key = null;
    state.data = null;
    state.envelope = null;
    state.detailId = null;
    if (state.autoLockTimer) clearTimeout(state.autoLockTimer);
    $$('.modal[open]').forEach((dialog) => dialog.close());
    $('#appView').hidden = true;
    $('#authView').hidden = false;
    $('#unlockPanel').hidden = false;
    $('#setupPanel').hidden = true;
    $('#unlockPassword').focus();
    if (showMessage) $('#unlockError').textContent = "因长时间无操作，保险箱已自动锁定";
  }

  function resetAutoLock() {
    if (!state.key) return;
    if (state.autoLockTimer) clearTimeout(state.autoLockTimer);
    state.autoLockTimer = setTimeout(() => lockVault(true), AUTO_LOCK_MS);
  }

  function uid() {
    return crypto.randomUUID ? crypto.randomUUID() : `${Date.now()}-${crypto.getRandomValues(new Uint32Array(1))[0]}`;
  }

  function normalizeUrl(value) {
    const input = value.trim();
    if (!input) return "";
    const withProtocol = /^[a-z][a-z\d+.-]*:/i.test(input) ? input : `https://${input}`;
    try {
      const parsed = new URL(withProtocol);
      if (!['http:', 'https:'].includes(parsed.protocol)) return null;
      return parsed.href;
    } catch {
      return null;
    }
  }

  function displayHost(url) {
    try { return new URL(url).hostname.replace(/^www\./, ""); } catch { return url; }
  }

  function formatDate(value) {
    const date = new Date(value);
    const now = new Date();
    const diffDays = Math.floor((now - date) / 86400000);
    if (diffDays === 0) return "今天更新";
    if (diffDays === 1) return "昨天更新";
    if (diffDays < 7) return `${diffDays} 天前更新`;
    return `${date.getFullYear()}.${String(date.getMonth() + 1).padStart(2, '0')}.${String(date.getDate()).padStart(2, '0')}`;
  }

  function filteredItems() {
    if (!state.data) return [];
    const query = state.search.trim().toLocaleLowerCase('zh-CN');
    return state.data.items
      .filter((item) => {
        if (state.filter === "favorite") return item.favorite;
        if (state.filter !== "all") return item.type === state.filter;
        return true;
      })
      .filter((item) => {
        if (!query) return true;
        return [item.title, item.username, item.url, item.notes]
          .filter(Boolean)
          .some((value) => value.toLocaleLowerCase('zh-CN').includes(query));
      })
      .sort((a, b) => Number(b.favorite) - Number(a.favorite) || new Date(b.updatedAt) - new Date(a.updatedAt));
  }

  function renderItems() {
    if (!state.data) return;
    const all = state.data.items;
    $('#allCount').textContent = all.length;
    $('#accountCount').textContent = all.filter((item) => item.type === 'account').length;
    $('#noteCount').textContent = all.filter((item) => item.type === 'note').length;
    $('#favoriteCount').textContent = all.filter((item) => item.favorite).length;

    const titles = {
      all: ["全部项目", "集中管理你的账户与私密信息"],
      account: ["账户密码", "安全保存账号、密码和登录网址"],
      note: ["私密备忘", "存放恢复码、私密文字和重要信息"],
      favorite: ["星标收藏", "快速找到你最常使用的项目"]
    };
    $('#listTitle').textContent = state.search ? "搜索结果" : titles[state.filter][0];
    $('#listSubtitle').textContent = state.search ? `找到 ${filteredItems().length} 个匹配项目` : titles[state.filter][1];

    const grid = $('#itemGrid');
    grid.replaceChildren();
    grid.classList.toggle('list-view', state.view === 'list');
    const items = filteredItems();
    $('#emptyState').hidden = items.length !== 0;
    grid.hidden = items.length === 0;
    items.forEach((item) => grid.append(createCard(item)));
  }

  function createCard(item) {
    const card = document.createElement('article');
    card.className = 'vault-card';
    card.tabIndex = 0;
    card.setAttribute('role', 'button');
    card.setAttribute('aria-label', `查看 ${item.title}`);
    card.addEventListener('click', () => openDetail(item.id));
    card.addEventListener('keydown', (event) => {
      if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); openDetail(item.id); }
    });

    const top = document.createElement('div');
    top.className = 'card-top';
    const avatar = document.createElement('div');
    avatar.className = `item-avatar${item.type === 'note' ? ' note-avatar' : ''}`;
    avatar.textContent = item.type === 'note' ? '✦' : (item.title.trim()[0] || '#');
    const titleBox = document.createElement('div');
    titleBox.className = 'card-title';
    const title = document.createElement('h2');
    title.textContent = item.title;
    const sub = document.createElement('p');
    sub.textContent = item.type === 'account' ? (item.url ? displayHost(item.url) : '账户密码') : '私密备忘';
    titleBox.append(title, sub);
    const favorite = document.createElement('button');
    favorite.className = `icon-button favorite-button${item.favorite ? ' active' : ''}`;
    favorite.type = 'button';
    favorite.setAttribute('aria-label', item.favorite ? '取消星标' : '添加星标');
    favorite.innerHTML = icons.star;
    favorite.addEventListener('click', async (event) => {
      event.stopPropagation();
      item.favorite = !item.favorite;
      item.updatedAt = new Date().toISOString();
      await saveVault();
      renderItems();
    });
    top.append(avatar, titleBox, favorite);

    const main = document.createElement('div');
    main.className = 'card-main';
    if (item.type === 'account') {
      const user = document.createElement('p');
      user.textContent = item.username || '未填写账号';
      const password = document.createElement('p');
      password.className = 'masked';
      password.textContent = item.password ? '••••••••••' : '未填写密码';
      main.append(user, password);
    } else {
      const notes = document.createElement('p');
      notes.className = 'note-preview';
      notes.textContent = item.notes || '暂无内容';
      main.append(notes);
    }

    const footer = document.createElement('div');
    footer.className = 'card-footer';
    const updated = document.createElement('span');
    updated.textContent = formatDate(item.updatedAt);
    footer.append(updated);
    if (item.type === 'account') {
      const actions = document.createElement('div');
      actions.style.display = 'flex';
      actions.style.gap = '14px';
      if (item.username) actions.append(makeQuickCopyButton('复制账号', item.username));
      if (item.password) actions.append(makeQuickCopyButton('复制密码', item.password));
      footer.append(actions);
    } else {
      footer.append(makeQuickCopyButton('复制内容', item.notes || ''));
    }
    card.append(top, main, footer);
    return card;
  }

  function makeQuickCopyButton(label, value) {
    const button = document.createElement('button');
    button.type = 'button';
    button.textContent = label;
    button.disabled = !value;
    button.addEventListener('click', async (event) => {
      event.stopPropagation();
      await copyText(value, `${label.replace('复制', '')}已复制`);
    });
    return button;
  }

  async function copyText(value, message = "已复制") {
    if (!value) return;
    try {
      await navigator.clipboard.writeText(value);
    } catch {
      const area = document.createElement('textarea');
      area.value = value;
      area.style.position = 'fixed';
      area.style.opacity = '0';
      document.body.append(area);
      area.select();
      document.execCommand('copy');
      area.remove();
    }
    showToast(message);
    resetAutoLock();
  }

  function showToast(message) {
    $('#toastText').textContent = message;
    $('#toast').classList.add('show');
    if (state.toastTimer) clearTimeout(state.toastTimer);
    state.toastTimer = setTimeout(() => $('#toast').classList.remove('show'), 1900);
  }

  function setItemType(type) {
    $('#itemType').value = type;
    $('#accountFields').hidden = type !== 'account';
    $$('.type-switch button').forEach((button) => button.classList.toggle('active', button.dataset.type === type));
    $('#itemNotes').placeholder = type === 'note' ? '写下任何需要加密保存的私密信息…' : '记录恢复码、提示或任何私密信息…';
  }

  function openItemDialog(item = null, initialType = 'account') {
    $('#itemForm').reset();
    $('#itemError').textContent = '';
    $('#itemId').value = item?.id || '';
    $('#itemDialogTitle').textContent = item ? '编辑项目' : '新建项目';
    const type = item?.type || initialType;
    setItemType(type);
    if (item) {
      $('#itemTitle').value = item.title || '';
      $('#itemUrl').value = item.url || '';
      $('#itemUsername').value = item.username || '';
      $('#itemPassword').value = item.password || '';
      $('#itemNotes').value = item.notes || '';
      $('#itemFavorite').checked = Boolean(item.favorite);
    }
    $('#itemDialog').showModal();
    setTimeout(() => $('#itemTitle').focus(), 0);
  }

  function addDetailRow(container, label, value, options = {}) {
    if (!value && !options.showEmpty) return;
    const row = document.createElement('div');
    row.className = 'detail-row';
    const fieldLabel = document.createElement('label');
    fieldLabel.textContent = label;
    const valueBox = document.createElement('div');
    valueBox.className = `detail-value${options.notes ? ' detail-notes' : ''}`;
    const content = document.createElement('span');
    if (options.link) {
      const link = document.createElement('a');
      link.href = value;
      link.target = '_blank';
      link.rel = 'noopener noreferrer';
      link.textContent = value;
      content.append(link);
    } else {
      content.textContent = options.masked ? '••••••••••••' : (value || '未填写');
      if (options.masked) content.dataset.visible = 'false';
    }
    valueBox.append(content);
    if (options.masked) {
      const reveal = document.createElement('button');
      reveal.type = 'button';
      reveal.className = 'icon-button detail-copy';
      reveal.innerHTML = icons.eye;
      reveal.setAttribute('aria-label', '显示密码');
      reveal.addEventListener('click', () => {
        const visible = content.dataset.visible === 'true';
        content.dataset.visible = String(!visible);
        content.textContent = visible ? '••••••••••••' : value;
        reveal.innerHTML = visible ? icons.eye : icons.eyeOff;
      });
      valueBox.append(reveal);
    }
    if (value) {
      const copy = document.createElement('button');
      copy.type = 'button';
      copy.className = 'icon-button detail-copy';
      copy.innerHTML = icons.copy;
      copy.setAttribute('aria-label', `复制${label}`);
      copy.addEventListener('click', () => copyText(value, `${label}已复制`));
      valueBox.append(copy);
    }
    row.append(fieldLabel, valueBox);
    container.append(row);
  }

  function openDetail(id) {
    const item = state.data.items.find((entry) => entry.id === id);
    if (!item) return;
    state.detailId = id;
    $('#detailType').textContent = item.type === 'account' ? '账户密码' : '私密备忘';
    $('#detailTitle').textContent = item.title;
    const body = $('#detailBody');
    body.replaceChildren();
    if (item.type === 'account') {
      addDetailRow(body, '登录网址', item.url, { link: true });
      addDetailRow(body, '用户名 / 邮箱', item.username, { showEmpty: true });
      addDetailRow(body, '密码', item.password, { masked: true, showEmpty: true });
    }
    addDetailRow(body, '备注', item.notes, { notes: true, showEmpty: true });
    $('#detailDialog').showModal();
  }

  function closeDialog(id) {
    const dialog = $(`#${id}`);
    if (dialog?.open) dialog.close();
  }

  async function handleItemSubmit(event) {
    event.preventDefault();
    const title = $('#itemTitle').value.trim();
    if (!title) { $('#itemError').textContent = '请填写项目名称'; return; }
    const type = $('#itemType').value;
    const url = type === 'account' ? normalizeUrl($('#itemUrl').value) : '';
    if (url === null) { $('#itemError').textContent = '网址格式不正确，仅支持 http 或 https'; return; }
    const id = $('#itemId').value;
    const existing = state.data.items.find((item) => item.id === id);
    const now = new Date().toISOString();
    const item = {
      id: existing?.id || uid(),
      type,
      title,
      url: url || '',
      username: type === 'account' ? $('#itemUsername').value.trim() : '',
      password: type === 'account' ? $('#itemPassword').value : '',
      notes: $('#itemNotes').value.trim(),
      favorite: $('#itemFavorite').checked,
      createdAt: existing?.createdAt || now,
      updatedAt: now
    };
    if (existing) Object.assign(existing, item);
    else state.data.items.push(item);
    await saveVault();
    closeDialog('itemDialog');
    renderItems();
    showToast(existing ? '项目已更新并加密' : '项目已加密保存');
  }

  function requestDelete(id) {
    state.pendingDeleteId = id;
    closeDialog('detailDialog');
    $('#deleteDialog').showModal();
  }

  async function confirmDelete() {
    if (!state.pendingDeleteId) return;
    state.data.items = state.data.items.filter((item) => item.id !== state.pendingDeleteId);
    state.pendingDeleteId = null;
    await saveVault();
    closeDialog('deleteDialog');
    renderItems();
    showToast('项目已删除');
  }

  function generatePassword() {
    const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*()-_=+';
    const values = crypto.getRandomValues(new Uint32Array(22));
    const password = [...values].map((value) => chars[value % chars.length]).join('');
    $('#itemPassword').value = password;
    $('#itemPassword').type = 'text';
    const toggle = $('[data-toggle-password="itemPassword"]');
    toggle.innerHTML = icons.eyeOff;
    toggle.setAttribute('aria-label', '隐藏密码');
    showToast('已生成 22 位强密码');
  }

  function downloadBackup() {
    const envelope = localStorage.getItem(STORAGE_KEY);
    if (!envelope) return;
    const blob = new Blob([envelope], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    const stamp = new Date().toISOString().slice(0, 10);
    anchor.href = url;
    anchor.download = `隐匣-加密备份-${stamp}.json`;
    anchor.click();
    URL.revokeObjectURL(url);
    showToast('加密备份已导出');
  }

  async function importBackup(file) {
    try {
      const raw = await file.text();
      const value = JSON.parse(raw);
      if (value.version !== 1 || !value.salt || !value.iv || !value.ciphertext) throw new Error();
      localStorage.setItem(STORAGE_KEY, JSON.stringify(value));
      lockVault();
      $('#unlockError').textContent = '备份已导入，请使用该备份的主密码解锁';
    } catch {
      showToast('备份文件无效');
    } finally {
      $('#importInput').value = '';
    }
  }

  function bindEvents() {
    $('#setupPassword').addEventListener('input', (event) => {
      const score = passwordStrength(event.target.value);
      const labels = ['请输入主密码', '较弱', '一般', '较强', '很强'];
      const colors = ['#ff7d73', '#ff7d73', '#efb95f', '#bada5a', '#c8f255'];
      $('#strengthBar').style.width = `${score * 25}%`;
      $('#strengthBar').style.background = colors[score];
      $('#strengthText').textContent = score ? `密码强度：${labels[score]}` : '建议使用多个不相关词语组成的长密码';
    });

    $('#setupForm').addEventListener('submit', async (event) => {
      event.preventDefault();
      const password = $('#setupPassword').value;
      const confirmation = $('#confirmPassword').value;
      $('#setupError').textContent = '';
      if (password.length < 12) { $('#setupError').textContent = '主密码至少需要 12 位'; return; }
      if (password !== confirmation) { $('#setupError').textContent = '两次输入的密码不一致'; return; }
      const button = $('#setupButton');
      setBusy(button, true, '正在创建加密保险箱…');
      try {
        await createVault(password);
        $('#setupForm').reset();
        showApp();
      } catch {
        $('#setupError').textContent = '创建失败，请确认浏览器支持 Web Crypto';
      } finally {
        setBusy(button, false);
      }
    });

    $('#unlockForm').addEventListener('submit', async (event) => {
      event.preventDefault();
      const remaining = state.lockUntil - Date.now();
      if (remaining > 0) { $('#unlockError').textContent = `尝试次数过多，请 ${Math.ceil(remaining / 1000)} 秒后再试`; return; }
      const password = $('#unlockPassword').value;
      if (!password) { $('#unlockError').textContent = '请输入主密码'; return; }
      const button = $('#unlockButton');
      $('#unlockError').textContent = '';
      setBusy(button, true, '正在解密…');
      try {
        await unlockVault(password);
        showApp();
      } catch (error) {
        state.failedUnlocks++;
        if (state.failedUnlocks >= 5) {
          const delay = Math.min(60, 2 ** (state.failedUnlocks - 4) * 5);
          state.lockUntil = Date.now() + delay * 1000;
          $('#unlockError').textContent = `密码错误，已暂停尝试 ${delay} 秒`;
        } else {
          $('#unlockError').textContent = '主密码不正确，请重试';
        }
        $('#unlockPassword').select();
      } finally {
        setBusy(button, false);
      }
    });

    $$('.password-toggle').forEach((button) => button.addEventListener('click', () => {
      const input = $(`#${button.dataset.togglePassword}`);
      const visible = input.type === 'text';
      input.type = visible ? 'password' : 'text';
      button.innerHTML = visible ? icons.eye : icons.eyeOff;
      button.setAttribute('aria-label', visible ? '显示密码' : '隐藏密码');
    }));

    $$('.nav-item').forEach((button) => button.addEventListener('click', () => {
      state.filter = button.dataset.filter;
      state.search = '';
      $('#searchInput').value = '';
      $$('.nav-item').forEach((item) => item.classList.toggle('active', item === button));
      renderItems();
      closeSidebar();
    }));

    $('#searchInput').addEventListener('input', (event) => {
      state.search = event.target.value;
      renderItems();
    });
    document.addEventListener('keydown', (event) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k' && state.key) {
        event.preventDefault(); $('#searchInput').focus();
      }
      if (event.key === 'Escape' && state.key) closeSidebar();
    });

    $$('[data-view]').forEach((button) => button.addEventListener('click', () => {
      state.view = button.dataset.view;
      $$('[data-view]').forEach((item) => item.classList.toggle('active', item === button));
      renderItems();
    }));
    $$('.type-switch button').forEach((button) => button.addEventListener('click', () => setItemType(button.dataset.type)));
    $$('[data-close-dialog]').forEach((button) => button.addEventListener('click', () => closeDialog(button.dataset.closeDialog)));
    $$('.modal').forEach((dialog) => dialog.addEventListener('click', (event) => {
      if (event.target === dialog) dialog.close();
    }));

    $('#addButton').addEventListener('click', () => openItemDialog(null, state.filter === 'note' ? 'note' : 'account'));
    $('#emptyAddButton').addEventListener('click', () => openItemDialog(null, state.filter === 'note' ? 'note' : 'account'));
    $('#itemForm').addEventListener('submit', handleItemSubmit);
    $('#generateButton').addEventListener('click', generatePassword);
    $('#detailEditButton').addEventListener('click', () => {
      const item = state.data.items.find((entry) => entry.id === state.detailId);
      closeDialog('detailDialog');
      if (item) openItemDialog(item);
    });
    $('#detailDeleteButton').addEventListener('click', () => requestDelete(state.detailId));
    $('#confirmDeleteButton').addEventListener('click', confirmDelete);
    $('#lockButton').addEventListener('click', () => lockVault());
    $('#backupButton').addEventListener('click', downloadBackup);
    $('#importButton').addEventListener('click', () => $('#importInput').click());
    $('#importInput').addEventListener('change', (event) => event.target.files[0] && importBackup(event.target.files[0]));
    $('#menuButton').addEventListener('click', () => {
      $('.sidebar').classList.add('open');
      $('#sidebarBackdrop').classList.add('show');
    });
    $('#sidebarBackdrop').addEventListener('click', closeSidebar);
    ['pointerdown', 'keydown', 'scroll', 'touchstart'].forEach((name) => document.addEventListener(name, resetAutoLock, { passive: true }));
  }

  function closeSidebar() {
    $('.sidebar').classList.remove('open');
    $('#sidebarBackdrop').classList.remove('show');
  }

  function initialize() {
    initIcons();
    bindEvents();
    const hasVault = Boolean(localStorage.getItem(STORAGE_KEY));
    $('#unlockPanel').hidden = !hasVault;
    $('#setupPanel').hidden = hasVault;
    if (!hasVault) $('#setupPassword').focus();
  }

  initialize();
})();
