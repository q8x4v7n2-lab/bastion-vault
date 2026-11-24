'use strict';

// BASTION VAULT 0.5: полностью клиентский прототип, не проходил независимый аудит.
// Никаких сетевых запросов, библиотек, серверной синхронизации или аналитики.
// Весь документ (включая названия сайтов) шифруется одним AES-256-GCM ключом.
const FORMAT = 'bastion-vault';
const VERSION = 1;
const ITERATIONS = 600_000;
const DB_NAME = 'bastion-vault-local-v1';
const STORE_NAME = 'encrypted';
const RECORD_ID = 'vault';
const AAD = new TextEncoder().encode('BASTION-VAULT/v1');
// Non-sensitive UI preference; never changes the encrypted vault or Face ID keys.
const LOCK_PREF = 'bastion-idle-lock-v07';
const LOCK_CHOICES = [0, 1, 5, 15];
function idleLockMinutes() {
  try { const saved=localStorage.getItem(LOCK_PREF); if(saved===null)return 5; const n=Number(saved); return LOCK_CHOICES.includes(n) ? n : 5; }
  catch { return 5; }
}
function idleLockMilliseconds() { return idleLockMinutes()*60_000; }

const BACKGROUND_LOCK_MS = 0;
const MAX_BACKUP_BYTES = 8_000_000;
const MAX_PASSWORD_LENGTH = 128;

const $ = (id) => document.getElementById(id);
let db;
let vault = null;
let key = null;
let envelope = null;
let editingId = null;
let pendingImport = null;
let busy = false;
let lastActivity = Date.now();
let hiddenAt = 0;
let toastTimer;

function toast(message) {
  const node = $('toast');
  node.textContent = translateText(message);
  node.classList.remove('hidden');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => node.classList.add('hidden'), 4100);
}
function setBusy(value, button) {
  busy = value;
  if (button) button.disabled = value;
  if (!value && document.hidden && vault) lockVault(false);
}
function randomBytes(length) { return crypto.getRandomValues(new Uint8Array(length)); }
function base64(bytes) {
  let result = '';
  for (let i = 0; i < bytes.length; i += 8192) result += String.fromCharCode(...bytes.subarray(i, i + 8192));
  return btoa(result);
}
function bytesFromBase64(str) {
  const binary = atob(str);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}
function validEnvelope(value) {
  if (!value || typeof value !== 'object' || value.format !== FORMAT || value.version !== VERSION ||
      value.iterations !== ITERATIONS || typeof value.salt !== 'string' ||
      typeof value.iv !== 'string' || typeof value.data !== 'string' ||
      value.data.length > MAX_BACKUP_BYTES || value.data.length < 25) return false;
  try { return bytesFromBase64(value.salt).length === 16 && bytesFromBase64(value.iv).length === 12 && bytesFromBase64(value.data).length >= 17; }
  catch { return false; }
}
function validVault(value) {
  if (!value || value.schema !== 1 || !Array.isArray(value.entries) || value.entries.length > 20_000) return false;
  if (value.totp !== undefined && (!Array.isArray(value.totp) || value.totp.length > 2000 || !value.totp.every(validTotp) || new Set(value.totp.map(t=>t.id)).size !== value.totp.length)) return false;
  const ids = new Set();
  return value.entries.every(e => {
    if (!e || typeof e.id !== 'string' || ids.has(e.id)) return false;
    ids.add(e.id);
    return e && typeof e.id === 'string' && e.id.length <= 70 &&
    typeof e.service === 'string' && e.service.length <= 100 &&
    typeof e.login === 'string' && e.login.length <= 200 &&
    typeof e.password === 'string' && e.password.length <= 1024 &&
    typeof e.url === 'string' && e.url.length <= 1000 &&
    typeof e.notes === 'string' && e.notes.length <= 3000;
  });
}

function openDB() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1);
    request.onupgradeneeded = () => request.result.createObjectStore(STORE_NAME);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
    request.onblocked = () => reject(new Error('Другая вкладка блокирует базу.'));
  });
}
function readEncrypted() {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readonly');
    const request = tx.objectStore(STORE_NAME).get(RECORD_ID);
    request.onsuccess = () => resolve(request.result ?? null);
    request.onerror = () => reject(request.error);
  });
}
function writeEncrypted(value) {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readwrite');
    tx.objectStore(STORE_NAME).put(value, RECORD_ID);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
    tx.onabort = () => reject(tx.error || new Error('Не удалось сохранить данные.'));
  });
}
async function deriveKey(master, salt, iterations = ITERATIONS) {
  const input = await crypto.subtle.importKey('raw', new TextEncoder().encode(master), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({name:'PBKDF2', salt, iterations, hash:'SHA-256'}, input,
    {name:'AES-GCM', length:256}, false, ['encrypt', 'decrypt']);
}
async function encryptVault(currentVault, currentKey, salt) {
  const iv = randomBytes(12);
  const plaintext = new TextEncoder().encode(JSON.stringify(currentVault));
  const sealed = await crypto.subtle.encrypt({name:'AES-GCM', iv, additionalData:AAD, tagLength:128}, currentKey, plaintext);
  return {format:FORMAT, version:VERSION, iterations:ITERATIONS, salt:base64(salt), iv:base64(iv), data:base64(new Uint8Array(sealed))};
}
async function decryptEnvelope(record, master) {
  if (!validEnvelope(record)) throw new Error('Неподдерживаемый или повреждённый формат копии.');
  const newKey = await deriveKey(master, bytesFromBase64(record.salt), record.iterations);
  let plaintext;
  try { plaintext = await crypto.subtle.decrypt({name:'AES-GCM', iv:bytesFromBase64(record.iv), additionalData:AAD, tagLength:128}, newKey, bytesFromBase64(record.data)); }
  catch { throw new Error('Неверный пароль либо повреждённые данные.'); }
  let decoded;
  try { decoded = JSON.parse(new TextDecoder('utf-8', {fatal:true}).decode(plaintext)); }
  catch { throw new Error('Повреждённое содержимое сейфа.'); }
  if (!validVault(decoded)) throw new Error('Повреждённые или несовместимые записи.');
  return {decoded, newKey};
}
async function persistVault(nextVault) {
  if (!key || !envelope) throw new Error('Сейф заблокирован.');
  const updated = await encryptVault(nextVault, key, bytesFromBase64(envelope.salt));
  if(!validEnvelope(updated))throw new Error('Сейф превышает допустимый размер.');
  await writeEncrypted(updated);
  if (key && envelope) { envelope = updated; vault = nextVault; }
}
function showGate(mode) {
  $('gate').classList.toggle('hidden', !$('languageSetup').classList.contains('hidden'));
  $('app').classList.add('hidden');
  $('lockBtn').classList.add('hidden');
  $('createView').classList.toggle('hidden', mode !== 'create');
  $('unlockView').classList.toggle('hidden', mode !== 'unlock');
}
function showApp() {
  if(document.hidden){lockVault(false);return;}
  $('gate').classList.add('hidden');
  $('app').classList.toggle('hidden', !$('languageSetup').classList.contains('hidden'));
  $('lockBtn').classList.remove('hidden');
  $('search').value = '';
  $('favoritesOnly').checked=false;
  lastActivity = Date.now();
  renderEntries();
  bioUi();
  selectTab('vault');
}
function closeDialogs() {
  for (const id of ['editor','importDialog','masterDialog','bioDialog']) if ($(id).open) $(id).close();
  $('secret').value = '';
  $('newMaster').value = '';
  $('confirmMaster').value = '';
  $('unlockMaster').value = '';
  $('importMaster').value = '';
  $('masterNew').value = '';
  $('masterConfirm').value = '';
  pendingImport = null;
}
function lockVault(showMessage = true) {
  resetBioSetup();
  clearTitan();
  closeDialogs();
  $('entryList').replaceChildren();
  $('auditPanel').replaceChildren();
  $('auditPanel').classList.add('hidden');
  $('search').value = '';
  for (const id of ['service','login','notes','siteUrl','generatedOutput']) $(id).value='';
  $('entryHistory').textContent='';
  vault = null;
  key = null;
  editingId = null;
  envelope = null;
  showGate('unlock');
  bioUi();
  if (showMessage) toast('Сейф заблокирован.');
}
function make(tag, className = '', value = '') {
  const el = document.createElement(tag);
  if (className) el.className = className;
  if (value) el.textContent = value;
  return el;
}
function getInitial(s) { return Array.from(s.trim())[0]?.toLocaleUpperCase('ru') || '◆'; }
async function copyToClipboard(value, what) {
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) await navigator.clipboard.writeText(value);
    else {
      const temp = make('textarea');
      temp.value = value;
      temp.setAttribute('readonly','');
      temp.style.position = 'fixed'; temp.style.top = '-1000px';
      document.body.append(temp); temp.select();
      const result = document.execCommand('copy'); temp.remove();
      if (!result) throw new Error('Clipboard');
    }
    toast(`${what} скопирован. Буфер обмена доступен другим приложениям.`);
  } catch { toast('Копирование не удалось: попробуй Safari по HTTPS.'); }
}
function ensureHttps(raw) {
  if (!raw.trim()) return '';
  const parsed = new URL(raw.trim());
  if (parsed.protocol !== 'https:' || !parsed.hostname || parsed.username || parsed.password) throw new Error('Разрешены только HTTPS-ссылки без логина в адресе.');
  return parsed.href;
}
function renderEntries() {
  if (!vault) return;
  $('count').textContent = String(vault.entries.length);
  const root = $('entryList');
  root.replaceChildren();
  const needle = $('search').value.trim().toLocaleLowerCase('ru');
  const onlyFavorites = $('favoritesOnly').checked;
  const filtered = [...vault.entries].filter(item => `${item.service} ${item.login}`.toLocaleLowerCase('ru').includes(needle) && (!onlyFavorites || item.favorite === true))
    .sort((a,b) => Number(b.favorite === true)-Number(a.favorite === true) || a.service.localeCompare(b.service, uiLanguage));
  if (filtered.length === 0) {
    const empty = make('div','empty');
    empty.append(make('strong','',vault.entries.length ? 'Ничего не найдено' : 'Здесь появятся твои аккаунты'));
    empty.append(document.createTextNode(vault.entries.length ? 'Попробуй другой запрос.' : 'Нажми «Добавить запись», чтобы создать первую зашифрованную запись.'));
    root.append(empty); translateNode(empty); return;
  }
  for (const item of filtered) {
    const row = make('article','entry');
    const mark = make('div','entry-mark',getInitial(item.service));
    const body = make('div','entry-body');
    body.append(make('div','entry-title',item.service));
    body.append(make('div','entry-login',item.login || 'Логин не указан'));
    const actions = make('div','entry-buttons');
    const star = make('button','btn ghost small favorite-btn',item.favorite === true ? '★' : '☆');
    star.type = 'button'; star.title = item.favorite === true ? translateText('Убрать из избранного') : translateText('В избранное');
    star.setAttribute('aria-label', star.title);
    star.setAttribute('aria-pressed',String(item.favorite === true));
    star.addEventListener('click',()=>toggleFavorite(item.id));
    const loginCopy = make('button','btn ghost small','@');
    loginCopy.type='button';loginCopy.title=translateText('Копировать логин');loginCopy.setAttribute('aria-label',loginCopy.title);
    loginCopy.disabled=!item.login;
    loginCopy.addEventListener('click',()=>copyToClipboard(item.login,translateText('Логин')));
    const copy = make('button','btn secondary small','Копия');
    copy.type = 'button'; copy.title = 'Копировать пароль';
    copy.addEventListener('click', () => copyToClipboard(item.password,'Пароль'));
    const edit = make('button','btn ghost small','Открыть');
    edit.type = 'button'; edit.addEventListener('click', () => openEditor(item.id));
    actions.append(star,loginCopy,copy,edit); row.append(mark,body,actions);root.append(row);
    translateNode(actions);
  }
}
async function toggleFavorite(id) {
  if (!vault || busy) return;
  const current = vault.entries.find(e=>e.id===id);
  if (!current) return;
  busy=true;
  try {
    const entries=vault.entries.map(e=>e.id===id ? {...e,favorite:e.favorite!==true} : e);
    await persistVault({...vault,entries});
    renderEntries();
  } catch(e) {toast(e.message||'Не удалось сохранить избранное.');}
  finally {setBusy(false);}
}
function randomIndex(max) {
  const maxValue = Math.floor(256 / max) * max;
  const x = new Uint8Array(1);
  do { crypto.getRandomValues(x); } while (x[0] >= maxValue);
  return x[0] % max;
}
function generatePassword(len, allowSymbols) {
  if (!Number.isInteger(len) || len < 12 || len > MAX_PASSWORD_LENGTH) {
    throw new Error('Длина пароля должна быть от 12 до 128 символов.');
  }
  const groups = ['abcdefghijkmnopqrstuvwxyz','ABCDEFGHJKLMNPQRSTUVWXYZ','23456789'];
  if (allowSymbols) groups.push('!@#$%^&*()-_=+[]{}?');
  const all = groups.join('');
  const chars = groups.map(group => group[randomIndex(group.length)]);
  while (chars.length < len) chars.push(all[randomIndex(all.length)]);
  for (let i=chars.length-1;i>0;i--) {const j=randomIndex(i+1);[chars[i],chars[j]]=[chars[j],chars[i]];}
  return chars.join('');
}
function openEditor(id = null) {
  if (!vault) return;
  clearEditorPilot();
  editingId = id;
  const item = id ? vault.entries.find(e => e.id === id) : null;
  $('editorTitle').textContent = item ? 'Изменить запись' : 'Новая запись';
  $('deleteEntry').classList.toggle('hidden', !item);
  $('service').value = item?.service ?? '';
  $('login').value = item?.login ?? '';
  $('secret').value = item?.password ?? '';
  $('secret').type = 'password';
  $('showSecret').textContent = translateText('Показать');
  $('siteUrl').value = item?.url ?? '';
  $('notes').value = item?.notes ?? '';
  const fmt = date => {if(!date)return '—';const d=new Date(date);return Number.isNaN(d.valueOf())?'—':new Intl.DateTimeFormat(uiLanguage,{dateStyle:'medium',timeStyle:'short'}).format(d);};
  $('entryHistory').classList.toggle('hidden',!item);
  $('entryHistory').textContent = item ? (translateText('Создано')+': '+fmt(item.createdAt)+'  •  '+translateText('Изменено')+': '+fmt(item.updatedAt)) : '';
  translateNode($('editor'));
  $('editor').showModal();
}
function renderAudit() {
  if (!vault) return;
  const p = $('auditPanel');
  p.replaceChildren();
  const counts = new Map();
  for (const e of vault.entries) if (e.password) counts.set(e.password,(counts.get(e.password)||0)+1);
  const reused = vault.entries.filter(e => e.password && counts.get(e.password)>1).length;
  const short = vault.entries.filter(e => e.password.length < 14).length;
  const empty = vault.entries.filter(e => !e.password).length;
  const common = new Set(['password','password123','123456','12345678','qwerty','qwerty123','admin','111111','letmein']);
  const obvious = vault.entries.filter(e => common.has(e.password.toLowerCase())).length;
  const line1 = make('div','', 'Локальная проверка: ');
  line1.append(make('strong','',String(vault.entries.length) + ' записей'));
  const line2 = make('div', reused ? 'bad':'', `Повторяющиеся пароли: ${reused} записей`);
  const line3 = make('div', short ? 'bad':'', `Пароли короче 14 символов: ${short}`);
  const hint = make('div','', 'Это базовая проверка, не доказательство стойкости. Никакие пароли никуда не отправляются.');
  const line4 = make('div', obvious ? 'bad':'', `Известные простые пароли: ${obvious}`);
  const line5 = make('div', empty ? 'bad':'', `Пустые пароли: ${empty}`);
  p.append(line1,line2,line3,line4,line5,hint);
  p.classList.remove('hidden');
  translateNode(p);
}
async function onCreate(event) {
  event.preventDefault(); if (busy) return;
  const first = $('newMaster').value;
  const again = $('confirmMaster').value;
  if (first.length < 16) return toast('Нужно минимум 16 символов для мастер-пароля.');
  if (first !== again) return toast('Мастер-пароли не совпадают.');
  setBusy(true,$('createBtn'));
  try {
    if (await readEncrypted()) throw new Error('Сейф уже создан; перезагрузи приложение.');
    const salt = randomBytes(16);
    const newKey = await deriveKey(first,salt);
    const data = {schema:1,entries:[]};
    const record = await encryptVault(data,newKey,salt);
    await writeEncrypted(record);
    key = newKey;vault = data;envelope = record;
    $('newMaster').value = ''; $('confirmMaster').value = '';
    showApp(); toast('Сейф создан. Сделай резервную копию после добавления записей.');
  } catch(e) {toast(e.message || 'Ошибка создания сейфа.');}
  finally {setBusy(false,$('createBtn'));}
}
async function onUnlock(event) {
  event.preventDefault(); if (busy) return;
  const pass = $('unlockMaster').value;
  $('unlockMaster').value = '';
  setBusy(true,$('unlockBtn'));
  try {
    const record = await readEncrypted();
    if (!record) throw new Error('Сейф не найден. Перезапусти приложение.');
    const result = await decryptEnvelope(record,pass);
    vault = result.decoded;key = result.newKey;envelope = record;
    showApp(); toast('Сейф открыт.');
  } catch(e) {toast(e.message || 'Ошибка разблокировки.');}
  finally {setBusy(false,$('unlockBtn'));}
}
async function onSaveEntry(event) {
  event.preventDefault(); if (!vault || busy) return;
  const service = $('service').value.trim();
  const login = $('login').value.trim();
  const password = $('secret').value;
  const notes = $('notes').value;
  if (!service) return toast('Укажи название сервиса.');
  if (!password) return toast('Укажи пароль или сгенерируй его.');
  if (password.length > 1024 || service.length > 100 || login.length > 200 || notes.length > 3000)
    return toast('Одно из полей превышает допустимую длину.');
  let url;
  try { url = ensureHttps($('siteUrl').value); if (url.length > 1000) throw new Error('Ссылка слишком длинная.'); }
  catch(e) {return toast(e.message);}
  const now = new Date().toISOString();
  const old = editingId ? vault.entries.find(x => x.id === editingId) : null;
  if (editingId && !old) return toast('Запись не найдена.');
  const entry = {...(old||{}),id: old?.id || crypto.randomUUID(),service,login,password,url,notes,createdAt:old?.createdAt || now,updatedAt:now};
  const nextEntries = old ? vault.entries.map(x=>x.id===old.id?entry:x) : [...vault.entries,entry];
  setBusy(true,$('saveEntry'));
  try {
    await persistVault({...vault,entries:nextEntries});
    $('editor').close(); $('secret').value = '';
    renderEntries(); $('auditPanel').classList.add('hidden');
    toast('Запись зашифрована и сохранена на устройстве.');
  } catch(e) {toast('Не удалось сохранить запись: '+ (e.message||'ошибка хранилища'));}
  finally {setBusy(false,$('saveEntry'));}
}
async function deleteEditingEntry() {
  if (!vault || !editingId || busy) return;
  const entry = vault.entries.find(e => e.id === editingId);
  if (!entry || !confirm(`Удалить «${entry.service}» без возможности восстановления из текущего сейфа?`)) return;
  setBusy(true);
  try {
    await persistVault({...vault,entries:vault.entries.filter(e=>e.id!==editingId)});
    $('editor').close();$('secret').value='';renderEntries();toast('Запись удалена.');
  }catch(e){toast(e.message||'Ошибка удаления.');}finally{setBusy(false);}
}
function downloadBackup() {
  if (!envelope || !vault || busy) return;
  const blob = new Blob([JSON.stringify(envelope,null,2)], {type:'application/json'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href=url;a.download=`BASTION-encrypted-${new Date().toISOString().slice(0,10)}.json`;
  document.body.append(a);a.click();a.remove();
  setTimeout(()=>URL.revokeObjectURL(url),30_000);
  toast('Создан файл только с зашифрованными данными. Сохрани в надёжном месте.');
}
async function prepareImport(event) {
  const file = event.target.files?.[0];
  event.target.value = '';
  if (!file) return;
  if (file.size > MAX_BACKUP_BYTES) return toast('Файл слишком большой для этой версии.');
  try {
    const record = JSON.parse(await file.text());
    if (!validEnvelope(record)) throw new Error('Это не поддерживаемая копия BASTION VAULT.');
    pendingImport = record;
    $('importMaster').value = '';
    $('importDialog').showModal();
  } catch(e) { toast(e.message || 'Не удалось открыть файл.'); }
}
async function onImport(event) {
  event.preventDefault();if (busy || !pendingImport) return;
  const pass = $('importMaster').value;
  $('importMaster').value='';
  setBusy(true,$('confirmImport'));
  try {
    const result = await decryptEnvelope(pendingImport,pass);
    const current = await readEncrypted();
    if (current && !confirm('Заменить весь текущий сейф импортированной копией? Убедись, что сохранил прежнюю резервную копию.')) return;
    await writeEncrypted(pendingImport);
    if(current?.salt !== pendingImport.salt) localStorage.removeItem(BIO_STORAGE);
    closeDialogs();
    vault=result.decoded;key=result.newKey;envelope=await readEncrypted();
    showApp();toast('Зашифрованная копия успешно восстановлена.');
  } catch(e) {toast(e.message||'Ошибка импорта.');}
  finally {setBusy(false,$('confirmImport'));}
}
async function onChangeMaster(event) {
  event.preventDefault();if (busy || !vault) return;
  const first=$('masterNew').value, second=$('masterConfirm').value;
  if(first.length<16)return toast('Нужно минимум 16 символов.');
  if(first!==second)return toast('Новые мастер-пароли не совпадают.');
  setBusy(true,$('confirmMasterChange'));
  try {
    const salt=randomBytes(16);
    const nextKey=await deriveKey(first,salt);
    const nextRecord=await encryptVault(vault,nextKey,salt);
    await writeEncrypted(nextRecord);
    key=nextKey;envelope=nextRecord;localStorage.removeItem(BIO_STORAGE);bioUi();
    $('masterDialog').close();$('masterNew').value='';$('masterConfirm').value='';
    toast('Мастер-пароль заменён. Скачай новую резервную копию.');
  }catch(e){toast(e.message||'Не удалось сменить пароль.');}
  finally{setBusy(false,$('confirmMasterChange'));}
}

// Optional local passkey PRF unlock. Requires browser support; never replaces the master password.
const BIO_STORAGE = 'bastion-vault-prf-v03';
function bioConfig() { try { return JSON.parse(localStorage.getItem(BIO_STORAGE) || 'null'); } catch { return null; } }
function bioAvailable() { return !!(window.PublicKeyCredential && navigator.credentials && window.isSecureContext); }
function bioUi() {
  const has = !!bioConfig();
  const available = bioAvailable();
  $('bioUnlockBtn').classList.toggle('hidden', !has || !available);
  // Keep setup action visible, explain why biometric unlock may be unavailable.
  $('bioSetupBtn').classList.remove('hidden');
  $('bioSetupBtn').disabled = !available;
  $('bioRemoveBtn').classList.toggle('hidden', !has);
  const status = $('bioStatus');
  if(status) status.textContent = !available
    ? 'Быстрый вход недоступен в этом браузере. Используйте установленное приложение и мастер-пароль.'
    : has ? 'Ключ доступа найден. Проверьте быстрый вход: Face ID, Touch ID или код устройства.'
          : 'Быстрый вход ещё не настроен. Нажмите кнопку настройки биометрии.';
  document.documentElement.dataset.bastionBio = has ? (available ? 'ready' : 'unsupported') : 'not-configured';
}

async function prfAes(secret) {
  return crypto.subtle.importKey('raw', secret, {name:'AES-GCM'}, false, ['encrypt','decrypt']);
}
// Face ID setup is intentionally split into user-initiated actions.
// Safari requires a focused document and an active user gesture for WebAuthn.
let setupMaster = null;
let setupCredential = null;
let setupSalt = null;
let setupStoredSalt = null;
function resetBioSetup() {
  setupMaster = null; setupCredential = null; setupSalt = null; setupStoredSalt = null;
  $('bioMaster').value = '';
  $('bioActionBtn').classList.add('hidden');
  $('bioActionBtn').textContent = translateText('Продолжить настройку Face ID');
}
function bioFocusReady() {
  if (document.visibilityState !== 'visible' || !document.hasFocus()) {
    toast('Safari неактивен. Вернись на вкладку и нажми кнопку ещё раз.');
    return false;
  }
  return true;
}
function setupBiometric() {
  if (busy || !vault || !bioAvailable()) return;
  resetBioSetup();
  $('bioDialog').showModal();
}
async function verifyBioMaster(event) {
  event.preventDefault();
  if (busy || !vault) return;
  const candidate = $('bioMaster').value;
  $('bioMaster').value = '';
  setBusy(true, $('bioVerifyBtn'));
  try {
    const stored = await readEncrypted();
    if (!stored) throw new Error('Сейф не найден.');
    await decryptEnvelope(stored, candidate);
    setupMaster = candidate;
    setupStoredSalt = stored.salt;
    setupSalt = randomBytes(32);
    $('bioActionBtn').classList.remove('hidden');
    $('bioActionBtn').textContent = translateText('Создать ключ доступа');
    toast('Пароль подтверждён. Теперь нажми «Создать ключ доступа».');
  } catch(e) {
    resetBioSetup();
    toast(e.message || 'Пароль не подошёл.');
  } finally { setBusy(false, $('bioVerifyBtn')); }
}
async function completeBioSetup(prfOutput) {
  if (!prfOutput || prfOutput.byteLength !== 32) throw new Error('Safari не вернул секрет PRF. Face ID не включён.');
  const wrappingKey = await prfAes(prfOutput);
  const iv = randomBytes(12);
  const encrypted = await crypto.subtle.encrypt({name:'AES-GCM', iv}, wrappingKey, new TextEncoder().encode(setupMaster));
  localStorage.setItem(BIO_STORAGE, JSON.stringify({
    credential:base64(new Uint8Array(setupCredential)),salt:base64(setupSalt),
    iv:base64(iv),data:base64(new Uint8Array(encrypted)),vaultSalt:setupStoredSalt
  }));
  resetBioSetup();
  $('bioDialog').close();
  bioUi();
  toast('Ключ доступа настроен. Проверь разблокировку после блокировки сейфа.');
}
async function performBioSetup() {
  if (busy || !vault || !setupMaster || !bioFocusReady()) return;
  // navigator.credentials.create/get must be invoked before the first await.
  let operation;
  try {
    if (!setupCredential) {
      operation = navigator.credentials.create({publicKey:{
        challenge:randomBytes(32),rp:{name:'BASTION VAULT'},
        user:{id:randomBytes(24),name:'local-vault',displayName:'BASTION VAULT'},
        pubKeyCredParams:[{type:'public-key',alg:-7},{type:'public-key',alg:-257}],
        authenticatorSelection:{authenticatorAttachment:'platform',userVerification:'required',residentKey:'preferred'},
        timeout:60000,attestation:'none',extensions:{prf:{eval:{first:setupSalt}}}
      }});
    } else {
      operation = navigator.credentials.get({publicKey:{
        challenge:randomBytes(32),allowCredentials:[{type:'public-key',id:setupCredential}],
        userVerification:'required',timeout:60000,extensions:{prf:{eval:{first:setupSalt}}}
      }});
    }
  } catch(e) {toast(e.message || 'Не удалось запустить Face ID.');return;}
  busy = true;
  $('bioActionBtn').disabled = true;
  try {
    const result = await operation;
    if (!result) throw new Error('Ключ доступа не создан.');
    if (!setupCredential) setupCredential = result.rawId;
    const prf = result.getClientExtensionResults()?.prf?.results?.first;
    if (prf) await completeBioSetup(prf);
    else if ($('bioActionBtn').textContent === translateText('Создать ключ доступа')) {
      $('bioActionBtn').textContent = translateText('Завершить настройку Face ID');
      toast('Ключ создан. Нажми «Завершить настройку Face ID».');
    } else throw new Error('WebAuthn PRF не поддерживается. Используй мастер-пароль.');
  } catch(e) {
    toast(e.name === 'NotAllowedError' ? 'Операция отменена или запрещена Safari.' : (e.message || 'Face ID недоступен.'));
  } finally {
    busy = false;
    $('bioActionBtn').disabled = false;
    if (document.hidden && vault) lockVault(false);
  }
}
async function unlockBiometric() {
  if (busy || !bioAvailable()) return;
  const config=bioConfig(); if (!config) return;
  busy=true; $('bioUnlockBtn').disabled=true;
  try {
    const assertion=await navigator.credentials.get({publicKey:{challenge:randomBytes(32),allowCredentials:[{type:'public-key',id:bytesFromBase64(config.credential)}],userVerification:'required',timeout:60000,extensions:{prf:{eval:{first:bytesFromBase64(config.salt)}}}}});
    const stored=await readEncrypted();
    if (!stored || stored.salt!==config.vaultSalt) throw new Error('Сейф изменён. Войди мастер-паролем и настрой биометрию заново.');
    const secret=assertion?.getClientExtensionResults()?.prf?.results?.first;
    if (!secret) throw new Error('Safari не вернул ключ PRF. Разблокируй мастер-паролем.');
    const wrappingKey=await prfAes(secret);
    const raw=await crypto.subtle.decrypt({name:'AES-GCM',iv:bytesFromBase64(config.iv)},wrappingKey,bytesFromBase64(config.data));
    const master=new TextDecoder().decode(raw);
    const result=await decryptEnvelope(stored,master);
    if(document.hidden)throw new Error('Вернись в приложение и повтори вход.');
    vault=result.decoded;key=result.newKey;envelope=stored;showApp();toast('Сейф открыт.');
  } catch(e) {toast(e.message || 'Face ID недоступен. Используй мастер-пароль.');}
  finally {busy=false;$('bioUnlockBtn').disabled=false;}
}

function attachHandlers() {
  document.querySelectorAll('[data-tab]').forEach(button => button.addEventListener('click', () => selectTab(button.dataset.tab)));
  $('auditBtn').addEventListener('click',()=>selectTab('audit'));
  $('generatedLength').addEventListener('input',()=>{$('generatedLengthLabel').textContent=$('generatedLength').value;});
  $('generateStandalone').addEventListener('click',generateStandalonePassword);
  $('copyGenerated').addEventListener('click',()=> $('generatedOutput').value ? copyToClipboard($('generatedOutput').value,'Пароль') : toast('Сначала создайте пароль.'));

  $('bioUnlockBtn').addEventListener('click',unlockBiometric);
  $('bioSetupBtn').addEventListener('click',setupBiometric);
  $('bioVerifyForm').addEventListener('submit',verifyBioMaster);
  $('bioActionBtn').addEventListener('click',performBioSetup);
  $('bioCancelBtn').addEventListener('click',()=>{$('bioDialog').close();resetBioSetup();});
  $('bioDialog').addEventListener('close',resetBioSetup);
  $('bioRemoveBtn').addEventListener('click',()=>{if(!vault || busy || !confirm('Отключить быстрый вход? Для следующего входа понадобится мастер-пароль.'))return;localStorage.removeItem(BIO_STORAGE);bioUi();toast('Быстрая разблокировка отключена.');});
  $('createForm').addEventListener('submit',onCreate);
  $('unlockForm').addEventListener('submit',onUnlock);
  $('editorForm').addEventListener('submit',onSaveEntry);
  $('importForm').addEventListener('submit',onImport);
  $('masterForm').addEventListener('submit',onChangeMaster);
  $('lockBtn').addEventListener('click',()=>{if(!busy)lockVault();else toast('Дождись окончания операции.');});
  $('addBtn').addEventListener('click',()=>openEditor());
  $('search').addEventListener('input',renderEntries);
  $('favoritesOnly').addEventListener('change',renderEntries);
  $('idleLockSelect').value=String(idleLockMinutes());
  $('idleLockSelect').addEventListener('change',()=>{
    const n=Number($('idleLockSelect').value);
    if(!LOCK_CHOICES.includes(n))return;
    try {localStorage.setItem(LOCK_PREF,String(n));}catch {toast('Не удалось сохранить настройку.');return;}
    lastActivity=Date.now();
    toast(translateText('Настройка автоблокировки сохранена.'));
  });

  $('exportBtn').addEventListener('click',()=>openReauth('export'));
  $('importFile').addEventListener('change',prepareImport);
  $('changeMasterBtn').addEventListener('click',()=>openReauth('master'));
  $('clearClipBtn').addEventListener('click',async()=>{
    try {await navigator.clipboard.writeText('');toast('Буфер обмена очищен.');}
    catch {toast('Не удалось очистить буфер.');}
  });
  $('showSecret').addEventListener('click',()=>{
    const show=$('secret').type==='password';$('secret').type=show?'text':'password';
    $('showSecret').textContent=translateText(show?'Скрыть':'Показать');
  });
  $('copyLogin').addEventListener('click',()=> $('login').value ? copyToClipboard($('login').value,'Логин') : toast('Логин не указан.'));
  $('copyPassword').addEventListener('click',()=> $('secret').value ? copyToClipboard($('secret').value,'Пароль') : toast('Пароль не указан.'));
  $('openWebsite').addEventListener('click',()=>{
    try {
      const url=ensureHttps($('siteUrl').value);
      if (!url) return toast('Добавь HTTPS-адрес сайта.');
      window.open(url,'_blank','noopener,noreferrer');
    } catch(e) {toast(e.message);}
  });
  $('deleteEntry').addEventListener('click',deleteEditingEntry);
  $('generateBtn').addEventListener('click',()=>{
    try {
      $('secret').value=generatePassword(Number($('length').value),$('symbols').checked);
      $('secret').type='password';$('showSecret').textContent=translateText('Показать');
      toast('Новый пароль создан. Он ещё не изменён на сайте!');
    } catch (e) { toast(e.message); }
  });
  for(const id of ['closeEditor','cancelEditor']) $(id).addEventListener('click',()=>{$('editor').close();$('secret').value='';});
  for(const id of ['cancelImport','dismissImport']) $(id).addEventListener('click',()=>{pendingImport=null;$('importDialog').close();$('importMaster').value='';});
  for(const id of ['cancelMaster','dismissMaster']) $(id).addEventListener('click',()=>{$('masterDialog').close();$('masterNew').value='';$('masterConfirm').value='';});
  for(const dialog of [$('editor'),$('importDialog'),$('masterDialog')]) dialog.addEventListener('close',()=>{
    $('secret').value='';$('importMaster').value='';$('masterNew').value='';$('masterConfirm').value='';
    if(dialog===$('importDialog'))pendingImport=null;
  });
  document.addEventListener('pointerdown',()=>lastActivity=Date.now(),{passive:true});
  document.addEventListener('keydown',()=>lastActivity=Date.now(),{passive:true});
  document.addEventListener('visibilitychange',()=>{
    if (document.hidden) {
      hiddenAt = Date.now();
      if (vault && !busy) lockVault(false);
    } else hiddenAt = 0;
  });
  window.addEventListener('pagehide',()=>{resetBioSetup();if(vault)lockVault(false);});
  setInterval(()=>{const ms=idleLockMilliseconds();if(vault && !busy && !document.hidden && ms>0 && Date.now()-lastActivity>=ms)lockVault();},5_000);
}
async function init() {
  attachHandlers();
  attachTitan();
  initLanguage();
  // Version label is authored directly in index.html.
  if (!window.isSecureContext || !crypto?.subtle || !window.indexedDB) {
    $('gate').classList.add('hidden');$('unsupported').classList.remove('hidden');return;
  }
  try {
    db = await openDB();
    const current = await readEncrypted();
    window.bastionHasVault=!!current;
    showGate(current ? 'unlock' : 'create');
    bioUi();
  } catch(e) {
    $('gate').classList.add('hidden');
    $('unsupported').classList.remove('hidden');
    $('unsupported').append(make('p','',e.message||'Локальное хранилище недоступно.'));
  }
  if('serviceWorker' in navigator) navigator.serviceWorker.register('./sw.js').catch(()=>{});
}

// GHOST PROTOCOL UI localization. Never translates user secrets or vault contents.
const LANG_KEY = 'bastion-ui-language-v05';
const UI_EN = {"BASTION VAULT — приватный сейф": "BASTION VAULT — Private Vault", "🔒 Закрыть": "🔒 Lock", "Нужен защищённый браузер": "Secure browser required", "Для шифрования требуются HTTPS, Web Crypto и локальная база IndexedDB. Открой приложение через HTTPS в Safari.": "Encryption requires HTTPS, Web Crypto and local IndexedDB storage. Open the app over HTTPS.", "ПЕРВЫЙ ЗАПУСК": "INITIAL SETUP", "Создай свой": "Create your", "приватный сейф": "private vault", "Пароли шифруются на устройстве. Мастер-пароль никому не отправляется и не сохраняется.": "Passwords are encrypted on your device. Your master password is never sent or stored.", "Мастер-пароль (минимум 16 символов)": "Master password (at least 16 characters)", "Повтори мастер-пароль": "Repeat master password", "⚠ Если забудешь мастер-пароль, восстановить сейф невозможно. Не используй здесь пароли от других сервисов.": "⚠ If you forget the master password, the vault cannot be recovered. Never reuse another account password.", "Создать зашифрованный сейф": "Create encrypted vault", "СЕЙФ ЗАБЛОКИРОВАН": "VAULT LOCKED", "Твои секреты.": "Your secrets.", "Твои правила.": "Your rules.", "Для доступа к хранилищу введи мастер-пароль. Интернет не нужен.": "Enter your master password to access the vault. No internet needed.", "Мастер-пароль": "Master password", "Разблокировать": "Unlock", "◈ Разблокировать через Face ID / код устройства": "◈ Unlock with Face ID / device passcode", "Забыл пароль? Расшифровать данные без него нельзя.": "Forgot your password? Your data cannot be decrypted without it.", "◆ ЛОКАЛЬНО": "◆ LOCAL", "◆ БЕЗ АНАЛИТИКИ": "◆ NO TRACKING", "ХРАНИЛИЩЕ РАЗБЛОКИРОВАНО": "VAULT UNLOCKED", "Мой сейф": "My vault", "записей": "entries", "Данные расшифрованы только в памяти этого приложения. Они не отправляются на сервер.": "Data is decrypted only in this app's memory. It is not sent to a server.", "＋ Добавить запись": "＋ Add entry", "◈ Аудит": "◈ Audit", "Безопасность и резервирование": "Security & backup", "Локальные данные можно потерять при удалении веб-приложения или очистке его хранилища. Регулярно сохраняй зашифрованную резервную копию.": "Local data can be lost if the app or its storage is removed. Export encrypted backups regularly.", "↓ Экспорт зашифрованной копии": "↓ Export encrypted backup", "◈ Настроить Face ID (экспериментально)": "◈ Set up Face ID (experimental)", "Отключить Face ID": "Disable Face ID", "⇄ Сменить мастер-пароль": "⇄ Change master password", "Очистить буфер обмена": "Clear clipboard", "↑ Импорт зашифрованной копии": "↑ Import encrypted backup", "Настройка Face ID": "Face ID setup", "Сначала подтверди текущий мастер-пароль. Затем отдельной кнопкой запусти создание ключа доступа. Поддержка PRF в Safari не гарантирована.": "First verify your current master password. Then create a passkey using the separate button. PRF support is not guaranteed.", "Текущий мастер-пароль": "Current master password", "Проверить мастер-пароль": "Verify master password", "Создать ключ доступа": "Create passkey", "ЗАЩИФРОВАННАЯ ЗАПИСЬ": "ENCRYPTED ENTRY", "Новая запись": "New entry", "Изменить запись": "Edit entry", "Сервис / приложение": "Service / app", "Логин / e-mail": "Login / email", "Пароль": "Password", "Показать": "Show", "Скрыть": "Hide", "Длина": "Length", "Символы": "Symbols", "✦ Генерировать": "✦ Generate", "Адрес сайта (HTTPS)": "Website URL (HTTPS)", "Заметки (тоже шифруются)": "Notes (also encrypted)", "Копировать логин": "Copy login", "Копировать пароль": "Copy password", "Открыть сайт": "Open website", "Удалить запись": "Delete entry", "Замена пароля здесь не меняет пароль на самом сайте. Сначала измени его в настройках аккаунта, затем сохрани новый здесь.": "Changing a password here does not change it on the website. Update it on the website first.", "Сохранить": "Save", "Отмена": "Cancel", "Проверка резервной копии": "Verify backup", "Введи мастер-пароль": "Enter the master password for the", "импортируемой": "imported", "копии. Нынешний сейф будет заменён только после успешной проверки и твоего подтверждения.": "backup. The current vault will only be replaced after verification and confirmation.", "Мастер-пароль копии": "Backup master password", "Проверить копию": "Verify backup", "Сменить мастер-пароль": "Change master password", "Все записи будут заново зашифрованы с новой случайной солью. Старые резервные копии по-прежнему открываются старым паролем.": "All entries will be re-encrypted with a new random salt. Old backups still use the old password.", "Новый мастер-пароль (от 16 символов)": "New master password (16+ characters)", "Повтори новый пароль": "Repeat new password", "Зашифровать заново": "Re-encrypt", "Продолжить настройку Face ID": "Continue Face ID setup", "Завершить настройку Face ID": "Finish Face ID setup", "Ничего не найдено": "Nothing found", "Здесь появятся твои аккаунты": "Your accounts will appear here", "Попробуй другой запрос.": "Try another search.", "Нажми «Добавить запись», чтобы создать первую зашифрованную запись.": "Tap Add entry to create your first encrypted record.", "Логин не указан": "No login provided", "Копия": "Copy", "Открыть": "Open", "Локальная проверка:": "Local check:", "Повторяющиеся пароли:": "Reused passwords:", "Пароли короче 14 символов:": "Passwords shorter than 14 characters:", "Известные простые пароли:": "Common weak passwords:", "Пустые пароли:": "Empty passwords:", "Это базовая проверка, не доказательство стойкости. Никакие пароли никуда не отправляются.": "This is a basic local check, not proof of password strength. Passwords are never transmitted.", "Длинная уникальная парольная фраза": "A long unique passphrase", "Повтори без ошибок": "Repeat exactly", "Твой мастер-пароль": "Your master password", "Найти сервис или логин...": "Search services or logins...", "Например, Telegram": "For example, Telegram", "Имя пользователя или почта": "Username or email", "Введи или сгенерируй": "Enter or generate", "Дополнительная информация...": "Additional information...", "Закрыть": "Close", "Поиск записей": "Search entries", "Сейф заблокирован.": "Vault locked.", "Сейф открыт.": "Vault unlocked.", "Сейф создан. Сделай резервную копию после добавления записей.": "Vault created. Export a backup after adding entries.", "Сейф не найден. Перезапусти приложение.": "Vault not found. Restart the app.", "Нужно минимум 16 символов для мастер-пароля.": "Master password must be at least 16 characters.", "Мастер-пароли не совпадают.": "Master passwords do not match.", "Пароль подтверждён. Теперь нажми «Создать ключ доступа».": "Password verified. Now tap Create passkey.", "Ключ доступа настроен. Проверь разблокировку после блокировки сейфа.": "Passkey set up. Test unlocking after locking the vault.", "Face ID недоступен. Используй мастер-пароль.": "Face ID unavailable. Use your master password.", "Быстрая разблокировка отключена.": "Quick unlock disabled.", "Запись зашифрована и сохранена на устройстве.": "Entry encrypted and saved on device.", "Запись удалена.": "Entry deleted.", "Буфер обмена очищен.": "Clipboard cleared.", "Не удалось очистить буфер.": "Could not clear clipboard.", "Новый пароль создан. Он ещё не изменён на сайте!": "Password generated. It has not been changed on the website!", "Логин не указан.": "No login provided.", "Пароль не указан.": "No password provided.", "Нужно минимум 16 символов.": "At least 16 characters required.", "Новые мастер-пароли не совпадают.": "New master passwords do not match.", "Мастер-пароль заменён. Скачай новую резервную копию.": "Master password changed. Export a fresh backup.", "Сейф уже создан; перезагрузи приложение.": "Vault already exists; reload the app.", "Укажи название сервиса.": "Enter a service name.", "Укажи пароль или сгенерируй его.": "Enter or generate a password.", "Пароль скопирован. Буфер обмена доступен другим приложениям.": "Password copied. Other apps can access the clipboard.", "Логин скопирован. Буфер обмена доступен другим приложениям.": "Login copied. Other apps can access the clipboard.", "Зашифрованная копия успешно восстановлена.": "Encrypted backup restored.", "Ключ создан. Нажми «Завершить настройку Face ID».": "Passkey created. Tap Finish Face ID setup.", "Safari не вернул секрет PRF. Face ID не включён.": "Browser did not return PRF secret. Face ID not enabled.", "Safari неактивен. Вернись на вкладку и нажми кнопку ещё раз.": "Browser is not focused. Return to the app and try again."};
let uiLanguage = 'ru';
let languageMode = 'system';
const originalText = new WeakMap();
const originalAttrs = new WeakMap();
function systemLanguage(){ return (navigator.languages?.[0] || navigator.language || 'en').toLowerCase().startsWith('ru') ? 'ru' : 'en'; }
function translateText(input){
  if(uiLanguage==='ru') return input;
  const match = /^(\s*)([\s\S]*?)(\s*)$/.exec(input);
  const core = match[2];
  if (Object.prototype.hasOwnProperty.call(UI_EN,core)) return match[1]+UI_EN[core]+match[3];
  return input;
}
function translateNode(node){
  if(node.nodeType===3){
    const parent=node.parentElement;
    if(!parent || parent.closest('#entryList .entry-title,#entryList .entry-login,#notes,#service,#login,#secret,#siteUrl,#languageSetup,#toast') || parent.closest('script,style')) return;
    if(!originalText.has(node)) originalText.set(node,node.nodeValue);
    const source=originalText.get(node), translated=translateText(source);
    if(node.nodeValue!==translated) node.nodeValue=translated;
  }else if(node.nodeType===1){
    if(node.id==='languageSetup' || node.id==='toast' || node.closest('#languageSetup')) return;
    for(const attr of ['placeholder','aria-label','title']) if(node.hasAttribute(attr)){
      let values=originalAttrs.get(node);if(!values){values={};originalAttrs.set(node,values);}
      if(!(attr in values))values[attr]=node.getAttribute(attr);
      const translated=translateText(values[attr]);if(node.getAttribute(attr)!==translated)node.setAttribute(attr,translated);
    }
    for(const child of node.childNodes) translateNode(child);
  }
}
Object.assign(UI_EN, {
  'Только избранное':'Favorites only',
  'В избранное':'Add to favorites',
  'Убрать из избранного':'Remove from favorites',
  'Создано':'Created',
  'Изменено':'Updated',
  'Автоблокировка':'Auto-lock',
  'Когда блокировать сейф при бездействии? При сворачивании приложение блокируется всегда.':'Lock after inactivity. The vault always locks when sent to the background.',
  'Сразу при сворачивании':'On background only',
  'Через 1 минуту':'After 1 minute',
  'Через 5 минут':'After 5 minutes',
  'Через 15 минут':'After 15 minutes',
  'Настройка автоблокировки сохранена.':'Auto-lock setting saved.',
  'История записи':'Entry history',
  'Логин':'Login'
});
function applyLanguage(lang){
  uiLanguage = lang==='ru'?'ru':'en';
  document.documentElement.lang=uiLanguage;
  document.documentElement.dir='ltr';
  translateNode(document.body);
  const btn=$('langSettingsBtn');if(btn)btn.textContent='🌐 '+uiLanguage.toUpperCase();
  if(vault)renderEntries();
}
function showLanguageSetup(){
  $('languageSetup').classList.remove('hidden');
  $('gate').classList.add('hidden');$('app').classList.add('hidden');
  $('languageSelect').value=uiLanguage;
}
function initLanguage(){
  let saved=null;try{saved=JSON.parse(localStorage.getItem(LANG_KEY)||'null');}catch{}
  languageMode=saved?.mode==='manual'?'manual':'system';
  applyLanguage(languageMode==='manual'?saved?.language:systemLanguage());
  $('langSettingsBtn').addEventListener('click',showLanguageSetup);
  $('changeLanguageBtn').addEventListener('click',showLanguageSetup);
  $('systemLanguageBtn').addEventListener('click',()=>{languageMode='system';$('languageSelect').classList.add('hidden');$('languageSelectLabel').classList.add('hidden');});
  $('manualLanguageBtn').addEventListener('click',()=>{languageMode='manual';$('languageSelect').classList.remove('hidden');$('languageSelectLabel').classList.remove('hidden');});
  $('languageContinueBtn').addEventListener('click',()=>{
    const lang=languageMode==='system'?systemLanguage():$('languageSelect').value;
    try{localStorage.setItem(LANG_KEY,JSON.stringify({mode:languageMode,language:lang}));}catch{}
    $('languageSetup').classList.add('hidden');
    applyLanguage(lang);
    if(vault)showApp();else showGate(window.bastionHasVault?'unlock':'create');
  });
  if(!saved)showLanguageSetup();
}


function selectTab(tab) {
  if(!vault) return;
  for(const name of ['vault','generator','audit','settings','auth','connect']) {
    const page=$(name+'Page');
    if(page)page.classList.toggle('hidden',name!==tab);
  }
  document.querySelectorAll('[data-tab]').forEach(button=>{
    const active=button.dataset.tab===tab;
    button.classList.toggle('active',active);
    button.setAttribute('aria-current',active?'page':'false');
  });
  if(tab==='audit')renderAudit();
  if(tab==='settings')bioUi();else clearSettingsPilot();
  if(tab==='auth')renderTotp();
  if(tab==='connect')renderConnect();
  if(tab!=='auth')$('totpList').replaceChildren();
  if(tab==='generator' && !$('generatedOutput').value)generateStandalonePassword();
  window.scrollTo({top:0,behavior:'smooth'});
}
function generateStandalonePassword() {
  try { $('generatedOutput').value=generatePassword(Number($('generatedLength').value),$('generatedSymbols').checked); }
  catch(e) {toast(e.message||'Не удалось создать пароль.');}
}

// TITAN: TOTP RFC 4226/6238, account guides, and local device verification.
const B32='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function decodeBase32(input){
  const raw=String(input).toUpperCase().replace(/[\s-]/g,'').replace(/=+$/,'');
  if(raw.length<16||raw.length>256||!/^[A-Z2-7]+$/.test(raw))throw new Error('Нужен ключ Base32 (буквы A–Z и цифры 2–7), от 16 символов.');
  let bits=0,n=0,out=[];for(const ch of raw){n=(n<<5)|B32.indexOf(ch);bits+=5;if(bits>=8){bits-=8;out.push((n>>bits)&255);}}
  if(bits>=5||(bits&&((n&((1<<bits)-1))!==0)))throw new Error('Ключ неполный или повреждён.');
  return Uint8Array.from(out);
}
function parseTotp(input){
  let secret=input.trim(),name='',algorithm='SHA-1',digits=6,period=30;
  if(/^otpauth:/i.test(secret)){
    const u=new URL(secret);if(u.protocol!=='otpauth:'||u.hostname!=='totp')throw new Error('Поддерживаются только коды TOTP, не HOTP.');
    for(const param of ['secret','algorithm','digits','period'])if(u.searchParams.getAll(param).length>1)throw new Error('Повторяющиеся параметры QR.');
    name=decodeURIComponent(u.pathname.slice(1)).slice(0,100);secret=u.searchParams.get('secret')||'';
    const a=(u.searchParams.get('algorithm')||'SHA1').toUpperCase().replace('-','');algorithm=({SHA1:'SHA-1',SHA256:'SHA-256',SHA512:'SHA-512'})[a];
    digits=Number(u.searchParams.get('digits')||6);period=Number(u.searchParams.get('period')||30);
  }
  secret=secret.toUpperCase().replace(/[\s-]/g,'').replace(/=+$/,'');decodeBase32(secret);
  if(!['SHA-1','SHA-256','SHA-512'].includes(algorithm)||![6,8].includes(digits)||!Number.isInteger(period)||period<15||period>120)throw new Error('Неподдерживаемые параметры TOTP.');
  return {secret,name,algorithm,digits,period};
}
function validTotp(t){try{return !!t&&typeof t.id==='string'&&t.id.length<=70&&typeof t.name==='string'&&t.name.length>0&&t.name.length<=100&&typeof t.secret==='string'&&decodeBase32(t.secret).length>=10&&['SHA-1','SHA-256','SHA-512'].includes(t.algorithm)&&[6,8].includes(t.digits)&&Number.isInteger(t.period)&&t.period>=15&&t.period<=120&&typeof t.entryId==='string'&&t.entryId.length<=70;}catch{return false;}}
async function totpCode(t,seconds=Math.floor(Date.now()/1000)){
  const counter=new ArrayBuffer(8);new DataView(counter).setBigUint64(0,BigInt(Math.floor(seconds/t.period)));
  const k=await crypto.subtle.importKey('raw',decodeBase32(t.secret),{name:'HMAC',hash:t.algorithm},false,['sign']);
  const bytes=new Uint8Array(await crypto.subtle.sign('HMAC',k,counter));const o=bytes[bytes.length-1]&15;
  const n=((bytes[o]&127)<<24)|(bytes[o+1]<<16)|(bytes[o+2]<<8)|bytes[o+3];return String(n%10**t.digits).padStart(t.digits,'0');
}
let totpGeneration=0,qrStream=null,qrTimer=null,qrGeneration=0,pilotStep=0,pilotMode='auth',pilotActive=false;
function stopQr(){++qrGeneration;clearTimeout(qrTimer);qrTimer=null;if(qrStream){qrStream.getTracks().forEach(t=>t.stop());qrStream=null;}$('qrVideo').srcObject=null;$('qrVideo').classList.add('hidden');}
function clearTotpForm(){stopQr();$('totpForm').reset();$('totpEntry').replaceChildren();$('pilotInline').classList.add('hidden');document.querySelectorAll('.pilot-highlight').forEach(n=>n.classList.remove('pilot-highlight'));}
function clearTitan(){clearEditorPilot();clearSettingsPilot();clearReauth();++totpGeneration;stopQr();for(const id of ['totpDialog','pilotDialog'])if($(id).open)$(id).close();clearTotpForm();$('totpList').replaceChildren();$('connectList').replaceChildren();pilotActive=false;}
function openTotp(name='',guide=false){if(!vault||busy)return;clearTotpForm();$('totpName').value=name;const select=$('totpEntry');select.add(new Option('Без связи',''));for(const e of vault.entries)select.add(new Option(e.service+' — '+e.login,e.id));$('totpDialog').showModal();pilotActive=guide;if(guide)pilotHint();}
function pilotHint(){if(!pilotActive||!$('totpDialog').open)return;const n=$('totpName'),s=$('totpSecret');document.querySelectorAll('.pilot-highlight').forEach(x=>x.classList.remove('pilot-highlight'));let field=n,msg='1. Введи название аккаунта в подсвеченное поле.';if(n.value.trim()){field=s;msg='2. Вставь секретный ключ из настроек сервиса. Для QR нажми «Прочитать QR с фото» или «Сканировать камерой».';try{parseTotp(s.value);field=$('totpSave');msg='3. Ключ распознан. При желании выбери запись сейфа, затем нажми «Сохранить 2FA».';}catch{}}field.classList.add('pilot-highlight');$('pilotInline').textContent=msg;$('pilotInline').classList.remove('hidden');}
async function saveTotp(e){e.preventDefault();if(!vault||busy)return;let t;try{t=parseTotp($('totpSecret').value);t.name=$('totpName').value.trim()||t.name;if(!t.name)throw new Error('Введи название аккаунта.');t.id=crypto.randomUUID();t.entryId=$('totpEntry').value;if(!validTotp(t))throw new Error('Проверь поля.');if((vault.totp||[]).length>=2000)throw new Error('Достигнут лимит кодов.');}catch(err){return toast(err.message);}
  setBusy(true,$('totpSave'));try{await persistVault({...vault,totp:[...(vault.totp||[]),t]});$('totpDialog').close();clearTotpForm();pilotActive=false;if(vault){selectTab('auth');toast('Код сохранён. Введи его в исходном сервисе для подтверждения.');}}catch(err){toast(err.message||'Ошибка сохранения.');}finally{setBusy(false,$('totpSave'));}}
function renderTotp(){const list=$('totpList');++totpGeneration;list.replaceChildren();if(!vault)return;const entries=vault.totp||[];if(!entries.length){list.append(make('div','empty','Пока нет кодов. Нажми «Добавить код 2FA» или запусти помощника.'));return;}
  for(const t of entries){const card=make('article','titan-card');const title=make('strong','',t.name);const linked=vault.entries.find(e=>e.id===t.entryId);const code=make('div','titan-code','••• •••');code.dataset.totpId=t.id;const progress=make('progress','titan-time');progress.max=t.period;progress.value=0;const time=make('span','titan-muted','');time.dataset.totpTime=t.id;const actions=make('div','titan-actions');const copy=make('button','btn secondary','Копировать');copy.type='button';copy.addEventListener('click',()=>{if(!vault||document.hidden)return;const current=code.dataset.code;if(current&&code.dataset.slot===String(Math.floor(Date.now()/1000/t.period)))copyToClipboard(current,'Код 2FA');else toast('Код обновляется. Нажми ещё раз.');});const remove=make('button','btn ghost','Удалить');remove.type='button';remove.addEventListener('click',async()=>{if(!vault||busy||!confirm('Удалить код только из BASTION? Сначала убедись, что есть другой способ входа в аккаунт.'))return;setBusy(true);try{await persistVault({...vault,totp:vault.totp.filter(x=>x.id!==t.id)});renderTotp();}catch(e){toast(e.message);}finally{setBusy(false);}});actions.append(copy,remove);card.append(title,make('span','titan-muted',linked?'Связь: '+linked.service:'Одноразовый код'),code,progress,time,actions);list.append(card);}refreshTotp();}
async function refreshTotp(){if(!vault||document.hidden||$('authPage').classList.contains('hidden'))return;const generation=totpGeneration;const now=Math.floor(Date.now()/1000);for(const node of $('totpList').querySelectorAll('[data-totp-id]')){const t=vault?.totp?.find(x=>x.id===node.dataset.totpId);if(!t)return;const slot=String(Math.floor(now/t.period));const left=t.period-now%t.period;node.nextElementSibling.value=left;node.nextElementSibling.nextElementSibling.textContent='Обновление через '+left+' сек.';if(node.dataset.slot===slot)continue;try{const code=await totpCode(t,now);if(!vault||document.hidden||generation!==totpGeneration)return;node.textContent=code.slice(0,Math.ceil(code.length/2))+' '+code.slice(Math.ceil(code.length/2));node.dataset.code=code;node.dataset.slot=slot;}catch{node.textContent='Ошибка';}}}
function acceptQr(raw){const parsed=parseTotp(raw);$('totpSecret').value=raw;if(parsed.name)$('totpName').value=parsed.name;$('qrStatus').textContent='QR распознан. Проверь название и сохрани код.';pilotHint();stopQr();}
async function photoQr(file){if(!vault||!file||file.size>15e6)return toast('Выбери изображение до 15 МБ.');const generation=++qrGeneration;let bitmap;try{bitmap=await createImageBitmap(file);if(bitmap.width*bitmap.height>25e6)throw new Error('Изображение слишком большое.');let raw;if(window.BarcodeDetector){try{const results=await new BarcodeDetector({formats:['qr_code']}).detect(bitmap);if(results.length===1)raw=results[0].rawValue;}catch{}}if(!raw&&typeof decodeCleanQR==='function')raw=decodeCleanQR(bitmap);if(!raw)throw new Error('QR не распознан. Обрежь скриншот до одного QR с белой рамкой или вставь ключ вручную.');if(vault&&$('totpDialog').open&&generation===qrGeneration)acceptQr(raw);}catch(e){if(generation===qrGeneration)$('qrStatus').textContent=e.message;}finally{bitmap?.close();}}
async function cameraQr(){if(!vault||!$('totpDialog').open)return;stopQr();const generation=qrGeneration;if(!window.BarcodeDetector||!navigator.mediaDevices?.getUserMedia){$('qrStatus').textContent='Камера-сканер не поддерживается браузером. Сделай скриншот QR, загрузи фото или вставь ключ вручную.';return;}try{const stream=await navigator.mediaDevices.getUserMedia({video:{facingMode:{ideal:'environment'}},audio:false});if(generation!==qrGeneration||!vault||!$('totpDialog').open){stream.getTracks().forEach(t=>t.stop());return;}qrStream=stream;const video=$('qrVideo');video.srcObject=stream;video.classList.remove('hidden');await video.play();const detector=new BarcodeDetector({formats:['qr_code']});async function scan(){if(generation!==qrGeneration||!vault)return;try{const results=await detector.detect(video);if(generation!==qrGeneration)return;if(results.length===1){acceptQr(results[0].rawValue);return;}}catch(e){if(generation===qrGeneration){stopQr();$('qrStatus').textContent='Не удалось распознать QR. Используй фото или ключ.';}return;}qrTimer=setTimeout(scan,250);}scan();}catch(e){if(generation===qrGeneration){stopQr();$('qrStatus').textContent='Камера недоступна. Проверь разрешения или вставь ключ вручную.';}}}
const SERVICES=[{name:'Google',url:'https://myaccount.google.com/security',auth:true,path:'Безопасность → Двухэтапная аутентификация → Authenticator.'},{name:'Instagram',url:'https://www.instagram.com/',auth:true,path:'Профиль → меню → Центр аккаунтов → Пароль и безопасность → Двухфакторная аутентификация → Приложение для аутентификации.'},{name:'VK',url:'https://id.vk.com/',auth:true,path:'VK ID → Безопасность и вход → Двухфакторная аутентификация. Если есть вариант приложения-аутентификатора, выбери его.'},{name:'Telegram',url:'https://telegram.org/',auth:false,path:'В приложении Telegram: Настройки → Конфиденциальность → Двухэтапная аутентификация. Настрой дополнительный пароль и почту восстановления; входные коды Telegram не являются TOTP.'},{name:'GitHub',url:'https://github.com/settings/security',auth:true,path:'Settings → Password and authentication → Two-factor authentication → Authenticator app.'},{name:'Apple Account',url:'https://account.apple.com/',auth:false,path:'В настройках iPhone: Apple Account → Вход и безопасность → Двухфакторная аутентификация. Apple использует доверенные устройства, а не обычный TOTP.'}];
function renderConnect(){const list=$('connectList');list.replaceChildren();if(!vault)return;for(const service of SERVICES){const card=make('article','titan-card');const matching=vault.entries.filter(e=>e.service.toLowerCase().includes(service.name.toLowerCase()));const linked=(vault.totp||[]).filter(t=>matching.some(e=>e.id===t.entryId));card.append(make('strong','',service.name),make('span','titan-muted',`Записей: ${matching.length} · связанных 2FA: ${linked.length}. Защита на сайте не проверена.`));const btn=make('button','btn secondary','Настроить с помощником');btn.type='button';btn.addEventListener('click',()=>openPilot('auth',service.name));card.append(btn);list.append(card);}}
function openPilot(mode='auth',service='Google'){if(!vault||busy)return;pilotMode=mode;pilotStep=0;const sel=$('pilotService');sel.replaceChildren();for(const s of SERVICES)sel.add(new Option(s.name,s.name));sel.value=service;sel.classList.toggle('hidden',mode!=='auth');sel.previousElementSibling.classList.toggle('hidden',mode!=='auth');$('pilotDialog').showModal();renderPilot();}
function renderPilot(){const s=SERVICES.find(x=>x.name===$('pilotService').value)||SERVICES[0];const steps=pilotMode==='settings'?[['Резервная копия','Открой настройки и нажми «Экспорт зашифрованной копии». Сохрани файл в «Файлы». Не отправляй его в GitHub.'],['Биометрия','В настройках нажми «Настроить Face ID / Touch ID / код устройства», введи мастер-пароль, затем создай ключ доступа.'],['Проверка входа','Нажми «Проверить быстрый вход». Сейф закроется. Используй кнопку биометрии; мастер-пароль остаётся запасным способом.']]:[['Открой настройки сервиса',s.path+' Названия пунктов могут отличаться в твоей версии приложения.'],[s.auth?'Подготовь секретный ключ':'Настрой защиту в сервисе',s.auth?'Выбери приложение-аутентификатор. На одном телефоне удобнее скопировать ключ настройки или сделать скриншот QR. Не делись этим ключом.':'Выполни шаги в самом сервисе. BASTION не может получить доступ к его настройкам.'],[s.auth?'Добавь ключ в BASTION':'Сохрани запись',s.auth?'Нажми кнопку ниже. Помощник подсветит нужные поля. После сохранения введи код в сервисе и удали скриншот QR.':'Нажми кнопку ниже, чтобы открыть редактор записи. Не сохраняй непроверенный новый пароль.']];const step=steps[pilotStep];$('pilotProgress').textContent=`Шаг ${pilotStep+1} из ${steps.length}`;$('pilotTitle').textContent=step[0];$('pilotText').textContent=step[1];$('pilotLink').classList.toggle('hidden',pilotMode!=='auth'||pilotStep!==0);$('pilotLink').href=s.url;$('pilotBack').disabled=pilotStep===0;$('pilotAction').textContent=pilotStep===steps.length-1?(pilotMode==='settings'?'Открыть настройки':s.auth?'Добавить 2FA':'Открыть редактор'):'Далее';}
function advancePilot(){if(!vault)return;if(pilotStep<2){++pilotStep;renderPilot();return;}const s=SERVICES.find(x=>x.name===$('pilotService').value)||SERVICES[0];$('pilotDialog').close();if(pilotMode==='settings'){selectTab('settings');startSettingsPilot();return;}if(s.auth){selectTab('auth');openTotp(s.name,true);}else{selectTab('vault');openEditor();$('service').value=s.name;startEditorPilot();}}
function attachTitan(){attachReauth();attachExtraPilot();
  $('addTotp').onclick=()=>openTotp();$('authPilot').onclick=()=>openPilot();$('pilotStart').onclick=()=>openPilot();$('settingsPilot').onclick=()=>openPilot('settings');$('pilotClose').onclick=()=>$('pilotDialog').close();$('pilotService').onchange=()=>{pilotStep=0;renderPilot();};$('pilotBack').onclick=()=>{if(pilotStep){--pilotStep;renderPilot();}};$('pilotAction').onclick=advancePilot;
  $('totpClose').onclick=()=>$('totpDialog').close();$('totpDialog').addEventListener('close',()=>{clearTotpForm();pilotActive=false;});$('totpForm').addEventListener('submit',saveTotp);$('totpName').addEventListener('input',pilotHint);$('totpSecret').addEventListener('input',pilotHint);$('qrPhoto').onclick=()=>$('qrFile').click();$('qrFile').onchange=()=>{const file=$('qrFile').files?.[0];$('qrFile').value='';if(file)photoQr(file);};$('qrCamera').onclick=cameraQr;
  $('bioTestBtn').onclick=()=>{if(!vault||busy)return;if(!bioConfig())return toast('Сначала настрой быстрый вход.');lockVault(false);toast('Нажми кнопку биометрии, чтобы проверить вход.');};
  setInterval(refreshTotp,500);document.addEventListener('visibilitychange',()=>{if(document.hidden)stopQr();});
}

let editorGuide=false,settingsGuideStep=-1;
function clearEditorPilot(){editorGuide=false;$('editorHint').classList.add('hidden');$('editor').querySelectorAll('.pilot-highlight').forEach(x=>x.classList.remove('pilot-highlight'));}
function updateEditorPilot(){if(!editorGuide)return;const steps=[['service','1. Введи название сайта или приложения.'],['login','2. Введи логин или почту. Если их нет, можно оставить поле пустым.'],['secret','3. Вставь действующий пароль. Для нового аккаунта можно нажать «Генерировать», затем установить пароль в сервисе.'],['siteUrl','4. При желании добавь HTTPS-адрес.'],['notes','5. При желании добавь заметку.'],['saveEntry','6. Нажми «Сохранить». Запись будет зашифрована.']];const current=editorGuide-1;const [id,msg]=steps[current];$('editor').querySelectorAll('.pilot-highlight').forEach(x=>x.classList.remove('pilot-highlight'));$(id).classList.add('pilot-highlight');$('editorHint').replaceChildren(make('span','',msg));if(current<steps.length-1){const b=make('button','btn secondary small','Далее');b.type='button';b.onclick=()=>{editorGuide++;updateEditorPilot();};$('editorHint').append(b);} $('editorHint').classList.remove('hidden');$(id).scrollIntoView({block:'nearest'});}
function startEditorPilot(){editorGuide=1;updateEditorPilot();}
function clearSettingsPilot(){settingsGuideStep=-1;$('settingsHint').classList.add('hidden');$('settingsPage').querySelectorAll('.pilot-highlight').forEach(x=>x.classList.remove('pilot-highlight'));}
function startSettingsPilot(){settingsGuideStep=0;updateSettingsPilot();}
function updateSettingsPilot(){if(settingsGuideStep<0)return;const steps=[['exportBtn','1. Нажми подсвеченную кнопку, подтверди личность и сохрани копию в «Файлы». Затем вернись сюда.'],['bioSetupBtn','2. Нажми подсвеченную кнопку, введи мастер-пароль и создай ключ доступа. Если уже настроено, можно пропустить.'],['idleLockSelect','3. Выбери время автоблокировки. Рекомендуем 1 или 5 минут.'],['bioTestBtn','4. Проверь быстрый вход. Сейф заблокируется, а ты сможешь войти с помощью биометрии или мастер-пароля.']];$('settingsPage').querySelectorAll('.pilot-highlight').forEach(x=>x.classList.remove('pilot-highlight'));const [id,msg]=steps[settingsGuideStep];$(id).classList.add('pilot-highlight');const hint=$('settingsHint');hint.replaceChildren(make('span','',msg));if(settingsGuideStep<3){const btn=make('button','btn secondary small','Далее');btn.type='button';btn.onclick=()=>{settingsGuideStep++;updateSettingsPilot();};hint.append(btn);}hint.classList.remove('hidden');$(id).scrollIntoView({block:'nearest'});}
function attachExtraPilot(){$('editorPilot').onclick=startEditorPilot;$('editor').addEventListener('close',clearEditorPilot);}
let reauthAction='',reauthOK=0,reauthEpoch=0;
function clearReauth(){++reauthEpoch;reauthAction='';reauthOK=0;$('reauthMaster').value='';$('reauthContinue').classList.add('hidden');if($('reauthDialog').open)$('reauthDialog').close();}
function openReauth(action){if(!vault||busy)return;clearReauth();reauthAction=action;$('reauthMessage').textContent=action==='export'?'Подтверди личность для экспорта зашифрованной копии.':'Подтверди личность для смены мастер-пароля.';$('reauthBio').classList.toggle('hidden',!bioAvailable()||!bioConfig());$('reauthDialog').showModal();}
function approveReauth(epoch){if(epoch!==reauthEpoch||!vault||document.hidden||!$('reauthDialog').open)return;reauthOK=Date.now();$('reauthMessage').textContent='Личность подтверждена. Нажми «Продолжить» в течение 30 секунд.';$('reauthContinue').classList.remove('hidden');}
async function reauthMaster(e){e.preventDefault();if(!vault||busy)return;const pass=$('reauthMaster').value;$('reauthMaster').value='';const epoch=reauthEpoch;setBusy(true,$('reauthVerify'));try{await decryptEnvelope(envelope,pass);approveReauth(epoch);}catch{toast('Мастер-пароль не подошёл.');}finally{setBusy(false,$('reauthVerify'));}}
async function reauthBio(){if(!vault||busy||!bioAvailable())return;const cfg=bioConfig(),epoch=reauthEpoch;if(!cfg||cfg.vaultSalt!==envelope.salt)return toast('Используй мастер-пароль.');setBusy(true,$('reauthBio'));try{const assertion=await navigator.credentials.get({publicKey:{challenge:randomBytes(32),allowCredentials:[{type:'public-key',id:bytesFromBase64(cfg.credential)}],userVerification:'required',timeout:60000,extensions:{prf:{eval:{first:bytesFromBase64(cfg.salt)}}}}});const secret=assertion?.getClientExtensionResults()?.prf?.results?.first;if(!secret)throw Error('PRF unavailable');const wrapping=await prfAes(secret);const raw=await crypto.subtle.decrypt({name:'AES-GCM',iv:bytesFromBase64(cfg.iv)},wrapping,bytesFromBase64(cfg.data));if(epoch!==reauthEpoch||!vault)return;await decryptEnvelope(envelope,new TextDecoder().decode(raw));approveReauth(epoch);}catch{toast('Не удалось подтвердить биометрию. Используй мастер-пароль.');}finally{setBusy(false,$('reauthBio'));}}
function attachReauth(){$('reauthClose').onclick=clearReauth;$('reauthDialog').addEventListener('close',()=>{if(!$('reauthDialog').open){++reauthEpoch;reauthOK=0;reauthAction='';$('reauthMaster').value='';}});$('reauthForm').addEventListener('submit',reauthMaster);$('reauthBio').onclick=reauthBio;$('reauthContinue').onclick=()=>{if(!vault||busy||!reauthOK||Date.now()-reauthOK>30000)return toast('Подтверди личность ещё раз.');const action=reauthAction;clearReauth();if(action==='export')downloadBackup();else if(action==='master')$('masterDialog').showModal();};}
init();
