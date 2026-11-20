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
const IDLE_LOCK_MS = 5 * 60_000;
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
  await writeEncrypted(updated);
  envelope = updated;
  vault = nextVault;
}
function showGate(mode) {
  $('gate').classList.toggle('hidden', !$('languageSetup').classList.contains('hidden'));
  $('app').classList.add('hidden');
  $('lockBtn').classList.add('hidden');
  $('createView').classList.toggle('hidden', mode !== 'create');
  $('unlockView').classList.toggle('hidden', mode !== 'unlock');
}
function showApp() {
  $('gate').classList.add('hidden');
  $('app').classList.toggle('hidden', !$('languageSetup').classList.contains('hidden'));
  $('lockBtn').classList.remove('hidden');
  $('search').value = '';
  lastActivity = Date.now();
  renderEntries();
  bioUi();
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
  closeDialogs();
  $('entryList').replaceChildren();
  $('auditPanel').replaceChildren();
  $('auditPanel').classList.add('hidden');
  $('search').value = '';
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
  const filtered = [...vault.entries].filter(item => `${item.service} ${item.login}`.toLocaleLowerCase('ru').includes(needle))
    .sort((a,b) => a.service.localeCompare(b.service, 'ru'));
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
    const copy = make('button','btn secondary small','Копия');
    copy.type = 'button'; copy.title = 'Копировать пароль';
    copy.addEventListener('click', () => copyToClipboard(item.password,'Пароль'));
    const edit = make('button','btn ghost small','Открыть');
    edit.type = 'button'; edit.addEventListener('click', () => openEditor(item.id));
    actions.append(copy,edit); row.append(mark,body,actions);root.append(row);
    translateNode(actions);
  }
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
  p.classList.toggle('hidden');
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
  const entry = {id: old?.id || crypto.randomUUID(),service,login,password,url,notes,createdAt:old?.createdAt || now,updatedAt:now};
  const nextEntries = old ? vault.entries.map(x=>x.id===old.id?entry:x) : [...vault.entries,entry];
  setBusy(true,$('saveEntry'));
  try {
    await persistVault({schema:1,entries:nextEntries});
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
    await persistVault({schema:1,entries:vault.entries.filter(e=>e.id!==editingId)});
    $('editor').close();$('secret').value='';renderEntries();toast('Запись удалена.');
  }catch(e){toast(e.message||'Ошибка удаления.');}finally{setBusy(false);}
}
function downloadBackup() {
  if (!envelope) return;
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
  $('bioUnlockBtn').classList.toggle('hidden', !has || !bioAvailable());
  $('bioSetupBtn').classList.toggle('hidden', !bioAvailable());
  $('bioRemoveBtn').classList.toggle('hidden', !has);
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
    const stored=await readEncrypted();
    if (!stored || stored.salt!==config.vaultSalt) throw new Error('Мастер-пароль или сейф изменён. Используй мастер-пароль и настрой Face ID заново.');
    const assertion=await navigator.credentials.get({publicKey:{challenge:randomBytes(32),allowCredentials:[{type:'public-key',id:bytesFromBase64(config.credential)}],userVerification:'required',timeout:60000,extensions:{prf:{eval:{first:bytesFromBase64(config.salt)}}}}});
    const secret=assertion?.getClientExtensionResults()?.prf?.results?.first;
    if (!secret) throw new Error('Safari не вернул ключ PRF. Разблокируй мастер-паролем.');
    const wrappingKey=await prfAes(secret);
    const raw=await crypto.subtle.decrypt({name:'AES-GCM',iv:bytesFromBase64(config.iv)},wrappingKey,bytesFromBase64(config.data));
    const master=new TextDecoder().decode(raw);
    const result=await decryptEnvelope(stored,master);
    vault=result.decoded;key=result.newKey;envelope=stored;showApp();toast('Сейф открыт.');
  } catch(e) {toast(e.message || 'Face ID недоступен. Используй мастер-пароль.');}
  finally {busy=false;$('bioUnlockBtn').disabled=false;}
}

function attachHandlers() {
  $('bioUnlockBtn').addEventListener('click',unlockBiometric);
  $('bioSetupBtn').addEventListener('click',setupBiometric);
  $('bioVerifyForm').addEventListener('submit',verifyBioMaster);
  $('bioActionBtn').addEventListener('click',performBioSetup);
  $('bioCancelBtn').addEventListener('click',()=>{$('bioDialog').close();resetBioSetup();});
  $('bioDialog').addEventListener('close',resetBioSetup);
  $('bioRemoveBtn').addEventListener('click',()=>{localStorage.removeItem(BIO_STORAGE);bioUi();toast('Быстрая разблокировка отключена.');});
  $('createForm').addEventListener('submit',onCreate);
  $('unlockForm').addEventListener('submit',onUnlock);
  $('editorForm').addEventListener('submit',onSaveEntry);
  $('importForm').addEventListener('submit',onImport);
  $('masterForm').addEventListener('submit',onChangeMaster);
  $('lockBtn').addEventListener('click',()=>lockVault());
  $('addBtn').addEventListener('click',()=>openEditor());
  $('search').addEventListener('input',renderEntries);
  $('auditBtn').addEventListener('click',renderAudit);
  $('exportBtn').addEventListener('click',downloadBackup);
  $('importFile').addEventListener('change',prepareImport);
  $('changeMasterBtn').addEventListener('click',()=>$('masterDialog').showModal());
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
  setInterval(()=>{if(vault && !document.hidden && Date.now()-lastActivity>=IDLE_LOCK_MS)lockVault();},10_000);
}
async function init() {
  attachHandlers();
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

init();
