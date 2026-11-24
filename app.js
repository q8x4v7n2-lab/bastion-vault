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
let backgroundLockPending=false;
let toastTimer;

function toast(message) {
  const node = $('toast');
  node.textContent = message;
  node.classList.remove('hidden');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => node.classList.add('hidden'), 4100);
}
function setBusy(value, button) {
  busy = value;
  if (button) button.disabled = value;
  if (!value && vault && (document.hidden||backgroundLockPending)) lockVault(false);
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
  if(value.oneProgress!==undefined&&(!value.oneProgress||typeof value.oneProgress.id!=='string'||value.oneProgress.id.length>70||![0,1,2,3].includes(value.oneProgress.step)))return false;
  if (!validEvolution(value)) return false;
  if (value.totp !== undefined && (!Array.isArray(value.totp) || value.totp.length > 2000 || !value.totp.every(validTotp) || new Set(value.totp.map(t=>t.id)).size !== value.totp.length)) return false;
  const ids = new Set();
  return value.entries.every(e => {
    if (!e || typeof e.id !== 'string' || ids.has(e.id)) return false;
    ids.add(e.id);
    if(e.recovery!==undefined&&(!e.recovery||typeof e.recovery.email!=='string'||e.recovery.email.length>254||typeof e.recovery.phone!=='string'||e.recovery.phone.length>40||!['','Google','Apple','VK','Microsoft','Другое'].includes(e.recovery.provider)))return false;
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
    request.onblocked = () => reject(new Error(translateText("Другая вкладка блокирует базу.")));
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
function writeEncrypted(value, expected) {
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE_NAME, 'readwrite');
    const store=tx.objectStore(STORE_NAME);
    if(expected!==undefined){const request=store.get(RECORD_ID);request.onsuccess=()=>{if(expected===null?!!request.result:(request.result?.data!==expected.data||request.result?.iv!==expected.iv)){tx.abort();return;}store.put(value,RECORD_ID);};}else store.put(value,RECORD_ID);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
    tx.onabort = () => reject(tx.error || new Error(translateText("Не удалось сохранить данные.")));
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
  if (!validEnvelope(record)) throw new Error(translateText("Неподдерживаемый или повреждённый формат копии."));
  const newKey = await deriveKey(master, bytesFromBase64(record.salt), record.iterations);
  let plaintext;
  try { plaintext = await crypto.subtle.decrypt({name:'AES-GCM', iv:bytesFromBase64(record.iv), additionalData:AAD, tagLength:128}, newKey, bytesFromBase64(record.data)); }
  catch { throw new Error(translateText("Неверный пароль либо повреждённые данные.")); }
  let decoded;
  try { decoded = JSON.parse(new TextDecoder('utf-8', {fatal:true}).decode(plaintext)); }
  catch { throw new Error(translateText("Повреждённое содержимое сейфа.")); }
  if (!validVault(decoded)) throw new Error(translateText("Повреждённые или несовместимые записи."));
  return {decoded, newKey};
}
async function persistVault(nextVault) {
  if (!key || !envelope) throw new Error(translateText("Сейф заблокирован."));
  if(!validVault(nextVault))throw Error(translateText("Несовместимые данные или превышен лимит."));
  nextVault = evolveHistory(vault, nextVault);
  if(!validVault(nextVault))throw Error(translateText("Несовместимая история."));
  const updated = await encryptVault(nextVault, key, bytesFromBase64(envelope.salt));
  if(!validEnvelope(updated))throw new Error(translateText("Сейф превышает допустимый размер."));
  await writeEncrypted(updated, envelope);
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
  window.bastionHasVault=true;
  if(document.hidden){lockVault(false);return;}
  $('gate').classList.add('hidden');
  $('app').classList.toggle('hidden', !$('languageSetup').classList.contains('hidden'));
  $('lockBtn').classList.remove('hidden');
  $('search').value = '';
  $('favoritesOnly').checked=false;
  $('vaultKindFilter').value='all';
  lastActivity = Date.now();
  renderEntries();
  bioUi();
  selectTab('home');
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
  cancelAutoRequest();
  if ($('onePicker').open) $('onePicker').close();
  $('onePickerList').replaceChildren(); $('homeSearch').value='';
  resetBioSetup();
  clearTitan();
  clearInfinity();
  clearEvolution();
  closeDialogs();
  $('entryList').replaceChildren();
  $('auditPanel').replaceChildren();
  $('auditPanel').classList.add('hidden');
  $('search').value = '';
  for (const id of ['service','login','notes','siteUrl','generatedOutput']) $(id).value='';
  $('entryHistory').textContent='';
  backgroundLockPending=false;document.documentElement.classList.remove('privacy-locked');
  vault = null;
  key = null;
  editingId = null;
  envelope = null;
  showGate('unlock');
  bioUi();
  if (showMessage) toast(translateText("Сейф заблокирован."));
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
    toast(formatText("{0} скопирован. Буфер обмена доступен другим приложениям.",[what]));
  } catch { toast(translateText("Копирование не удалось: попробуй Safari по HTTPS.")); }
}
function ensureHttps(raw) {
  if (!raw.trim()) return '';
  const parsed = new URL(raw.trim());
  if (parsed.protocol !== 'https:' || !parsed.hostname || parsed.username || parsed.password) throw new Error(translateText("Разрешены только HTTPS-ссылки без логина в адресе."));
  return parsed.href;
}
function renderEntries() {
  if (!vault) return;
  $('count').textContent = String(vault.entries.length);
  refreshHome();
  const root = $('entryList');
  root.replaceChildren();
  const needle = $('search').value.trim().toLocaleLowerCase('ru');
  const onlyFavorites = $('favoritesOnly').checked;
  const kindFilter=$('vaultKindFilter').value;
  const filtered = [...vault.entries].filter(item => `${item.service} ${item.ghost?'':item.login}`.toLocaleLowerCase('ru').includes(needle) && (!onlyFavorites || item.favorite === true) && (kindFilter==='all'||(item.kind||'login')===kindFilter))
    .sort((a,b) => Number(b.favorite === true)-Number(a.favorite === true) || a.service.localeCompare(b.service, uiLanguage));
  if (filtered.length === 0) {
    const empty = make('div','empty');
    empty.append(make('strong','',vault.entries.length ? translateText("Ничего не найдено") : translateText("Здесь появятся твои аккаунты")));
    empty.append(document.createTextNode(vault.entries.length ? translateText("Попробуй другой запрос.") : translateText("Нажми «Добавить запись», чтобы создать первую зашифрованную запись.")));
    root.append(empty);  return;
  }
  for (const item of filtered) {
    const row = make('article','entry');
    const mark = make('div','entry-mark',getInitial(item.service));
    const body = make('div','entry-body');
    body.append(make('div','entry-title',item.service+(item.ghost?' · 🔒':'')+(item.kind&&item.kind!=='login'?' · '+translateText(EVO_KINDS[item.kind][0]):'')));
    body.append(make('div','entry-login',item.ghost?translateText("Скрытая запись"):(item.login || translateText("Логин не указан"))));
    const actions = make('div','entry-buttons');
    const star = make('button','btn ghost small favorite-btn',item.favorite === true ? '★' : '☆');
    star.type = 'button'; star.title = item.favorite === true ? translateText(translateText("Убрать из избранного")) : translateText(translateText("В избранное"));
    star.setAttribute('aria-label', star.title);
    star.setAttribute('aria-pressed',String(item.favorite === true));
    star.addEventListener('click',()=>toggleFavorite(item.id));
    const loginCopy = make('button','btn ghost small','@');
    loginCopy.type='button';loginCopy.title=translateText(translateText("Копировать логин"));loginCopy.setAttribute('aria-label',loginCopy.title);
    loginCopy.disabled=!item.login;
    loginCopy.addEventListener('click',()=>ghostCopy(item.id,'login'));
    const copy = make('button','btn secondary small',translateText("Копия"));
    copy.type = 'button'; copy.title = translateText("Копировать пароль");
    copy.addEventListener('click', () => ghostCopy(item.id,'password'));
    const edit = make('button','btn ghost small',translateText("Открыть"));
    edit.type = 'button'; edit.addEventListener('click', () => openEditor(item.id));
    const one=infButton(translateText("Войти"),()=>openOne(item.id),"ghost small");one.classList.toggle('hidden',!!item.kind&&item.kind!=="login"); actions.append(star,loginCopy,copy,edit,one); row.append(mark,body,actions);root.append(row);
    
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
  } catch(e) {toast(localizedError(e)||translateText("Не удалось сохранить избранное."));}
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
    throw new Error(translateText("Длина пароля должна быть от 12 до 128 символов."));
  }
  const groups = ['abcdefghijkmnopqrstuvwxyz','ABCDEFGHJKLMNPQRSTUVWXYZ','23456789'];
  if (allowSymbols) groups.push('!@#$%^&*()-_=+[]{}?');
  const all = groups.join('');
  const chars = groups.map(group => group[randomIndex(group.length)]);
  while (chars.length < len) chars.push(all[randomIndex(all.length)]);
  for (let i=chars.length-1;i>0;i--) {const j=randomIndex(i+1);[chars[i],chars[j]]=[chars[j],chars[i]];}
  return chars.join('');
}
function openEditor(id = null, approved = false) {
  if (!vault || busy) return;
  if(id && !approved && protectedEntry(id)) return ghostAuthorize(()=>openEditor(id,true));
  clearEditorPilot();
  editingId = id;
  const item = id ? vault.entries.find(e => e.id === id) : null;
  $('editorTitle').textContent = item ? translateText("Изменить запись") : translateText("Новая запись");
  $('deleteEntry').classList.toggle('hidden', !item);
  $('service').value = item?.service ?? '';
  $('login').value = item?.login ?? '';
  $('secret').value = item?.password ?? '';
  $('secret').type = 'password';
  $('showSecret').textContent = translateText(translateText("Показать"));
  $('siteUrl').value = item?.url ?? '';
  $('notes').value = item?.notes ?? '';
  $('entryKind').value=item?.kind||'login'; $('entryGhost').checked=!!item?.ghost; applyEntryKind();
  const fmt = date => {if(!date)return '—';const d=new Date(date);return Number.isNaN(d.valueOf())?'—':new Intl.DateTimeFormat(uiLanguage,{dateStyle:'medium',timeStyle:'short'}).format(d);};
  $('entryHistory').classList.toggle('hidden',!item);
  $('entryHistory').textContent = item ? (translateText(translateText("Создано"))+': '+fmt(item.createdAt)+'  •  '+translateText(translateText("Изменено"))+': '+fmt(item.updatedAt)) : '';
  
  $('editor').showModal();
}
function renderAudit() {
  if (!vault) return;
  const p = $('auditPanel');
  p.replaceChildren();
  const passwords=vault.entries.filter(e=>!e.kind||e.kind==='login');
  const counts = new Map();
  for (const e of passwords) if (e.password) counts.set(e.password,(counts.get(e.password)||0)+1);
  const reused = passwords.filter(e => e.password && counts.get(e.password)>1).length;
  const short = passwords.filter(e => e.password.length < 14).length;
  const empty = passwords.filter(e => !e.password).length;
  const common = new Set(['password','password123','123456','12345678','qwerty','qwerty123','admin','111111','letmein']);
  const obvious = passwords.filter(e => common.has(e.password.toLowerCase())).length;
  const line1 = make('div','', translateText("Локальная проверка: "));
  line1.append(make('strong','',String(passwords.length) + translateText(" записей")));
  const line2 = make('div', reused ? 'bad':'', formatText("Повторяющиеся пароли: {0} записей",[reused]));
  const line3 = make('div', short ? 'bad':'', formatText("Пароли короче 14 символов: {0}",[short]));
  const hint = make('div','', translateText("Это базовая проверка, не доказательство стойкости. Никакие пароли никуда не отправляются."));
  const line4 = make('div', obvious ? 'bad':'', formatText("Известные простые пароли: {0}",[obvious]));
  const line5 = make('div', empty ? 'bad':'', formatText("Пустые пароли: {0}",[empty]));
  p.append(line1,line2,line3,line4,line5,hint);
  p.classList.remove('hidden');
  
}
async function onCreate(event) {
  event.preventDefault(); if (busy) return;
  const first = $('newMaster').value;
  const again = $('confirmMaster').value;
  if (first.length < 16) return toast(translateText("Нужно минимум 16 символов для мастер-пароля."));
  if (first !== again) return toast(translateText("Мастер-пароли не совпадают."));
  setBusy(true,$('createBtn'));
  try {
    if (await readEncrypted()) throw new Error(translateText("Сейф уже создан; перезагрузи приложение."));
    const salt = randomBytes(16);
    const newKey = await deriveKey(first,salt);
    const data = {schema:1,entries:[]};
    const record = await encryptVault(data,newKey,salt);
    await writeEncrypted(record, null);
    key = newKey;vault = data;envelope = record;
    $('newMaster').value = ''; $('confirmMaster').value = '';
    showApp(); toast(translateText("Сейф создан. Сделай резервную копию после добавления записей."));
  } catch(e) {toast(localizedError(e) || translateText("Ошибка создания сейфа."));}
  finally {setBusy(false,$('createBtn'));}
}
async function onUnlock(event) {
  event.preventDefault(); if (busy) return;
  const pass = $('unlockMaster').value;
  $('unlockMaster').value = '';
  setBusy(true,$('unlockBtn'));
  try {
    const record = await readEncrypted();
    if (!record) throw new Error(translateText("Сейф не найден. Перезапусти приложение."));
    const result = await decryptEnvelope(record,pass);
    vault = result.decoded;key = result.newKey;envelope = record;
    showApp(); toast(translateText("Сейф открыт."));
  } catch(e) {toast(localizedError(e) || translateText("Ошибка разблокировки."));}
  finally {setBusy(false,$('unlockBtn'));}
}
async function onSaveEntry(event) {
  event.preventDefault(); if (!vault || busy) return;
  const service = $('service').value.trim();
  const login = $('login').value.trim();
  const password = $('secret').value;
  const notes = $('notes').value;
  if (!service) return toast(translateText("Укажи название сервиса."));
  if (!password && $('entryKind').value==='login') return toast(translateText("Укажи пароль или сгенерируй его."));
  if (!password && !notes && !login) return toast(translateText("Заполни хотя бы одно поле."));
  if (password.length > 1024 || service.length > 100 || login.length > 200 || notes.length > 3000)
    return toast(translateText("Одно из полей превышает допустимую длину."));
  let url;
  try { url = ensureHttps($('siteUrl').value); if (url.length > 1000) throw new Error(translateText("Ссылка слишком длинная.")); }
  catch(e) {return toast(localizedError(e));}
  const now = new Date().toISOString();
  const old = editingId ? vault.entries.find(x => x.id === editingId) : null;
  if (editingId && !old) return toast(translateText("Запись не найдена."));
  const entry = {...(old||{}),id: old?.id || crypto.randomUUID(),service,login,password,url,notes,kind:$('entryKind').value,ghost:$('entryGhost').checked,createdAt:old?.createdAt || now,updatedAt:now};
  const nextEntries = old ? vault.entries.map(x=>x.id===old.id?entry:x) : [...vault.entries,entry];
  setBusy(true,$('saveEntry'));
  try {
    await persistVault({...vault,entries:nextEntries});
    $('editor').close(); $('secret').value = '';
    renderEntries(); $('auditPanel').classList.add('hidden');
    toast(translateText("Запись зашифрована и сохранена на устройстве."));
  } catch(e) {toast(translateText("Не удалось сохранить запись: ")+ (localizedError(e)||translateText("ошибка хранилища")));}
  finally {setBusy(false,$('saveEntry'));}
}
async function deleteEditingEntry() {
  if (!vault || !editingId || busy) return;
  const entry = vault.entries.find(e => e.id === editingId);
  if (!entry || !confirm(formatText("Удалить «{0}»? {1}",[entry.service,historyDays(vault)?translateText("Запись попадёт в историю на установленный срок."):translateText("История выключена; восстановление только из копии.")]))) return;
  setBusy(true);
  try {
    await persistVault({...vault,entries:vault.entries.filter(e=>e.id!==editingId),totp:(vault.totp||[]).map(t=>t.entryId===entry.id&&entry.ghost?{...t,ghost:true}:t)});
    $('editor').close();$('secret').value='';renderEntries();toast(translateText("Запись удалена."));
  }catch(e){toast(localizedError(e)||translateText("Ошибка удаления."));}finally{setBusy(false);}
}
function downloadBackup() {
  if (!envelope || !vault || busy) return;
  const blob = new Blob([JSON.stringify(envelope,null,2)], {type:'application/json'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href=url;a.download=`BASTION-encrypted-${new Date().toISOString().slice(0,10)}.json`;
  document.body.append(a);a.click();a.remove();
  setTimeout(()=>URL.revokeObjectURL(url),30_000);
  toast(translateText("Создан файл только с зашифрованными данными. Сохрани в надёжном месте."));
}
async function prepareImport(event) {
  const file = event.target.files?.[0];
  event.target.value = '';
  if (!file) return;
  if (file.size > MAX_BACKUP_BYTES) return toast(translateText("Файл слишком большой для этой версии."));
  try {
    const record = JSON.parse(await file.text());
    if (!validEnvelope(record)) throw new Error(translateText("Это не поддерживаемая копия BASTION VAULT."));
    pendingImport = record;
    $('importMaster').value = '';
    $('importDialog').showModal();
  } catch(e) { toast(localizedError(e) || translateText("Не удалось открыть файл.")); }
}
async function onImport(event) {
  event.preventDefault();if (busy || !pendingImport) return;
  const pass = $('importMaster').value;
  $('importMaster').value='';
  setBusy(true,$('confirmImport'));
  try {
    const result = await decryptEnvelope(pendingImport,pass);
    const current = await readEncrypted();
    if(current&&!vault)throw new Error(translateText("Сначала разблокируй текущий сейф."));
    if (current && !confirm(translateText("Заменить весь текущий сейф импортированной копией? Убедись, что сохранил прежнюю резервную копию."))) return;
    await writeEncrypted(pendingImport,current);
    if(current?.salt !== pendingImport.salt) localStorage.removeItem(BIO_STORAGE);
    closeDialogs();
    vault=result.decoded;key=result.newKey;envelope=await readEncrypted();
    showApp();toast(translateText("Зашифрованная копия успешно восстановлена."));
  } catch(e) {toast(localizedError(e)||translateText("Ошибка импорта."));}
  finally {setBusy(false,$('confirmImport'));}
}
async function onChangeMaster(event) {
  event.preventDefault();if (busy || !vault) return;
  const first=$('masterNew').value, second=$('masterConfirm').value;
  if(first.length<16)return toast(translateText("Нужно минимум 16 символов."));
  if(first!==second)return toast(translateText("Новые мастер-пароли не совпадают."));
  setBusy(true,$('confirmMasterChange'));
  try {
    const salt=randomBytes(16);
    const nextKey=await deriveKey(first,salt);
    const nextRecord=await encryptVault(vault,nextKey,salt);
    await writeEncrypted(nextRecord, envelope);
    key=nextKey;envelope=nextRecord;localStorage.removeItem(BIO_STORAGE);bioUi();
    $('masterDialog').close();$('masterNew').value='';$('masterConfirm').value='';
    toast(translateText("Мастер-пароль заменён. Скачай новую резервную копию."));
  }catch(e){toast(localizedError(e)||translateText("Не удалось сменить пароль."));}
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
  if(status) status.textContent = translateText(!available
    ? translateText("Быстрый вход недоступен в этом браузере. Используйте установленное приложение и мастер-пароль.")
    : has ? translateText("Ключ доступа найден. Проверьте быстрый вход: Face ID, Touch ID или код устройства.")
          : translateText("Быстрый вход ещё не настроен. Нажмите кнопку настройки биометрии."));
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
  $('bioActionBtn').textContent = translateText(translateText("Продолжить настройку Face ID"));
}
function bioFocusReady() {
  if (document.visibilityState !== 'visible' || !document.hasFocus()) {
    toast(translateText("Safari неактивен. Вернись на вкладку и нажми кнопку ещё раз."));
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
    if (!stored) throw new Error(translateText("Сейф не найден."));
    await decryptEnvelope(stored, candidate);
    setupMaster = candidate;
    setupStoredSalt = stored.salt;
    setupSalt = randomBytes(32);
    $('bioActionBtn').classList.remove('hidden');
    $('bioActionBtn').textContent = translateText(translateText("Создать ключ доступа"));
    toast(translateText("Пароль подтверждён. Теперь нажми «Создать ключ доступа»."));
  } catch(e) {
    resetBioSetup();
    toast(localizedError(e) || translateText("Пароль не подошёл."));
  } finally { setBusy(false, $('bioVerifyBtn')); }
}
async function completeBioSetup(prfOutput) {
  if (!prfOutput || prfOutput.byteLength !== 32) throw new Error(translateText("Safari не вернул секрет PRF. Face ID не включён."));
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
  toast(translateText("Ключ доступа настроен. Проверь разблокировку после блокировки сейфа."));
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
  } catch(e) {toast(localizedError(e) || translateText("Не удалось запустить Face ID."));return;}
  busy = true;
  $('bioActionBtn').disabled = true;
  try {
    const result = await operation;
    if (!result) throw new Error(translateText("Ключ доступа не создан."));
    if (!setupCredential) setupCredential = result.rawId;
    const prf = result.getClientExtensionResults()?.prf?.results?.first;
    if (prf) await completeBioSetup(prf);
    else if ($('bioActionBtn').textContent === translateText(translateText("Создать ключ доступа"))) {
      $('bioActionBtn').textContent = translateText(translateText("Завершить настройку Face ID"));
      toast(translateText("Ключ создан. Нажми «Завершить настройку Face ID»."));
    } else throw new Error(translateText("WebAuthn PRF не поддерживается. Используй мастер-пароль."));
  } catch(e) {
    toast(e.name === 'NotAllowedError' ? translateText("Операция отменена или запрещена Safari.") : (localizedError(e) || translateText("Face ID недоступен.")));
  } finally {
    busy = false;
    $('bioActionBtn').disabled = false;
    if (document.hidden && vault) lockVault(false);
  }
}
async function unlockBiometric(auto=false) {
  if (busy || !bioAvailable()) return;
  const config=bioConfig(); if (!config) return;
  busy=true; $('bioUnlockBtn').disabled=true;
  const controller=new AbortController(); activeBioRequest=controller;
  $('cancelAutoBio').classList.toggle('hidden',auto!==true);
  try {
    const assertion=await navigator.credentials.get({signal:controller.signal,publicKey:{challenge:randomBytes(32),allowCredentials:[{type:'public-key',id:bytesFromBase64(config.credential)}],userVerification:'required',timeout:auto===true?15000:60000,extensions:{prf:{eval:{first:bytesFromBase64(config.salt)}}}}});
    if(controller.signal.aborted) return;
    const stored=await readEncrypted();
    if (!stored || stored.salt!==config.vaultSalt) throw new Error(translateText("Сейф изменён. Войди мастер-паролем и настрой биометрию заново."));
    const secret=assertion?.getClientExtensionResults()?.prf?.results?.first;
    if (!secret) throw new Error(translateText("Safari не вернул ключ PRF. Разблокируй мастер-паролем."));
    const wrappingKey=await prfAes(secret);
    const raw=await crypto.subtle.decrypt({name:'AES-GCM',iv:bytesFromBase64(config.iv)},wrappingKey,bytesFromBase64(config.data));
    const master=new TextDecoder().decode(raw);
    const result=await decryptEnvelope(stored,master);
    if(controller.signal.aborted || document.hidden) return;
    vault=result.decoded;key=result.newKey;envelope=stored;showApp();toast(translateText("Сейф открыт."));
  } catch(e) {if(!controller.signal.aborted && auto!==true)toast(localizedError(e) || translateText("Face ID недоступен. Используй мастер-пароль."));}
  finally {activeBioRequest=null;busy=false;$('bioUnlockBtn').disabled=false;$('cancelAutoBio').classList.add('hidden');}
}

function attachHandlers() {
  document.querySelectorAll('[data-tab]').forEach(button => button.addEventListener('click', () => selectTab(button.dataset.tab)));
  $('auditBtn').addEventListener('click',()=>selectTab('audit'));
  $('generatedLength').addEventListener('input',()=>{$('generatedLengthLabel').textContent=$('generatedLength').value;});
  $('generateStandalone').addEventListener('click',generateStandalonePassword);
  $('copyGenerated').addEventListener('click',()=> $('generatedOutput').value ? copyToClipboard($('generatedOutput').value,translateText("Пароль")) : toast(translateText("Сначала создайте пароль.")));

  $('bioUnlockBtn').addEventListener('click',unlockBiometric);
  $('bioSetupBtn').addEventListener('click',setupBiometric);
  $('bioVerifyForm').addEventListener('submit',verifyBioMaster);
  $('bioActionBtn').addEventListener('click',performBioSetup);
  $('bioCancelBtn').addEventListener('click',()=>{$('bioDialog').close();resetBioSetup();});
  $('bioDialog').addEventListener('close',resetBioSetup);
  $('bioRemoveBtn').addEventListener('click',()=>{if(!vault || busy || !confirm(translateText("Отключить быстрый вход? Для следующего входа понадобится мастер-пароль.")))return;localStorage.removeItem(BIO_STORAGE);bioUi();toast(translateText("Быстрая разблокировка отключена."));});
  $('createForm').addEventListener('submit',onCreate);
  $('unlockForm').addEventListener('submit',onUnlock);
  $('editorForm').addEventListener('submit',onSaveEntry);
  $('importForm').addEventListener('submit',onImport);
  $('masterForm').addEventListener('submit',onChangeMaster);
  $('lockBtn').addEventListener('click',()=>{if(!busy)lockVault();else toast(translateText("Дождись окончания операции."));});
  $('addBtn').addEventListener('click',()=>openEditor());
  $('search').addEventListener('input',renderEntries);
  $('favoritesOnly').addEventListener('change',renderEntries);
  $('idleLockSelect').value=String(idleLockMinutes());
  $('idleLockSelect').addEventListener('change',()=>{
    const n=Number($('idleLockSelect').value);
    if(!LOCK_CHOICES.includes(n))return;
    try {localStorage.setItem(LOCK_PREF,String(n));}catch {toast(translateText("Не удалось сохранить настройку."));return;}
    lastActivity=Date.now();
    toast(translateText(translateText("Настройка автоблокировки сохранена.")));
  });

  $('exportBtn').addEventListener('click',()=>openReauth('export'));
  $('importFile').addEventListener('change',prepareImport);
  $('changeMasterBtn').addEventListener('click',()=>openReauth('master'));
  $('clearClipBtn').addEventListener('click',async()=>{
    try {await navigator.clipboard.writeText('');toast(translateText("Буфер обмена очищен."));}
    catch {toast(translateText("Не удалось очистить буфер."));}
  });
  $('showSecret').addEventListener('click',()=>{
    const show=$('secret').type==='password';$('secret').type=show?'text':'password';
    $('showSecret').textContent=translateText(show?translateText("Скрыть"):translateText("Показать"));
    clearTimeout(ghostTimer);if(show)ghostTimer=setTimeout(maskGhost,15000);
  });
  $('copyLogin').addEventListener('click',()=> $('login').value ? copyToClipboard($('login').value,translateText("Логин")) : toast(translateText("Логин не указан.")));
  $('copyPassword').addEventListener('click',()=> $('secret').value ? copyToClipboard($('secret').value,translateText("Пароль")) : toast(translateText("Пароль не указан.")));
  $('openWebsite').addEventListener('click',()=>{
    try {
      const url=ensureHttps($('siteUrl').value);
      if (!url) return toast(translateText("Добавь HTTPS-адрес сайта."));
      window.open(url,'_blank','noopener,noreferrer');
    } catch(e) {toast(localizedError(e));}
  });
  $('deleteEntry').addEventListener('click',deleteEditingEntry);
  $('generateBtn').addEventListener('click',()=>{
    try {
      $('secret').value=generatePassword(Number($('length').value),$('symbols').checked);
      $('secret').type='password';$('showSecret').textContent=translateText(translateText("Показать"));
      toast(translateText("Новый пароль создан. Он ещё не изменён на сайте!"));
    } catch (e) { toast(localizedError(e)); }
  });
  for(const id of ['closeEditor','cancelEditor']) $(id).addEventListener('click',()=>{$('editor').close();$('secret').value='';});
  for(const id of ['cancelImport','dismissImport']) $(id).addEventListener('click',()=>{pendingImport=null;$('importDialog').close();$('importMaster').value='';});
  for(const id of ['cancelMaster','dismissMaster']) $(id).addEventListener('click',()=>{$('masterDialog').close();$('masterNew').value='';$('masterConfirm').value='';});
  for(const dialog of [$('editor'),$('importDialog'),$('masterDialog')]) dialog.addEventListener('close',()=>{
    $('secret').value='';$('importMaster').value='';$('masterNew').value='';$('masterConfirm').value='';
    if(dialog===$('importDialog'))pendingImport=null;
    if(dialog===$('editor')){maskGhost();for(const id of ['service','login','notes','siteUrl'])$(id).value='';}
  });
  document.addEventListener('pointerdown',()=>lastActivity=Date.now(),{passive:true});
  document.addEventListener('keydown',()=>lastActivity=Date.now(),{passive:true});
  document.addEventListener('visibilitychange',()=>{
    if (document.hidden) {
      maskGhost();
      hiddenAt = Date.now();
      if(vault){if(!busy)lockVault(false);else{backgroundLockPending=true;document.documentElement.classList.add('privacy-locked');}}
    } else {hiddenAt=0;if(vault&&backgroundLockPending&&!busy)lockVault(false);}
  });
  window.addEventListener('pagehide',()=>{resetBioSetup();cancelAutoRequest();if(vault){if(!busy)lockVault(false);else{backgroundLockPending=true;document.documentElement.classList.add('privacy-locked');}}});
  setInterval(()=>{const ms=idleLockMilliseconds();if(vault && !busy && backgroundLockPending){lockVault(false);return;}if(vault && !busy && !document.hidden && ms>0 && Date.now()-lastActivity>=ms)lockVault();},5_000);
}
async function init() {
  attachHandlers();
  attachFortress();
  attachTitan();
  attachInfinity();
  attachEvolution();
  captureStaticLanguage();
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
    if(current) tryAutoBio();
  } catch(e) {
    $('gate').classList.add('hidden');
    $('unsupported').classList.remove('hidden');
    $('unsupported').append(make('p','',localizedError(e)||translateText("Локальное хранилище недоступно.")));
  }
  if('serviceWorker' in navigator) navigator.serviceWorker.register('./sw.js').catch(()=>{});
}

// GLOBAL offline localization. User content is never translated.
const LANG_KEY = 'bastion-ui-language-v05';
let uiLanguage = 'ru';
let languageMode = 'system';
const UI_CATALOG=Object.create(null);
UI_CATALOG.ru={name:'Русский',dir:'ltr',strings:BASTION_RU_OVERRIDES};
function validLanguagePack(code,pack){
 if(!/^[a-zA-Z]{2,8}(?:-[a-zA-Z0-9]{1,8})*$/.test(code)||!pack||typeof pack.name!=='string'||!['ltr','rtl'].includes(pack.dir)||!pack.strings)return false;
 return BASTION_LOCALE_KEYS.every(k=>Object.hasOwn(pack.strings,k)&&typeof pack.strings[k]==='string'&&pack.strings[k].trim().length>0&&JSON.stringify((k.match(/\{\d+\}/g)||[]).sort())===JSON.stringify((pack.strings[k].match(/\{\d+\}/g)||[]).sort()));
}
for(const [code,pack] of Object.entries(BASTION_LOCALE_PACKS))if(validLanguagePack(code,pack))UI_CATALOG[code]=pack;
Object.freeze(UI_CATALOG);
let staticLanguageNodes=[],staticLanguageAttrs=[];
function captureStaticLanguage(){
 // Preserve implicit option values before translating their labels.
 for(const option of document.querySelectorAll('option:not([value])'))option.value=option.value;
 const w=document.createTreeWalker(document.body,NodeFilter.SHOW_TEXT);let n;while(n=w.nextNode()){if(n.parentElement&&!n.parentElement.closest('script,style,#toast'))staticLanguageNodes.push([n,n.nodeValue]);}
 for(const e of document.querySelectorAll('[placeholder],[aria-label],[title]'))for(const a of ['placeholder','aria-label','title'])if(e.hasAttribute(a))staticLanguageAttrs.push([e,a,e.getAttribute(a)]);
}
function systemLanguage(){for(const l of navigator.languages||[navigator.language||'en']){const tag=l.toLowerCase();if(Object.hasOwn(UI_CATALOG,tag))return tag;const code=tag.split('-')[0];if(Object.hasOwn(UI_CATALOG,code))return code;}return Object.hasOwn(UI_CATALOG,'en')?'en':'ru';}
function translateText(input){
 if(typeof input!=='string')return input;const pack=UI_CATALOG[uiLanguage]?.strings;
 if(pack&&Object.hasOwn(pack,input))return pack[input];
 const match=/^(\s*)([\s\S]*?)(\s*)$/.exec(input);const core=match[2];
 if(pack&&Object.hasOwn(pack,core))return match[1]+pack[core]+match[3];return input;
}
function formatText(key,args){return translateText(key).replace(/\{(\d+)\}/g,(_,i)=>String(args[Number(i)]??''));}
function localizedError(error){
 const msg=error?.message;
 if(typeof msg==='string'&&(BASTION_LOCALE_KEYS.includes(msg)||Object.values(UI_CATALOG[uiLanguage]?.strings||{}).includes(msg)))return msg;
 return translateText('Операция не выполнена. Проверь данные и повтори.');
}
function applyLanguage(lang){
 uiLanguage=Object.hasOwn(UI_CATALOG,lang)?lang:(Object.hasOwn(UI_CATALOG,'en')?'en':'ru');
 document.documentElement.lang=uiLanguage;document.documentElement.dir=UI_CATALOG[uiLanguage].dir;
 document.title=translateText('BASTION VAULT — приватный сейф');
 for(const [node,src] of staticLanguageNodes)if(node.isConnected)node.nodeValue=translateText(src);
 for(const [node,attr,src] of staticLanguageAttrs)if(node.isConnected)node.setAttribute(attr,translateText(src));
 refreshHome();bioUi();const btn=$('langSettingsBtn');if(btn)btn.textContent='🌐 '+uiLanguage.toUpperCase();
 if(vault)renderEntries();
}
function languageSearchNames(code){let names=code;for(const locale of [uiLanguage,'en','ru'])try{names+=' '+new Intl.DisplayNames([locale],{type:'language'}).of(code);}catch{}return names.toLowerCase();}
function showLanguageSetup(){
  cancelAutoRequest();
  if(vault && busy)return;
  $('languageSetup').classList.remove('hidden');
  $('gate').classList.add('hidden');$('app').classList.add('hidden');
  $('languageSearch').value='';for(const o of $('languageSelect').options)o.hidden=false; $('languageSelect').value=uiLanguage;
 for(const id of ['languageSelect','languageSelectLabel','languageSearch','languageSearchLabel'])$(id).classList.toggle('hidden',languageMode!=='manual');
}
function initLanguage(){
  $('languageSelect').replaceChildren(...Object.entries(UI_CATALOG).map(([code,pack])=>new Option(pack.name,code)));
  let saved=null;try{saved=JSON.parse(localStorage.getItem(LANG_KEY)||'null');}catch{}
  languageMode=saved?.mode==='manual'?'manual':'system';
  applyLanguage(languageMode==='manual'?saved?.language:systemLanguage());
  $('langSettingsBtn').addEventListener('click',showLanguageSetup);
  $('changeLanguageBtn').addEventListener('click',showLanguageSetup);
  $('systemLanguageBtn').addEventListener('click',()=>{languageMode='system';$('languageSelect').classList.add('hidden');$('languageSelectLabel').classList.add('hidden');$('languageSearch').classList.add('hidden');$('languageSearchLabel').classList.add('hidden');});
  $('manualLanguageBtn').addEventListener('click',()=>{languageMode='manual';$('languageSelect').classList.remove('hidden');$('languageSelectLabel').classList.remove('hidden');$('languageSearch').classList.remove('hidden');$('languageSearchLabel').classList.remove('hidden');});
  $('languageContinueBtn').addEventListener('click',()=>{
    const lang=languageMode==='system'?systemLanguage():$('languageSelect').value;
    try{localStorage.setItem(LANG_KEY,JSON.stringify({mode:languageMode,language:lang}));}catch{}
    $('languageSetup').classList.add('hidden');
    applyLanguage(lang);
    if(vault)showApp();else {showGate(window.bastionHasVault?'unlock':'create');if(window.bastionHasVault)tryAutoBio();}
  });
  if(!saved)showLanguageSetup();
}



function selectTab(tab) {
  if(!vault) return;
  if(tab==='add'){openEditor();return;}
  if(tab==='home')refreshHome();
  for(const name of ['home','tools','vault','generator','audit','settings','auth','connect']) {
    const page=$(name+'Page');
    if(page)page.classList.toggle('hidden',name!==tab);
  }
  document.querySelectorAll('[data-tab]').forEach(button=>{
    const active=button.dataset.tab===tab || (button.closest('#bottomNav') && button.dataset.tab==='tools' && ['generator','audit','auth','connect'].includes(tab));
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
  catch(e) {toast(localizedError(e)||translateText("Не удалось создать пароль."));}
}

// TITAN: TOTP RFC 4226/6238, account guides, and local device verification.
const B32='ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
function decodeBase32(input){
  const raw=String(input).toUpperCase().replace(/[\s-]/g,'').replace(/=+$/,'');
  if(raw.length<16||raw.length>256||!/^[A-Z2-7]+$/.test(raw))throw new Error(translateText("Нужен ключ Base32 (буквы A–Z и цифры 2–7), от 16 символов."));
  let bits=0,n=0,out=[];for(const ch of raw){n=(n<<5)|B32.indexOf(ch);bits+=5;if(bits>=8){bits-=8;out.push((n>>bits)&255);}}
  if(bits>=5||(bits&&((n&((1<<bits)-1))!==0)))throw new Error(translateText("Ключ неполный или повреждён."));
  return Uint8Array.from(out);
}
function parseTotp(input){
  let secret=input.trim(),name='',algorithm='SHA-1',digits=6,period=30;
  if(/^otpauth:/i.test(secret)){
    const u=new URL(secret);if(u.protocol!=='otpauth:'||u.hostname!=='totp')throw new Error(translateText("Поддерживаются только коды TOTP, не HOTP."));
    for(const param of ['secret','algorithm','digits','period'])if(u.searchParams.getAll(param).length>1)throw new Error(translateText("Повторяющиеся параметры QR."));
    name=decodeURIComponent(u.pathname.slice(1)).slice(0,100);secret=u.searchParams.get('secret')||'';
    const a=(u.searchParams.get('algorithm')||'SHA1').toUpperCase().replace('-','');algorithm=({SHA1:'SHA-1',SHA256:'SHA-256',SHA512:'SHA-512'})[a];
    digits=Number(u.searchParams.get('digits')||6);period=Number(u.searchParams.get('period')||30);
  }
  secret=secret.toUpperCase().replace(/[\s-]/g,'').replace(/=+$/,'');decodeBase32(secret);
  if(!['SHA-1','SHA-256','SHA-512'].includes(algorithm)||![6,8].includes(digits)||!Number.isInteger(period)||period<15||period>120)throw new Error(translateText("Неподдерживаемые параметры TOTP."));
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
function openTotp(name='',guide=false){if(!vault||busy)return;clearTotpForm();$('totpName').value=name;const select=$('totpEntry');select.add(new Option(translateText("Без связи"),''));for(const e of vault.entries)select.add(new Option(e.service+' — '+e.login,e.id));$('totpDialog').showModal();pilotActive=guide;if(guide)pilotHint();}
function pilotHint(){if(!pilotActive||!$('totpDialog').open)return;const n=$('totpName'),s=$('totpSecret');document.querySelectorAll('.pilot-highlight').forEach(x=>x.classList.remove('pilot-highlight'));let field=n,msg=translateText("1. Введи название аккаунта в подсвеченное поле.");if(n.value.trim()){field=s;msg=translateText("2. Вставь секретный ключ из настроек сервиса. Для QR нажми «Прочитать QR с фото» или «Сканировать камерой».");try{parseTotp(s.value);field=$('totpSave');msg=translateText("3. Ключ распознан. При желании выбери запись сейфа, затем нажми «Сохранить 2FA».");}catch{}}field.classList.add('pilot-highlight');$('pilotInline').textContent=msg;$('pilotInline').classList.remove('hidden');}
async function saveTotp(e){e.preventDefault();if(!vault||busy)return;let t;try{t=parseTotp($('totpSecret').value);t.name=$('totpName').value.trim()||t.name;if(!t.name)throw new Error(translateText("Введи название аккаунта."));t.id=crypto.randomUUID();t.entryId=$('totpEntry').value;if(!validTotp(t))throw new Error(translateText("Проверь поля."));if((vault.totp||[]).length>=2000)throw new Error(translateText("Достигнут лимит кодов."));}catch(err){return toast(localizedError(err));}
  setBusy(true,$('totpSave'));try{await persistVault({...vault,totp:[...(vault.totp||[]),t]});$('totpDialog').close();clearTotpForm();pilotActive=false;if(vault){selectTab('auth');toast(translateText("Код сохранён. Введи его в исходном сервисе для подтверждения."));}}catch(err){toast(localizedError(err)||translateText("Ошибка сохранения."));}finally{setBusy(false,$('totpSave'));}}
function renderTotp(){const list=$('totpList');++totpGeneration;list.replaceChildren();if(!vault)return;const entries=vault.totp||[];if(!entries.length){list.append(make('div','empty',translateText("Пока нет кодов. Нажми «Добавить код 2FA» или запусти помощника.")));return;}
  for(const t of entries){const card=make('article','titan-card');const title=make('strong','',t.name);const linked=vault.entries.find(e=>e.id===t.entryId);const code=make('div','titan-code','••• •••');code.dataset.totpId=t.id;const progress=make('progress','titan-time');progress.max=t.period;progress.value=0;const time=make('span','titan-muted','');time.dataset.totpTime=t.id;const actions=make('div','titan-actions');const copy=make('button','btn secondary',translateText("Копировать"));copy.type='button';copy.addEventListener('click',()=>{if(!vault||document.hidden)return;if(t.ghost||protectedEntry(t.entryId))return ghostAuthorize(async()=>{if(!vault)return;const fresh=vault.totp?.find(x=>x.id===t.id);if(fresh)await copyToClipboard(await totpCode(fresh),translateText("Код 2FA"));});const current=code.dataset.code;if(current&&code.dataset.slot===String(Math.floor(Date.now()/1000/t.period)))copyToClipboard(current,translateText("Код 2FA"));else toast(translateText("Код обновляется. Нажми ещё раз."));});const remove=make('button','btn ghost',translateText("Удалить"));remove.type='button';remove.addEventListener('click',async()=>{if(!vault||busy||!confirm(translateText("Удалить код только из BASTION? Сначала убедись, что есть другой способ входа в аккаунт.")))return;setBusy(true);try{await persistVault({...vault,totp:vault.totp.filter(x=>x.id!==t.id)});renderTotp();}catch(e){toast(localizedError(e));}finally{setBusy(false);}});actions.append(copy,remove);card.append(title,make('span','titan-muted',linked?translateText("Связь: ")+linked.service:translateText("Одноразовый код")),code,progress,time,actions);list.append(card);}refreshTotp();}
async function refreshTotp(){if(!vault||document.hidden||$('authPage').classList.contains('hidden'))return;const generation=totpGeneration;const now=Math.floor(Date.now()/1000);for(const node of $('totpList').querySelectorAll('[data-totp-id]')){const t=vault?.totp?.find(x=>x.id===node.dataset.totpId);if(!t)return;if(t.ghost||protectedEntry(t.entryId)){node.textContent=translateText("🔒 Скрыт");delete node.dataset.code;delete node.dataset.slot;continue;}const slot=String(Math.floor(now/t.period));const left=t.period-now%t.period;node.nextElementSibling.value=left;node.nextElementSibling.nextElementSibling.textContent=translateText("Обновление через ")+left+translateText(" сек.");if(node.dataset.slot===slot)continue;try{const code=await totpCode(t,now);if(!vault||document.hidden||generation!==totpGeneration)return;node.textContent=code.slice(0,Math.ceil(code.length/2))+' '+code.slice(Math.ceil(code.length/2));node.dataset.code=code;node.dataset.slot=slot;}catch{node.textContent=translateText("Ошибка");}}}
function acceptQr(raw){const parsed=parseTotp(raw);$('totpSecret').value=raw;if(parsed.name)$('totpName').value=parsed.name;$('qrStatus').textContent=translateText("QR распознан. Проверь название и сохрани код.");pilotHint();stopQr();}
async function photoQr(file){if(!vault||!file||file.size>15e6)return toast(translateText("Выбери изображение до 15 МБ."));const generation=++qrGeneration;let bitmap;try{bitmap=await createImageBitmap(file);if(bitmap.width*bitmap.height>25e6)throw new Error(translateText("Изображение слишком большое."));let raw;if(window.BarcodeDetector){try{const results=await new BarcodeDetector({formats:['qr_code']}).detect(bitmap);if(results.length===1)raw=results[0].rawValue;}catch{}}if(!raw&&typeof decodeCleanQR==='function')raw=decodeCleanQR(bitmap);if(!raw)throw new Error(translateText("QR не распознан. Обрежь скриншот до одного QR с белой рамкой или вставь ключ вручную."));if(vault&&$('totpDialog').open&&generation===qrGeneration)acceptQr(raw);}catch(e){if(generation===qrGeneration)$('qrStatus').textContent=localizedError(e);}finally{bitmap?.close();}}
async function cameraQr(){if(!vault||!$('totpDialog').open)return;stopQr();const generation=qrGeneration;if(!window.BarcodeDetector||!navigator.mediaDevices?.getUserMedia){$('qrStatus').textContent=translateText("Камера-сканер не поддерживается браузером. Сделай скриншот QR, загрузи фото или вставь ключ вручную.");return;}try{const stream=await navigator.mediaDevices.getUserMedia({video:{facingMode:{ideal:'environment'}},audio:false});if(generation!==qrGeneration||!vault||!$('totpDialog').open){stream.getTracks().forEach(t=>t.stop());return;}qrStream=stream;const video=$('qrVideo');video.srcObject=stream;video.classList.remove('hidden');await video.play();const detector=new BarcodeDetector({formats:['qr_code']});async function scan(){if(generation!==qrGeneration||!vault)return;try{const results=await detector.detect(video);if(generation!==qrGeneration)return;if(results.length===1){acceptQr(results[0].rawValue);return;}}catch(e){if(generation===qrGeneration){stopQr();$('qrStatus').textContent=translateText("Не удалось распознать QR. Используй фото или ключ.");}return;}qrTimer=setTimeout(scan,250);}scan();}catch(e){if(generation===qrGeneration){stopQr();$('qrStatus').textContent=translateText("Камера недоступна. Проверь разрешения или вставь ключ вручную.");}}}
const SERVICES=[{name:'Google',url:'https://myaccount.google.com/security',auth:true,path:'Безопасность → Двухэтапная аутентификация → Authenticator.'},{name:'Instagram',url:'https://www.instagram.com/',auth:true,path:'Профиль → меню → Центр аккаунтов → Пароль и безопасность → Двухфакторная аутентификация → Приложение для аутентификации.'},{name:'VK',url:'https://id.vk.com/',auth:true,path:'VK ID → Безопасность и вход → Двухфакторная аутентификация. Если есть вариант приложения-аутентификатора, выбери его.'},{name:'Telegram',url:'https://telegram.org/',auth:false,path:'В приложении Telegram: Настройки → Конфиденциальность → Двухэтапная аутентификация. Настрой дополнительный пароль и почту восстановления; входные коды Telegram не являются TOTP.'},{name:'GitHub',url:'https://github.com/settings/security',auth:true,path:'Settings → Password and authentication → Two-factor authentication → Authenticator app.'},{name:'Apple Account',url:'https://account.apple.com/',auth:false,path:'В настройках iPhone: Apple Account → Вход и безопасность → Двухфакторная аутентификация. Apple использует доверенные устройства, а не обычный TOTP.'}];
function renderConnect(){const list=$('connectList');list.replaceChildren();if(!vault)return;for(const service of SERVICES){const card=make('article','titan-card');const matching=vault.entries.filter(e=>e.service.toLowerCase().includes(service.name.toLowerCase()));const linked=(vault.totp||[]).filter(t=>matching.some(e=>e.id===t.entryId));card.append(make('strong','',service.name),make('span','titan-muted',formatText("Записей: {0} · связанных 2FA: {1}. Защита на сайте не проверена.",[matching.length,linked.length])));const btn=make('button','btn secondary',translateText("Настроить с помощником"));btn.type='button';btn.addEventListener('click',()=>openPilot('auth',service.name));card.append(btn);list.append(card);}}
function openPilot(mode='auth',service='Google'){if(!vault||busy)return;pilotMode=mode;pilotStep=0;const sel=$('pilotService');sel.replaceChildren();for(const s of SERVICES)sel.add(new Option(s.name,s.name));sel.value=service;sel.classList.toggle('hidden',mode!=='auth');sel.previousElementSibling.classList.toggle('hidden',mode!=='auth');$('pilotDialog').showModal();renderPilot();}
function renderPilot(){const s=SERVICES.find(x=>x.name===$('pilotService').value)||SERVICES[0];const steps=pilotMode==='settings'?[[translateText("Резервная копия"),translateText("Открой настройки и нажми «Экспорт зашифрованной копии». Сохрани файл в «Файлы». Не отправляй его в GitHub.")],[translateText("Биометрия"),translateText("В настройках нажми «Настроить Face ID / Touch ID / код устройства», введи мастер-пароль, затем создай ключ доступа.")],[translateText("Проверка входа"),translateText("Нажми «Проверить быстрый вход». Сейф закроется. Используй кнопку биометрии; мастер-пароль остаётся запасным способом.")]]:[[translateText("Открой настройки сервиса"),translateText(s.path)+translateText(" Названия пунктов могут отличаться в твоей версии приложения.")],[s.auth?translateText("Подготовь секретный ключ"):translateText("Настрой защиту в сервисе"),s.auth?translateText("Выбери приложение-аутентификатор. На одном телефоне удобнее скопировать ключ настройки или сделать скриншот QR. Не делись этим ключом."):translateText("Выполни шаги в самом сервисе. BASTION не может получить доступ к его настройкам.")],[s.auth?translateText("Добавь ключ в BASTION"):translateText("Сохрани запись"),s.auth?translateText("Нажми кнопку ниже. Помощник подсветит нужные поля. После сохранения введи код в сервисе и удали скриншот QR."):translateText("Нажми кнопку ниже, чтобы открыть редактор записи. Не сохраняй непроверенный новый пароль.")]];const step=steps[pilotStep];$('pilotProgress').textContent=formatText("Шаг {0} из {1}",[pilotStep+1,steps.length]);$('pilotTitle').textContent=step[0];$('pilotText').textContent=step[1];$('pilotLink').classList.toggle('hidden',pilotMode!=='auth'||pilotStep!==0);$('pilotLink').href=s.url;$('pilotBack').disabled=pilotStep===0;$('pilotAction').textContent=pilotStep===steps.length-1?(pilotMode==='settings'?translateText("Открыть настройки"):s.auth?translateText("Добавить 2FA"):translateText("Открыть редактор")):translateText("Далее");}
function advancePilot(){if(!vault)return;if(pilotStep<2){++pilotStep;renderPilot();return;}const s=SERVICES.find(x=>x.name===$('pilotService').value)||SERVICES[0];$('pilotDialog').close();if(pilotMode==='settings'){selectTab('settings');startSettingsPilot();return;}if(s.auth){selectTab('auth');openTotp(s.name,true);}else{selectTab('vault');openEditor();$('service').value=s.name;startEditorPilot();}}
function attachTitan(){attachReauth();attachExtraPilot();
  $('addTotp').onclick=()=>openTotp();$('authPilot').onclick=()=>openPilot();$('pilotStart').onclick=()=>openPilot();$('settingsPilot').onclick=()=>openPilot('settings');$('pilotClose').onclick=()=>$('pilotDialog').close();$('pilotService').onchange=()=>{pilotStep=0;renderPilot();};$('pilotBack').onclick=()=>{if(pilotStep){--pilotStep;renderPilot();}};$('pilotAction').onclick=advancePilot;
  $('totpClose').onclick=()=>$('totpDialog').close();$('totpDialog').addEventListener('close',()=>{clearTotpForm();pilotActive=false;});$('totpForm').addEventListener('submit',saveTotp);$('totpName').addEventListener('input',pilotHint);$('totpSecret').addEventListener('input',pilotHint);$('qrPhoto').onclick=()=>$('qrFile').click();$('qrFile').onchange=()=>{const file=$('qrFile').files?.[0];$('qrFile').value='';if(file)photoQr(file);};$('qrCamera').onclick=cameraQr;
  $('bioTestBtn').onclick=()=>{if(!vault||busy)return;if(!bioConfig())return toast(translateText("Сначала настрой быстрый вход."));lockVault(false);toast(translateText("Нажми кнопку биометрии, чтобы проверить вход."));};
  setInterval(refreshTotp,500);document.addEventListener('visibilitychange',()=>{if(document.hidden)stopQr();});
}

let editorGuide=false,settingsGuideStep=-1;
function clearEditorPilot(){editorGuide=false;$('editorHint').classList.add('hidden');$('editor').querySelectorAll('.pilot-highlight').forEach(x=>x.classList.remove('pilot-highlight'));}
function updateEditorPilot(){if(!editorGuide)return;const steps=[['service',translateText("1. Введи название сайта или приложения.")],['login',translateText("2. Введи логин или почту. Если их нет, можно оставить поле пустым.")],['secret',translateText("3. Вставь действующий пароль. Для нового аккаунта можно нажать «Генерировать», затем установить пароль в сервисе.")],['siteUrl',translateText("4. При желании добавь HTTPS-адрес.")],['notes',translateText("5. При желании добавь заметку.")],['saveEntry',translateText("6. Нажми «Сохранить». Запись будет зашифрована.")]];const current=editorGuide-1;const [id,msg]=steps[current];$('editor').querySelectorAll('.pilot-highlight').forEach(x=>x.classList.remove('pilot-highlight'));$(id).classList.add('pilot-highlight');$('editorHint').replaceChildren(make('span','',msg));if(current<steps.length-1){const b=make('button','btn secondary small',translateText("Далее"));b.type='button';b.onclick=()=>{editorGuide++;updateEditorPilot();};$('editorHint').append(b);} $('editorHint').classList.remove('hidden');$(id).scrollIntoView({block:'nearest'});}
function startEditorPilot(){editorGuide=1;updateEditorPilot();}
function clearSettingsPilot(){settingsGuideStep=-1;$('settingsHint').classList.add('hidden');$('settingsPage').querySelectorAll('.pilot-highlight').forEach(x=>x.classList.remove('pilot-highlight'));}
function startSettingsPilot(){settingsGuideStep=0;updateSettingsPilot();}
function updateSettingsPilot(){if(settingsGuideStep<0)return;const steps=[['exportBtn',translateText("1. Нажми подсвеченную кнопку, подтверди личность и сохрани копию в «Файлы». Затем вернись сюда.")],['bioSetupBtn',translateText("2. Нажми подсвеченную кнопку, введи мастер-пароль и создай ключ доступа. Если уже настроено, можно пропустить.")],['idleLockSelect',translateText("3. Выбери время автоблокировки. Рекомендуем 1 или 5 минут.")],['bioTestBtn',translateText("4. Проверь быстрый вход. Сейф заблокируется, а ты сможешь войти с помощью биометрии или мастер-пароля.")]];$('settingsPage').querySelectorAll('.pilot-highlight').forEach(x=>x.classList.remove('pilot-highlight'));const [id,msg]=steps[settingsGuideStep];$(id).classList.add('pilot-highlight');const hint=$('settingsHint');hint.replaceChildren(make('span','',msg));if(settingsGuideStep<3){const btn=make('button','btn secondary small',translateText("Далее"));btn.type='button';btn.onclick=()=>{settingsGuideStep++;updateSettingsPilot();};hint.append(btn);}hint.classList.remove('hidden');$(id).scrollIntoView({block:'nearest'});}
function attachExtraPilot(){$('editorPilot').onclick=startEditorPilot;$('editor').addEventListener('close',clearEditorPilot);}
let reauthAction='',reauthOK=0,reauthEpoch=0;
function clearReauth(){ghostPending=null;++reauthEpoch;reauthAction='';reauthOK=0;$('reauthMaster').value='';$('reauthContinue').classList.add('hidden');if($('reauthDialog').open)$('reauthDialog').close();}
function openReauth(action){if(!vault||busy)return;clearReauth();reauthAction=action;$('reauthMessage').textContent=action==='export'?translateText("Подтверди личность для экспорта зашифрованной копии."):action==='transfer'?translateText("Подтверди личность для создания файла переноса."):translateText("Подтверди личность для смены мастер-пароля.");$('reauthBio').classList.toggle('hidden',!bioAvailable()||!bioConfig());$('reauthDialog').showModal();}
function approveReauth(epoch){if(epoch!==reauthEpoch||!vault||document.hidden||!$('reauthDialog').open)return;reauthOK=Date.now();$('reauthMessage').textContent=translateText("Личность подтверждена. Нажми «Продолжить» в течение 30 секунд.");$('reauthContinue').classList.remove('hidden');}
async function reauthMaster(e){e.preventDefault();if(!vault||busy)return;const pass=$('reauthMaster').value;$('reauthMaster').value='';const epoch=reauthEpoch;setBusy(true,$('reauthVerify'));try{await decryptEnvelope(envelope,pass);approveReauth(epoch);}catch{toast(translateText("Мастер-пароль не подошёл."));}finally{setBusy(false,$('reauthVerify'));}}
async function reauthBio(){if(!vault||busy||!bioAvailable())return;const cfg=bioConfig(),epoch=reauthEpoch;if(!cfg||cfg.vaultSalt!==envelope.salt)return toast(translateText("Используй мастер-пароль."));setBusy(true,$('reauthBio'));try{const assertion=await navigator.credentials.get({publicKey:{challenge:randomBytes(32),allowCredentials:[{type:'public-key',id:bytesFromBase64(cfg.credential)}],userVerification:'required',timeout:60000,extensions:{prf:{eval:{first:bytesFromBase64(cfg.salt)}}}}});const secret=assertion?.getClientExtensionResults()?.prf?.results?.first;if(!secret)throw Error('PRF unavailable');const wrapping=await prfAes(secret);const raw=await crypto.subtle.decrypt({name:'AES-GCM',iv:bytesFromBase64(cfg.iv)},wrapping,bytesFromBase64(cfg.data));if(epoch!==reauthEpoch||!vault)return;await decryptEnvelope(envelope,new TextDecoder().decode(raw));approveReauth(epoch);}catch{toast(translateText("Не удалось подтвердить биометрию. Используй мастер-пароль."));}finally{setBusy(false,$('reauthBio'));}}
function attachReauth(){$('reauthClose').onclick=clearReauth;$('reauthDialog').addEventListener('close',()=>{if(!$('reauthDialog').open){++reauthEpoch;reauthOK=0;reauthAction='';$('reauthMaster').value='';}});$('reauthForm').addEventListener('submit',reauthMaster);$('reauthBio').onclick=reauthBio;$('reauthContinue').onclick=()=>{if(!vault||busy||!reauthOK||Date.now()-reauthOK>30000)return toast(translateText("Подтверди личность ещё раз."));const action=reauthAction, callback=ghostPending;clearReauth();if(action==='ghost'||action==='sync'){if(callback)callback();}else if(action==='transfer'){$('transferDialog').showModal();createTransfer();}else if(action==='export')downloadBackup();else if(action==='master')$('masterDialog').showModal();};}
// INFINITY — local tools. No network or third-party data access.
let infinityEpoch=0, incoming=null, transfer=null, migration=null, oneId='';
const activeInfinity=(epoch)=>!!vault&&!document.hidden&&epoch===infinityEpoch;
function infButton(text,fn,style='secondary'){const b=make('button','btn '+style,text);b.type='button';b.onclick=fn;return b;}
function infStatus(id,text){$(id).textContent=text;}
function clearInfinity(){++infinityEpoch;incoming=null;transfer=null;migration=null;oneId='';for(const id of ['oneDialog','dnaDialog','migrationDialog','transferDialog','verifyDialog','autofillDialog'])if($(id).open)$(id).close();for(const id of ['oneContent','dnaList','migrationPreview','transferCode','transferStatus','verifyStatus'])$(id).replaceChildren();for(const id of ['dnaEmail','dnaPhone','dnaProvider','transferPass','verifyPass','migrationFile','transferFile','verifyFile','transferQRFile'])$(id).value='';$('transferCanvas').width=1;$('transferCanvas').height=1;$('transferSave').disabled=true;$('migrationCommit').disabled=true;$('transferReceive').disabled=true;}
function openInfinity(id){if(!vault||busy)return;$(id).showModal();}
function entryForOne(){return vault?.entries.find(e=>e.id===oneId);}
function openOne(id,approved=false){if(!vault||busy)return;if(!approved&&protectedEntry(id))return ghostAuthorize(()=>openOne(id,true));oneId=id;renderOne();$('oneDialog').showModal();}
function renderOne(){const e=entryForOne();if(!e)return;const root=$('oneContent');root.replaceChildren(make('h3','',e.service));const step=Number(vault.oneProgress?.id===e.id?vault.oneProgress.step:0);root.append(make('p','pilot-inline', [translateText("1. Скопируй логин и вставь его в сервис."),translateText("2. Скопируй пароль и вставь в сервис."),translateText("3. При запросе кода 2FA скопируй его."),translateText("4. Проверь, что вход выполнен.")][Math.min(3,step)]));const linked=(vault.totp||[]).filter(t=>t.entryId===e.id);const a=infButton(translateText("Копировать логин"),()=>oneCopy('login',1));a.disabled=!e.login;const b=infButton(translateText("Копировать пароль"),()=>oneCopy('password',2));const url=infButton(translateText("Открыть сохранённый сайт"),()=>{try{const u=ensureHttps(e.url);if(!u)return toast(translateText("Добавь адрес сайта в записи."));if(confirm(translateText("Открыть ")+new URL(u).hostname+translateText("? Проверь адрес перед вводом пароля.")))window.open(u,'_blank','noopener,noreferrer');}catch{toast(translateText("Проверь адрес сайта."));}});url.disabled=!e.url;root.append(url,a,b);for(const t of linked)root.append(infButton(translateText("Копировать 2FA: ")+t.name,()=>oneCopy('totp',3,t.id)));root.append(infButton(translateText("Вход выполнен / начать заново"),()=>saveOneStep(e.id,0)),make('p','titan-muted',translateText("Прогресс зашифрован. BASTION не видит, что происходит на стороннем сайте.")));
}
async function saveOneStep(id,step){if(!vault||busy)return;setBusy(true);try{await persistVault({...vault,oneProgress:{id,step}});if(vault&&$('oneDialog').open)renderOne();}catch(e){toast(localizedError(e));}finally{setBusy(false);}}
async function oneCopy(field,step,tid){const e=entryForOne();if(!e||busy)return;const epoch=infinityEpoch;setBusy(true);try{let value=e[field];if(!activeInfinity(epoch)||!navigator.clipboard?.writeText)return;if(field==='totp'){const t=(vault.totp||[]).find(t=>t.id===tid&&t.entryId===e.id);if(!t)return;if(window.ClipboardItem&&navigator.clipboard.write){await navigator.clipboard.write([new ClipboardItem({'text/plain':totpCode(t).then(code=>{if(!activeInfinity(epoch))throw Error(translateText("Сейф закрыт."));return new Blob([code],{type:'text/plain'});})})]);}else{value=await totpCode(t);if(!activeInfinity(epoch))return;await navigator.clipboard.writeText(value);}}else{if(!value)return;await navigator.clipboard.writeText(value);}if(!vault||epoch!==infinityEpoch)return;await persistVault({...vault,oneProgress:{id:e.id,step}});if(activeInfinity(epoch)&&$('oneDialog').open)renderOne();toast(translateText("Скопировано. Вставь в нужном сервисе."));}catch(e){toast(translateText("Не удалось завершить действие. Проверь буфер и повтори."));}finally{setBusy(false);}}
function dnaFields(e){return {email:e?.recovery?.email||'',phone:e?.recovery?.phone||'',provider:e?.recovery?.provider||''};}
function openDNA(){if(!vault||busy)return;const s=$('dnaEntry');s.replaceChildren(new Option(translateText("Выбери аккаунт"),''));for(const e of vault.entries)s.add(new Option(e.service+' — '+e.login,e.id));loadDNA();renderDNA();openInfinity('dnaDialog');}
function loadDNA(){const e=vault?.entries.find(e=>e.id===$('dnaEntry').value);const f=dnaFields(e);$('dnaEmail').value=f.email;$('dnaPhone').value=f.phone;$('dnaProvider').value=f.provider;$('dnaSave').disabled=!e;$('dnaHint').textContent=e&&e.login.includes('@')?translateText("Логин похож на почту. Укажи её как почту восстановления только если это действительно так."):translateText("Укажи только проверенные связи из настроек аккаунта.");}
function renderDNA(){const root=$('dnaList');root.replaceChildren();if(!vault)return;const groups=new Map();for(const e of vault.entries){const f=dnaFields(e);for(const [kind,val] of [['Почта',f.email],['Телефон',f.phone],['Вход через',f.provider]])if(val){const normal=kind==='Телефон'?val.replace(/[^\d+]/g,''):val.trim().toLowerCase();if(!normal)continue;const k=translateText(kind)+': '+(kind==='Вход через'&&normal==='другое'?translateText('Другое'):normal);if(!groups.has(k))groups.set(k,[]);groups.get(k).push(e);}}if(!groups.size)root.append(make('p','titan-muted',translateText("Связей пока нет. Добавь их для аккаунтов выше.")));for(const [label,entries] of groups){const card=make('article','titan-card');card.append(make('strong','',label),make('p','',entries.length+translateText(" аккаунтов: при изменении этой связи проверь каждый.")));for(const e of entries)card.append(make('span','',e.service+' — '+e.login));root.append(card);}}
async function saveDNA(){if(!vault||busy)return;const id=$('dnaEntry').value;if(!vault.entries.some(e=>e.id===id))return;const recovery={email:$('dnaEmail').value.trim(),phone:$('dnaPhone').value.trim(),provider:$('dnaProvider').value};if(recovery.email.length>254)return toast(translateText("Слишком длинный адрес."));if(recovery.email&&!/^[^\s@]+@[^\s@]+$/.test(recovery.email))return toast(translateText("Проверь адрес почты."));if(recovery.phone&&!/^\+?[\d\s().-]{5,40}$/.test(recovery.phone))return toast(translateText("Проверь номер телефона."));setBusy(true);try{await persistVault({...vault,entries:vault.entries.map(e=>e.id===id?{...e,recovery}:e)});if(vault)renderDNA();toast(translateText("Связи сохранены."));}catch(e){toast(localizedError(e));}finally{setBusy(false);}}
// RFC4180-style parser: quoted fields, escaped quotes, embedded newlines; rejects malformed input.
function parseCSV(text){text=text.replace(/^\uFEFF/,'');let rows=[],row=[],field='',state=0;for(let i=0;i<text.length;i++){const c=text[i];if(state===1){if(c==='"'){if(text[i+1]==='"'){field+='"';i++;}else state=2;}else field+=c;continue;}if(c===','||c==='\n'||c==='\r'){row.push(field);field='';state=0;if(c!==','){if(c==='\r'&&text[i+1]==='\n')i++;if(row.some(x=>x!==''))rows.push(row);row=[];}continue;}if(state===2)throw Error(translateText("Некорректный CSV после кавычек."));if(c==='"'){if(field)throw Error(translateText("Некорректные кавычки CSV."));state=1;}else field+=c;}if(state===1)throw Error(translateText("Незакрытая кавычка CSV."));if(field||row.length){row.push(field);if(row.some(x=>x!==''))rows.push(row);}if(rows.length<2)throw Error(translateText("В файле нет записей."));if(rows.length>20001)throw Error(translateText("Слишком много записей."));return rows;}
function migrationEntries(text){const rows=parseCSV(text),headers=rows.shift().map(h=>h.trim().toLowerCase());const idx=(...names)=>names.map(n=>headers.indexOf(n)).find(i=>i>=0)??-1;const p=idx('password','login_password','пароль'),n=idx('title','name','account','название'),u=idx('url','login_uri','website','адрес'),l=idx('username','login_username','login','user name','login name','логин'),notes=idx('notes','note','comments','заметки'),type=idx('type'),otp=idx('otp','login_totp','totp','otpauth');if(p<0||(n<0&&u<0))throw Error('Не распознаны столбцы названия/сайта и пароля.');let skipped=0;const entries=[],totp=[];const get=(row,i)=>i<0?'':row[i]??'';for(const r of rows){if(r.length!==headers.length|| (type>=0&&get(r,type)&&get(r,type).toLowerCase()!=='login')){skipped++;continue;}const password=get(r,p),login=get(r,l),note=get(r,notes),raw=get(r,u).trim();let url='',service=get(r,n).trim();try{if(raw)url=ensureHttps(raw);}catch{skipped++;continue;}if(!service&&url)service=new URL(url).hostname;if(!service||!password||service.length>100||login.length>200||password.length>1024||note.length>3000||url.length>1000){skipped++;continue;}const id=crypto.randomUUID(),now=new Date().toISOString();const e={id,service,login,password,url,notes:note,createdAt:now,updatedAt:now};const secret=get(r,otp).trim();if(secret){try{const t={...parseTotp(secret),id:crypto.randomUUID(),entryId:id};if(!t.name)t.name=service;if(!validTotp(t))throw Error();totp.push(t);}catch{skipped++;continue;}}entries.push(e);}return {entries,totp,skipped};}
function entryIdentity(e){let site=e.service.trim().toLowerCase();try{if(e.url)site=new URL(e.url).hostname.toLowerCase();}catch{}return JSON.stringify([e.kind||"login",site,e.login]);}
function mergeImported(current,source){const entries=[...current.entries],totp=[...(current.totp||[])],idMap=new Map(),byIdentity=new Map(entries.map(e=>[entryIdentity(e),e])),ids=new Set(entries.map(e=>e.id));let duplicates=0,conflicts=0,added=0,addedTotp=0;for(const e of source.entries){const match=byIdentity.get(entryIdentity(e));if(match){if(match.password===e.password&&match.notes===e.notes&&match.url===e.url&&JSON.stringify(match.recovery||{})===JSON.stringify(e.recovery||{})){duplicates++;idMap.set(e.id,match.id);}else conflicts++;continue;}const id=ids.has(e.id)?crypto.randomUUID():e.id;const next={...e,id};ids.add(id);idMap.set(e.id,id);entries.push(next);byIdentity.set(entryIdentity(e),next);added++;}for(const t of source.totp||[]){const entryId=t.entryId?idMap.get(t.entryId):'';if(t.entryId&&!entryId){conflicts++;continue;}if(totp.some(x=>x.entryId===entryId&&x.secret===t.secret&&x.algorithm===t.algorithm&&x.period===t.period&&x.digits===t.digits)){duplicates++;continue;}if(totp.some(x=>x.entryId===entryId&&x.name===t.name)){conflicts++;continue;}totp.push({...t,id:crypto.randomUUID(),entryId});addedTotp++;}const result={...current,entries,totp};if(!validVault(result))throw Error(translateText("Превышен лимит или данные несовместимы."));return {result,added,addedTotp,duplicates,conflicts};}
function mergeMessage(m){return formatText("Новых паролей: {0}. Новых 2FA: {1}. Повторов: {2}. Конфликтов (пропущено): {3}.",[m.added,m.addedTotp,m.duplicates,m.conflicts]) ;}
async function previewMigration(){if(!vault||busy)return;const file=$('migrationFile').files?.[0];$('migrationFile').value='';migration=null;$('migrationCommit').disabled=true;if(!file)return;if(file.size>MAX_BACKUP_BYTES)return toast(translateText("Файл слишком большой."));const epoch=infinityEpoch;setBusy(true);try{const source=migrationEntries(await file.text());if(!activeInfinity(epoch)||!$('migrationDialog').open)return;const m=mergeImported(vault,source);migration={source};$('migrationPreview').textContent=mergeMessage(m)+translateText(" Не поддержано строк: ")+source.skipped+translateText(". Старые записи не изменятся.");$('migrationCommit').disabled=!m.added&&!m.addedTotp;}catch(e){infStatus('migrationPreview',localizedError(e));}finally{setBusy(false);}}
async function commitMigration(){if(!vault||busy||!migration)return;const m=mergeImported(vault,migration.source);if(!confirm(mergeMessage(m)+translateText(" Добавить в сейф?")))return;setBusy(true);try{await persistVault(m.result);migration=null;$('migrationCommit').disabled=true;renderEntries();infStatus('migrationPreview',translateText("Готово. ")+mergeMessage(m)+translateText(" Удали незашифрованный CSV из «Файлов» и «Недавно удалённых»."));}catch(e){toast(localizedError(e));}finally{setBusy(false);}}
function downloadInfinity(record,name){const url=URL.createObjectURL(new Blob([JSON.stringify(record)],{type:'application/json'}));const a=make('a');a.href=url;a.download=name;document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),10000);}
async function createTransfer(){if(!vault||busy)return;const epoch=infinityEpoch;setBusy(true);try{const code=Array.from(randomBytes(24),b=>b.toString(16).padStart(2,'0')).join('');const salt=randomBytes(16),k=await deriveKey(code,salt),record=await encryptVault(vault,k,salt);if(!validEnvelope(record))throw Error(translateText("Файл слишком большой."));if(!activeInfinity(epoch)||!$('transferDialog').open)return;transfer=record;infStatus('transferCode',code);drawInfinityQR(code,$('transferCanvas'));$('transferSave').disabled=false;infStatus('transferStatus',translateText("Сохрани файл и передай его на новый телефон. QR/код передай отдельно. Не фотографируй их без необходимости."));}catch(e){toast(localizedError(e));}finally{setBusy(false);}}
async function selectEncryptedFile(id,kind){const file=$(id).files?.[0];$(id).value='';if(!vault||busy||!file)return;incoming=null;const epoch=infinityEpoch;const status=kind==='verify'?'verifyStatus':'transferStatus';if(kind==='transfer')$('transferReceive').disabled=true;if(file.size>MAX_BACKUP_BYTES)return infStatus(status,translateText("Файл слишком большой."));setBusy(true);try{const rec=JSON.parse(await file.text());if(!validEnvelope(rec))throw Error(translateText("Неподдерживаемый файл BASTION."));if(!activeInfinity(epoch)||!$(kind==='verify'?'verifyDialog':'transferDialog').open)return;incoming={kind,rec};infStatus(status,translateText("Файл выбран. Введи ")+(kind==='verify'?translateText("мастер-пароль копии."):translateText("код переноса.")));if(kind==='transfer')$('transferReceive').disabled=false;}catch(e){infStatus(status,localizedError(e));}finally{setBusy(false);}}
async function verifyInfinity(e){e.preventDefault();if(!vault||busy||incoming?.kind!=='verify')return toast(translateText("Сначала выбери файл копии."));const pass=$('verifyPass').value;$('verifyPass').value='';const epoch=infinityEpoch;setBusy(true);try{const result=await decryptEnvelope(incoming.rec,pass);if(!activeInfinity(epoch)||!$('verifyDialog').open)return;const live=vault.entries;const same=live.filter(x=>result.decoded.entries.some(y=>x.id===y.id&&x.password===y.password&&x.login===y.login&&x.service===y.service&&x.url===y.url&&x.notes===y.notes&&JSON.stringify(x.recovery||{})===JSON.stringify(y.recovery||{})&&!!x.favorite===!!y.favorite)).length;const codes=result.decoded.totp||[];const good=codes.filter(t=>(vault.totp||[]).some(x=>x.id===t.id&&x.secret===t.secret&&x.algorithm===t.algorithm&&x.period===t.period&&x.digits===t.digits&&x.entryId===t.entryId)).length;infStatus('verifyStatus',formatText("Копия расшифрована и проверена. Записей: {0}; 2FA: {1}. Совпадает с текущим сейфом: {2} из {3} записей; {4} из {5} кодов. Текущий сейф не изменён.",[result.decoded.entries.length,codes.length,same,live.length,good,(vault.totp||[]).length]));}catch(err){infStatus('verifyStatus',localizedError(err));}finally{setBusy(false);}}
async function receiveInfinity(e){e.preventDefault();if(!vault||busy||incoming?.kind!=='transfer')return;const pass=$('transferPass').value.trim().toLowerCase();$('transferPass').value='';if(!/^[0-9a-f]{48}$/.test(pass))return toast(translateText("Нужен код из 48 символов."));const epoch=infinityEpoch;setBusy(true);try{const r=await decryptEnvelope(incoming.rec,pass);if(!activeInfinity(epoch)||!$('transferDialog').open)return;const m=!vault.entries.length&&!(vault.totp||[]).length&&!(vault.history||[]).length?{result:r.decoded,added:r.decoded.entries.length,addedTotp:(r.decoded.totp||[]).length,duplicates:0,conflicts:0}:mergeImported(vault,r.decoded);if(!confirm(mergeMessage(m)+translateText(" Добавить в сейф? Существующие записи не будут заменены.")))return;await persistVault(m.result);incoming=null;$('transferReceive').disabled=true;renderEntries();infStatus('transferStatus',translateText("Перенос завершён. ")+mergeMessage(m)+translateText(" Удали временный файл и код."));}catch(err){infStatus('transferStatus',localizedError(err));}finally{setBusy(false);}}
async function transferQR(){const file=$('transferQRFile').files?.[0];$('transferQRFile').value='';if(!file||!vault||busy||file.size>15e6)return;const epoch=infinityEpoch;let bmp;setBusy(true);try{bmp=await createImageBitmap(file);if(bmp.width*bmp.height>25e6)throw Error(translateText("Изображение слишком большое."));let raw;try{if(window.BarcodeDetector){const a=await new BarcodeDetector({formats:['qr_code']}).detect(bmp);if(a.length===1)raw=a[0].rawValue;}}catch{}if(!raw)raw=decodeCleanQR(bmp);if(!/^[0-9a-f]{48}$/.test(raw||''))throw Error(translateText("QR не распознан. Введи код вручную."));if(activeInfinity(epoch)&&$('transferDialog').open)$('transferPass').value=raw;}catch(e){toast(localizedError(e));}finally{bmp?.close();setBusy(false);}}
function attachInfinity(){for(const id of ['oneDialog','dnaDialog','migrationDialog','transferDialog','verifyDialog','autofillDialog']){$(id).querySelector('.inf-close').onclick=()=>$(id).close();$(id).addEventListener('close',()=>{if($(id).open)return;++infinityEpoch;if(id==='oneDialog'){$('oneContent').replaceChildren();oneId='';}if(id==='dnaDialog'){for(const x of ['dnaEmail','dnaPhone','dnaProvider'])$(x).value='';$('dnaEntry').replaceChildren();$('dnaList').replaceChildren();}if(id==='migrationDialog'){migration=null;$('migrationFile').value='';$('migrationCommit').disabled=true;infStatus('migrationPreview','');}if(id==='verifyDialog'){incoming=null;$('verifyPass').value='';infStatus('verifyStatus','');}if(id==='transferDialog'){incoming=null;transfer=null;$('transferPass').value='';infStatus('transferCode','');infStatus('transferStatus','');$('transferCanvas').width=1;$('transferCanvas').height=1;$('transferSave').disabled=true;$('transferReceive').disabled=true;}});}
$('dnaBtn').onclick=openDNA;$('dnaEntry').onchange=loadDNA;$('dnaSave').onclick=saveDNA;$('migrationBtn').onclick=()=>openInfinity('migrationDialog');$('migrationFile').onchange=previewMigration;$('migrationCommit').onclick=commitMigration;$('transferBtn').onclick=()=>openInfinity('transferDialog');$('transferCreate').onclick=()=>{$('transferDialog').close();openReauth('transfer');};$('transferSave').onclick=()=>{if(vault&&transfer)downloadInfinity(transfer,'BASTION-transfer.bastion');};$('transferFile').onchange=()=>selectEncryptedFile('transferFile','transfer');$('transferForm').onsubmit=receiveInfinity;$('transferQRFile').onchange=transferQR;$('verifyBtn').onclick=()=>openInfinity('verifyDialog');$('verifyFile').onchange=()=>selectEncryptedFile('verifyFile','verify');$('verifyForm').onsubmit=verifyInfinity;$('autofillBtn').onclick=()=>openInfinity('autofillDialog');$('autofillOne').onclick=()=>$('autofillDialog').close();}

// EVOLUTION: local-only, same encrypted envelope and origin.
const EVO_KINDS={login:['Аккаунт','Логин / e-mail','Пароль','Заметки'],wifi:['Wi-Fi','Имя сети (SSID)','Пароль Wi-Fi','Заметки'],card:['Карта','Последние 4 цифры / название','Номер карты (без CVV)','Срок действия / заметки'],document:['Документ','Тип / владелец','Номер документа','Текст документа (без вложений)'],api:['API-ключ','Имя ключа / проекта','Секретный ключ','Права / срок действия'],recovery:['Коды восстановления','Аккаунт','Код (необязательно)','Список кодов'],note:['Заметка','Тема','Секрет (необязательно)','Текст заметки'],pin:['PIN','Назначение','PIN-код','Заметки']};
let ghostPending=null,ghostTimer=0,evoEpoch=0,syncRecord=null,syncIncoming=null;
function validEvolution(v){if(v.historyDays!==undefined&&![0,7,30,90].includes(v.historyDays))return false;const check=e=>!!e&&typeof e.id==='string'&&e.id.length<=70&&['service','login','password','url','notes'].every((k,i)=>typeof e[k]==='string'&&e[k].length<=[100,200,1024,1000,3000][i])&&(e.kind===undefined||Object.hasOwn(EVO_KINDS,e.kind))&&(e.ghost===undefined||typeof e.ghost==='boolean');if(!v.entries.every(check))return false;return v.history===undefined||(Array.isArray(v.history)&&v.history.length<=1000&&v.history.every(h=>h&&typeof h.hid==='string'&&h.hid.length<=70&&Number.isFinite(h.at)&&['change','delete'].includes(h.reason)&&check(h.entry))&&new Set(v.history.map(h=>h.hid)).size===v.history.length);}
function historyDays(v){return v?.historyDays||0;}
function entrySnapshot(e){const {id,service,login,password,url,notes,kind,ghost,favorite,createdAt,updatedAt,recovery}=e;return {id,service,login,password,url,notes,kind:kind||'login',ghost:!!ghost,favorite:!!favorite,createdAt,updatedAt,recovery};}
function entryValue(e){return JSON.stringify([e.service,e.login,e.password,e.url,e.notes,e.kind||'login',!!e.ghost,e.recovery||{}]);}
function pruneHistory(list,days,now=Date.now()){if(!days)return [];const counts=new Map();return [...list].filter(h=>h.at>=now-days*86400000&&h.at<=now).sort((a,b)=>b.at-a.at).filter(h=>{let c=counts.get(h.entry.id)||0;counts.set(h.entry.id,c+1);return c<5;}).slice(0,1000);}
function evolveHistory(old,next){const days=historyDays(next);if(!days)return next.history||next.historyDays!==undefined?{...next,history:[]}:next;let history=[...(next.history||[])];if(old){const byId=new Map(next.entries.map(e=>[e.id,e]));for(const e of old.entries){const n=byId.get(e.id);if(!n||entryValue(e)!==entryValue(n))history.unshift({hid:crypto.randomUUID(),at:Date.now(),reason:n?'change':'delete',entry:entrySnapshot(e)});}}return {...next,history:pruneHistory(history,days)};}
function protectedEntry(id){return !!vault?.entries.find(e=>e.id===id)?.ghost;}
function ghostAuthorize(callback,action='ghost'){if(!vault||busy||document.hidden)return;openReauth(action);ghostPending=callback;$('reauthMessage').textContent=translateText("Подтверди личность для доступа к защищённым данным.");}
function ghostCopy(id,field){const run=()=>{const e=vault?.entries.find(x=>x.id===id);if(e&&e[field])copyToClipboard(e[field],field==='login'?translateText("Логин"):translateText("Секрет"));};if(protectedEntry(id))ghostAuthorize(run);else run();}
function maskGhost(){clearTimeout(ghostTimer);$('secret').type='password';$('showSecret').textContent=translateText(translateText("Показать"));}
function applyEntryKind(){const k=$('entryKind').value,labels=EVO_KINDS[k]||EVO_KINDS.login;for(const [i,id] of ['login','secret','notes'].entries()){const l=document.querySelector('label[for="'+id+'"]');if(l)l.textContent=translateText(labels[i+1]);} $('secret').placeholder=translateText(labels[2]);}
function clearEvolution(){++evoEpoch;ghostPending=null;maskGhost();syncRecord=null;syncIncoming=null;for(const id of ['historyDialog','syncDialog','mergeDialog'])if($(id).open)$(id).close();for(const id of ['historyList','syncEntries','syncReview','mergeList'])$(id).replaceChildren();$('syncPass').value='';$('syncFile').value='';$('syncStatus').textContent='';$('syncApply').disabled=true;}
function showHistory(){if(!vault||busy)return;$('historyRetention').value=String(historyDays(vault));renderHistory();$('historyDialog').showModal();}
function renderHistory(){const root=$('historyList');root.replaceChildren();if(!vault)return;const list=pruneHistory(vault.history||[],historyDays(vault));if(!list.length)root.append(make('p','titan-muted',translateText("Нет сохранённых версий.")));for(const h of list){const card=make('article','titan-card');card.append(make('strong','',h.entry.service),make('p','titan-muted',(h.reason==='delete'?translateText("Удалена"):translateText("Предыдущая версия"))+' · '+new Date(h.at).toLocaleString('ru-RU')),infButton(translateText("Восстановить"),()=>{ $('historyDialog').close();ghostAuthorize(()=>restoreHistory(h.hid)); }));root.append(card);}}
async function restoreHistory(hid){if(!vault||busy)return;const h=pruneHistory(vault.history||[],historyDays(vault)).find(x=>x.hid===hid);if(!h)return;const old=vault.entries.find(x=>x.id===h.entry.id);if(!confirm(translateText("Восстановить «")+h.entry.service+'»? '+(old?translateText("Текущая версия будет заменена, а её копия останется в истории."):translateText("Будет возвращена удалённая запись."))))return;const entry={...h.entry,ghost:!!old?.ghost||!!h.entry.ghost,updatedAt:new Date().toISOString()};await evoSave({...vault,entries:old?vault.entries.map(e=>e.id===entry.id?entry:e):[...vault.entries,entry]},translateText("Запись восстановлена. Проверь актуальность пароля и 2FA."));}
async function evoSave(next,msg){if(!vault||busy)return false;setBusy(true);try{await persistVault(next);if(vault){renderEntries();toast(msg);}return true;}catch(e){toast(localizedError(e)||translateText("Не удалось сохранить."));return false;}finally{setBusy(false);}}
function syncEntries(){const root=$('syncEntries');root.replaceChildren();if(!vault)return;const cutoff=$('syncSince').value?new Date($('syncSince').value+'T00:00:00').valueOf():0;for(const e of vault.entries){if(cutoff&&Date.parse(e.updatedAt||e.createdAt||'')<cutoff)continue;const l=make('label','checklabel');const c=make('input');c.type='checkbox';c.value=e.id;c.className='sync-choice';l.append(c,document.createTextNode(e.service+(e.ghost?' · 🔒':'')));root.append(l);}}
function syncSubset(v,ids){const set=new Set(ids);return {schema:1,entries:v.entries.filter(e=>set.has(e.id)),totp:(v.totp||[]).filter(t=>set.has(t.entryId))};}
async function exportSync(ids){if(!vault||busy)return;setBusy(true);const k=key,salt=bytesFromBase64(envelope.salt),epoch=evoEpoch;try{const snapshot=syncSubset(vault,ids);const record=await encryptVault(snapshot,k,salt);if(!validEnvelope(record))throw Error(translateText("Файл слишком большой."));if(vault&&key===k&&!document.hidden&&epoch===evoEpoch)downloadInfinity(record,'BASTION-sync-'+new Date().toISOString().slice(0,10)+'.bastion');}catch(e){toast(localizedError(e));}finally{setBusy(false);}}
function syncPlan(current,source){const byId=new Map(current.entries.map(e=>[e.id,e]));const byIdentity=new Map(current.entries.map(e=>[entryIdentity(e),e]));return source.entries.map(e=>{const old=byId.get(e.id);const match=byIdentity.get(entryIdentity(e));return {entry:e,old,kind:old?(match&&match.id!==old.id?'conflict':entryValue(old)===entryValue(e)?'same':'update'):match?'conflict':'new'};});}
function applySync(current,source,selected){const ids=new Set(selected),plan=syncPlan(current,source),entries=[...current.entries],idMap=new Map();let updates=0,added=0,addedTotp=0,skipped=0;for(const p of plan){const e=p.entry;if(!ids.has(e.id)||p.kind==='conflict'){skipped++;continue;}if(p.kind==='new'){if(entries.some(x=>entryIdentity(x)===entryIdentity(e))){skipped++;continue;}entries.push(e);added++;}else if(p.kind==='update'){const idx=entries.findIndex(x=>x.id===e.id);if(entries.some(x=>x.id!==e.id&&entryIdentity(x)===entryIdentity(e))){skipped++;continue;}entries[idx]={...e,ghost:!!e.ghost||!!entries[idx].ghost,favorite:!!e.favorite||!!entries[idx].favorite,updatedAt:new Date().toISOString()};updates++;}idMap.set(e.id,e.id);}const totp=[...(current.totp||[])];for(const t of source.totp||[]){if(!idMap.has(t.entryId))continue;if(totp.some(x=>x.id===t.id||x.entryId===t.entryId&&x.name===t.name)){skipped++;continue;}totp.push(t);addedTotp++;}return {result:{...current,entries,totp},added,updates,addedTotp,skipped};}
function reviewSync(){const root=$('syncReview');root.replaceChildren();if(!vault||!syncIncoming)return;for(const p of syncPlan(vault,syncIncoming)){const l=make('label','checklabel');const c=make('input');c.type='checkbox';c.value=p.entry.id;c.className='sync-review-choice';c.disabled=p.kind==='conflict';c.checked=p.kind==='new'||p.kind==='same';l.append(c,document.createTextNode(p.entry.service+' — '+({new:translateText("новая запись"),same:translateText("без изменения, проверить 2FA"),update:translateText("замена текущих данных (подтверди вручную)"),conflict:translateText("другой ID / совпадение, используй MERGE")}[p.kind])));root.append(l);}$('syncApply').disabled=false;}
async function readSync(){const file=$('syncFile').files?.[0];$('syncFile').value='';if(!file||!vault||busy)return;syncRecord=null;syncIncoming=null;$('syncReview').replaceChildren();$('syncApply').disabled=true;if(file.size>MAX_BACKUP_BYTES)return toast(translateText("Файл слишком большой."));const epoch=evoEpoch;setBusy(true);try{const r=JSON.parse(await file.text());if(!validEnvelope(r))throw Error(translateText("Неверный формат."));if(vault&&epoch===evoEpoch&&$('syncDialog').open){syncRecord=r;$('syncStatus').textContent=translateText("Файл выбран. Введи мастер-пароль источника.");}}catch(e){toast(localizedError(e));}finally{setBusy(false);}}
async function decryptSync(e){e.preventDefault();if(!vault||busy||!syncRecord)return toast(translateText("Выбери файл."));const pass=$('syncPass').value,epoch=evoEpoch;$('syncPass').value='';setBusy(true);try{const r=await decryptEnvelope(syncRecord,pass);if(!vault||epoch!==evoEpoch||!$('syncDialog').open)return;syncIncoming=r.decoded;reviewSync();$('syncStatus').textContent=translateText("Проверь список. Изменённые записи по умолчанию не выбраны.");}catch(err){toast(localizedError(err));}finally{setBusy(false);}}
function mergePairs(v){const groups=new Map();for(const e of v.entries){const k=entryIdentity(e);if(!groups.has(k))groups.set(k,[]);groups.get(k).push(e);}return [...groups.values()].filter(g=>g.length>1);}
function mergePair(v,keepId,dropId){const a=v.entries.find(e=>e.id===keepId),b=v.entries.find(e=>e.id===dropId);if(!a||!b||a===b||entryIdentity(a)!==entryIdentity(b))throw Error(translateText("Записи не совпадают."));const merged={...a,ghost:!!a.ghost||!!b.ghost,favorite:!!a.favorite||!!b.favorite,updatedAt:new Date().toISOString()};for(const k of ['password','url','notes','login'])if(!merged[k])merged[k]=b[k];if(!a.recovery&&b.recovery)merged.recovery=b.recovery;const totp=(v.totp||[]).map(t=>t.entryId===dropId?{...t,entryId:keepId}:t);return {...v,entries:v.entries.filter(e=>e.id!==dropId).map(e=>e.id===keepId?merged:e),totp,oneProgress:v.oneProgress?.id===dropId?{id:keepId,step:0}:v.oneProgress};}
function renderMerge(){const root=$('mergeList');root.replaceChildren();if(!vault)return;const groups=mergePairs(vault);if(!groups.length)root.append(make('p','titan-muted',translateText("Совпадающих записей не найдено.")));for(const group of groups){const a=group[0];for(const b of group.slice(1)){const card=make('article','titan-card');card.append(make('strong','',a.service+' / '+b.service),make('p','titan-muted',translateText("Пароли: ")+(a.password===b.password?translateText("совпадают"):translateText("различаются"))+translateText(" · заметки: ")+(a.notes===b.notes?translateText("совпадают"):translateText("различаются"))),make('p','titan-muted',translateText("Первая: ")+(a.updatedAt||translateText("дата неизвестна"))+translateText(" / Вторая: ")+(b.updatedAt||translateText("дата неизвестна"))));for(const [keep,drop,label] of [[a,b,translateText("Оставить первую")],[b,a,translateText("Оставить вторую")]])card.append(infButton(label,()=>{$('mergeDialog').close();ghostAuthorize(async()=>{if(!vault||!confirm(translateText("Объединить? Различающиеся поля второй записи не сохранятся в основной карточке.")))return;try{await evoSave(mergePair(vault,keep.id,drop.id),translateText("Записи объединены. 2FA сохранены."));}catch(e){toast(localizedError(e));}});}));root.append(card);}}}
function attachEvolution(){ $('entryKind').onchange=()=>{applyEntryKind();if(['card','document','api','recovery','pin'].includes($('entryKind').value))$('entryGhost').checked=true;};for(const id of ['historyDialog','syncDialog','mergeDialog']){$(id).querySelector('.evo-close').onclick=()=>$(id).close();$(id).addEventListener('close',()=>{if($(id).open)return;if(id==='syncDialog'){++evoEpoch;syncRecord=null;syncIncoming=null;$('syncPass').value='';$('syncReview').replaceChildren();$('syncEntries').replaceChildren();$('syncApply').disabled=true;$('syncStatus').textContent='';}else $(id==='historyDialog'?'historyList':'mergeList').replaceChildren();});}
 $('historyBtn').onclick=showHistory;$('historyPolicy').onclick=async()=>{if(!vault)return;const days=Number($('historyRetention').value);if(!days&&!confirm(translateText("Выключить и удалить всю историю?")))return;if(await evoSave({...vault,historyDays:days},translateText("Настройка сохранена.")))renderHistory();};$('historyPurge').onclick=async()=>{if(vault&&confirm(translateText("Удалить все прошлые версии из текущего сейфа?"))){await evoSave({...vault,history:[]},translateText("История очищена."));renderHistory();}};
 $('syncBtn').onclick=()=>{if(!vault||busy)return;syncEntries();$('syncDialog').showModal();};$('syncSince').onchange=syncEntries;$('syncAll').onclick=()=>{for(const c of $('syncEntries').querySelectorAll('input'))c.checked=true;};$('syncExport').onclick=()=>{const ids=[...$('syncEntries').querySelectorAll('input:checked')].map(x=>x.value);if(!ids.length)return toast(translateText("Выбери записи."));$('syncDialog').close();ghostAuthorize(()=>exportSync(ids),'sync');};$('syncFile').onchange=readSync;$('syncForm').onsubmit=decryptSync;$('syncApply').onclick=async()=>{if(!vault||busy||!syncIncoming)return;const ids=[...$('syncReview').querySelectorAll('input:checked')].map(x=>x.value);const r=applySync(vault,syncIncoming,ids);if(!confirm(formatText("Новых: {0}, замен: {1}, новых 2FA: {2}. Применить?",[r.added,r.updates,r.addedTotp])))return;if(await evoSave(r.result,translateText("Изменения сохранены. Пропущено: ")+r.skipped)){syncIncoming=null;syncRecord=null;$('syncReview').replaceChildren();$('syncApply').disabled=true;syncEntries();}};
 $('mergeBtn').onclick=()=>{if(!vault||busy)return;renderMerge();$('mergeDialog').showModal();};}


// FORTRESS GLASS — local interface and automatic opt-out passkey request.
const AUTO_BIO_KEY='bastion-auto-bio-v092';
let activeBioRequest=null, autoBioAttempted=false;
function autoBioEnabled(){try{return localStorage.getItem(AUTO_BIO_KEY)!=='off';}catch{return false;}}
function cancelAutoRequest(){if(activeBioRequest)activeBioRequest.abort();}
function tryAutoBio(){
 if(autoBioAttempted||!autoBioEnabled()||!window.bastionHasVault||!bioAvailable()||!bioConfig()||vault||busy||document.hidden||!$('languageSetup').classList.contains('hidden')||$('unlockView').classList.contains('hidden'))return;
 autoBioAttempted=true;unlockBiometric(true);
}
function refreshHome(){if(!vault)return;$('homeVaultCount').textContent=String(vault.entries.filter(e=>!e.kind||e.kind==='login').length)+' '+translateText(translateText("записей"));$('homeAuthCount').textContent=String((vault.totp||[]).length)+' '+translateText(translateText("кодов"));}
function onePicker(){if(!vault||busy)return;const root=$('onePickerList');root.replaceChildren();for(const e of vault.entries.filter(e=>!e.kind||e.kind==='login')){const b=make('button','btn secondary',e.service);b.type='button';b.onclick=()=>{$('onePicker').close();openOne(e.id);};root.append(b);}if(!root.children.length)root.append(make('p','',translateText(translateText("Нет аккаунтов для входа."))));$('onePicker').showModal();}
function attachFortress(){
 $('homeOne').onclick=onePicker;$('onePickerClose').onclick=()=>$('onePicker').close();$('onePicker').addEventListener('close',()=>$('onePickerList').replaceChildren());
 $('homeDNA').onclick=()=>$('dnaBtn').click();$('homeHistory').onclick=()=> $('historyBtn').click();$('homeSync').onclick=()=> $('syncBtn').click();$('homeUniversal').onclick=()=>{$('vaultKindFilter').value='all';selectTab('vault');renderEntries();};
 $('homeVault').onclick=()=>{$('vaultKindFilter').value='login';renderEntries();};
 $('vaultKindFilter').onchange=renderEntries;
 $('homeSearch').addEventListener('input',()=>{if(!vault)return;const q=$('homeSearch').value;$('vaultKindFilter').value='all';selectTab('vault');$('search').value=q;renderEntries();$('search').focus();$('homeSearch').value='';});
 $('autoBioPref').checked=autoBioEnabled();$('autoBioPref').onchange=()=>{try{localStorage.setItem(AUTO_BIO_KEY,$('autoBioPref').checked?'on':'off');}catch{$('autoBioPref').checked=autoBioEnabled();}};
 $('cancelAutoBio').onclick=cancelAutoRequest;$('unlockMaster').addEventListener('focus',cancelAutoRequest);
 $('languageSearch').addEventListener('input',()=>{const q=$('languageSearch').value.trim().toLowerCase();for(const o of $('languageSelect').options)o.hidden=!!q&&!o.textContent.toLowerCase().includes(q)&&!o.value.includes(q)&&!languageSearchNames(o.value).includes(q);const found=[...$('languageSelect').options].find(o=>!o.hidden);if(found)$('languageSelect').value=found.value;});
 document.addEventListener('visibilitychange',()=>{if(!document.hidden&&!autoBioAttempted)tryAutoBio();});
}



init();
