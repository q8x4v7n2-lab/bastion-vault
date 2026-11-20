'use strict';

// BASTION VAULT 0.1: полностью клиентский прототип, не проходил независимый аудит.
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
const BACKGROUND_LOCK_MS = 60_000;

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
  node.textContent = message;
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
      value.data.length > 8_000_000 || value.data.length < 25) return false;
  try { return bytesFromBase64(value.salt).length === 16 && bytesFromBase64(value.iv).length === 12 && bytesFromBase64(value.data).length >= 17; }
  catch { return false; }
}
function validVault(value) {
  if (!value || value.schema !== 1 || !Array.isArray(value.entries) || value.entries.length > 20_000) return false;
  return value.entries.every(e => e && typeof e.id === 'string' && e.id.length <= 70 &&
    typeof e.service === 'string' && e.service.length <= 100 &&
    typeof e.login === 'string' && e.login.length <= 200 &&
    typeof e.password === 'string' && e.password.length <= 1024 &&
    typeof e.url === 'string' && e.url.length <= 1000 &&
    typeof e.notes === 'string' && e.notes.length <= 3000);
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
  $('gate').classList.remove('hidden');
  $('app').classList.add('hidden');
  $('lockBtn').classList.add('hidden');
  $('createView').classList.toggle('hidden', mode !== 'create');
  $('unlockView').classList.toggle('hidden', mode !== 'unlock');
}
function showApp() {
  $('gate').classList.add('hidden');
  $('app').classList.remove('hidden');
  $('lockBtn').classList.remove('hidden');
  $('search').value = '';
  lastActivity = Date.now();
  renderEntries();
}
function closeDialogs() {
  for (const id of ['editor','importDialog','masterDialog']) if ($(id).open) $(id).close();
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
    root.append(empty); return;
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
  }
}
function randomIndex(max) {
  const maxValue = Math.floor(256 / max) * max;
  const x = new Uint8Array(1);
  do { crypto.getRandomValues(x); } while (x[0] >= maxValue);
  return x[0] % max;
}
function generatePassword(len, allowSymbols) {
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
  $('showSecret').textContent = 'Показать';
  $('siteUrl').value = item?.url ?? '';
  $('notes').value = item?.notes ?? '';
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
  const line1 = make('div','', 'Локальная проверка: ');
  line1.append(make('strong','',String(vault.entries.length) + ' записей'));
  const line2 = make('div', reused ? 'bad':'', `Повторяющиеся пароли: ${reused} записей`);
  const line3 = make('div', short ? 'bad':'', `Пароли короче 14 символов: ${short}`);
  const hint = make('div','', 'Это базовая проверка, не доказательство стойкости. Никакие пароли никуда не отправляются.');
  p.append(line1,line2,line3,hint);
  p.classList.toggle('hidden');
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
  let url;
  try { url = ensureHttps($('siteUrl').value); }
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
  if (file.size > 8_000_000) return toast('Файл слишком большой для этой версии.');
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
    key=nextKey;envelope=nextRecord;
    $('masterDialog').close();$('masterNew').value='';$('masterConfirm').value='';
    toast('Мастер-пароль заменён. Скачай новую резервную копию.');
  }catch(e){toast(e.message||'Не удалось сменить пароль.');}
  finally{setBusy(false,$('confirmMasterChange'));}
}
function attachHandlers() {
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
    $('showSecret').textContent=show?'Скрыть':'Показать';
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
    $('secret').value=generatePassword(Number($('length').value),$('symbols').checked);
    $('secret').type='password';$('showSecret').textContent='Показать';
    toast('Новый пароль создан. Он ещё не изменён на сайте!');
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
    if(document.hidden)hiddenAt=Date.now();
    else if(vault && hiddenAt && Date.now()-hiddenAt>=BACKGROUND_LOCK_MS)lockVault();
  });
  window.addEventListener('pagehide',()=>{if(vault)lockVault(false);});
  setInterval(()=>{if(vault && !document.hidden && Date.now()-lastActivity>=IDLE_LOCK_MS)lockVault();},10_000);
}
async function init() {
  attachHandlers();
  if (!window.isSecureContext || !crypto?.subtle || !window.indexedDB) {
    $('gate').classList.add('hidden');$('unsupported').classList.remove('hidden');return;
  }
  try {
    db = await openDB();
    const current = await readEncrypted();
    showGate(current ? 'unlock' : 'create');
  } catch(e) {
    $('gate').classList.add('hidden');
    $('unsupported').classList.remove('hidden');
    $('unsupported').append(make('p','',e.message||'Локальное хранилище недоступно.'));
  }
  if('serviceWorker' in navigator) navigator.serviceWorker.register('./sw.js').catch(()=>{});
}
init();
