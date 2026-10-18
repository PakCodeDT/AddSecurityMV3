'use strict';

const $ = id => document.getElementById(id);

let availableLists = {};   // core.js -> PROTECTION_LISTS + özel listeler
let activeLists = new Set();       // ekranda şu an işaretli olan (henüz kaydedilmemiş olabilir)
let savedActiveLists = new Set();  // core.js'de fiilen UYGULANMIŞ olan son durum
let listPriorities = {};   // id -> öncelik numarası (küçük = önce işlenir)

// ============================================================================
// CORE.JS İLE İLETİŞİM (background sayfasındaki window.AdSecurity)
// ============================================================================
// Firefox'ta `browser`, Chrome'da `chrome` globali bulunur; ikisini de destekle.
function getBrowserAPI() {
  try {
    if (typeof browser !== 'undefined' && browser && browser.runtime) return browser;
  } catch (e) {}
  try {
    if (typeof chrome !== 'undefined' && chrome && chrome.runtime) return chrome;
  } catch (e) {}
  return null;
}

function sendCoreMessage(action, extra = {}) {
  const api = getBrowserAPI();
  if (!api || !api.runtime || !api.runtime.sendMessage) {
    throw new Error('Eklenti API bulunamadı (browser/chrome.runtime yok)');
  }
  return api.runtime.sendMessage({ namespace: 'adsecurity', action, ...extra });
}

async function loadProtectionLists() {
  let res = null;
  try {
    res = await sendCoreMessage('getProtectionLists');
  } catch (e) {
    console.warn('[AdSecurity Ayarlar] background yanıt vermedi, filtre.json fallback:', e);
    res = null;
  }
  availableLists = (res && res.available) || {};
  activeLists = new Set((res && res.active) || []);
  listPriorities = (res && res.priorities) || {};

  // Fallback: background boş/hatalı dönerse filtre.json'u doğrudan oku ki
  // liste arayüzü tamamen boş kalmasın. (Salt görüntüleme amaçlı;
  // kaydetme yine background üzerinden yapılır.)
  if (Object.keys(availableLists).length === 0) {
    try {
      const r = await fetch('filtre.json', { cache: 'no-cache' });
      if (r && r.ok) {
        const defs = await r.json();
        availableLists = defs || {};
        activeLists = new Set(
          Object.keys(availableLists).filter(id => availableLists[id] && availableLists[id].defaultOn === true)
        );
        listPriorities = {};
        for (const id of Object.keys(availableLists)) {
          if (availableLists[id] && availableLists[id].tier !== undefined) {
            listPriorities[id] = availableLists[id].tier;
          }
        }
      }
    } catch (e) {
      console.error('[AdSecurity Ayarlar] filtre.json fallback başarısız:', e);
    }
  }

  savedActiveLists = new Set(activeLists);
}

async function persistActiveLists() {
  const res = await sendCoreMessage('setProtectionLists', { lists: Array.from(activeLists) });
  if (!res || res.ok === false) {
    throw new Error((res && res.error) || 'Bilinmeyen hata');
  }
}
function setsEqual(a, b) {
  if (a.size !== b.size) return false;
  for (const v of a) if (!b.has(v)) return false;
  return true;
}

// Ekranda işaretli listeler ile core.js'de fiilen uygulanmış olan liste
// aynı değilse "kaydedilmemiş değişiklik" var demektir.
function updateSaveButtonState() {
  const btn = $('btn-save-filters');
  if (!btn) return;
  const dirty = !setsEqual(activeLists, savedActiveLists);
  btn.classList.toggle('dirty', dirty);
  btn.textContent = dirty ? '💾 Kaydet ve Uygula (kaydedilmemiş değişiklikler var)' : '💾 Kaydet';
}

// ============================================================================
// FİLTRE LİSTESİ ARAYÜZÜ
// ============================================================================
function getPriority(id) {
  if (Object.prototype.hasOwnProperty.call(listPriorities, id)) return listPriorities[id];
  return 100000;
}

function renderFilterList() {
  const container = $('filter-list');
  container.innerHTML = '';

  const ids = Object.keys(availableLists)
    .filter(id => !(availableLists[id] && availableLists[id].ownRulesMarker))
    .sort((a, b) => getPriority(a) - getPriority(b));

  // Boş kalırsa kullanıcıya nedenini göster (eskiden tamamen boş görünüyordu).
  if (ids.length === 0) {
    const empty = document.createElement('div');
    empty.style.cssText = 'padding:16px;color:var(--text-dim);font-size:0.9rem;';
    empty.textContent = '⚠️ Filtre listesi yüklenemedi. Arka plan betiği (core.js/corest.js) çalışmıyor veya filtre.json okunamadı. Konsolu kontrol edin.';
    container.appendChild(empty);
    updateSaveButtonState();
    return;
  }
  for (const id of ids) {
    const list = availableLists[id];
    const isOn = activeLists.has(id);

    const item = document.createElement('div');
    item.className = 'filter-item' + (isOn ? ' enabled' : '');
    item.dataset.id = id;

    const toggle = document.createElement('button');
    toggle.className = 'filter-toggle' + (isOn ? ' on' : '');
    toggle.type = 'button';
    toggle.setAttribute('aria-pressed', String(isOn));
    toggle.addEventListener('click', () => toggleFilter(id));

    const info = document.createElement('div');
    info.className = 'filter-info';

    const title = document.createElement('div');
    title.className = 'filter-title';
    title.textContent = `${list.icon || ''} ${list.name || id}`.trim();

    const meta = document.createElement('div');
    meta.className = 'filter-meta';

    if (list.author) {
      const authorBadge = document.createElement('span');
      authorBadge.className = 'filter-badge';
      authorBadge.textContent = list.author;
      meta.appendChild(authorBadge);
    }

    if (list.license) {
      const licenseBadge = document.createElement('span');
      licenseBadge.className = 'filter-badge';
      licenseBadge.textContent = list.license;
      meta.appendChild(licenseBadge);
    }

    if (list.supportURL) {
      const link = document.createElement('a');
      link.className = 'filter-badge link';
      link.href = list.supportURL;
      link.target = '_blank';
      link.rel = 'noopener noreferrer';
      link.textContent = 'Kaynak';
      meta.appendChild(link);
    }

    if (list.isCustom) {
      const customBadge = document.createElement('span');
      customBadge.className = 'filter-badge';
      customBadge.textContent = list.type === 'manual' ? 'Manuel' : 'Özel URL';
      meta.appendChild(customBadge);
    }

    // Öncelik numarası: küçük olan, çakışan kurallarda önce değerlendirilir
    // ve kazanır (engelleme/istisna kuralları için).
    // Artık bir açılır liste (combobox) ile seçiliyor; birden fazla listenin
    // aynı önceliğe sahip olması artık serbest, bu yüzden benzersizlik kontrolü yok.
    const priorityWrap = document.createElement('label');
    priorityWrap.className = 'filter-badge';
    priorityWrap.style.display = 'flex';
    priorityWrap.style.alignItems = 'center';
    priorityWrap.style.gap = '4px';
    priorityWrap.textContent = 'Öncelik:';
    const prioritySelect = document.createElement('select');
    prioritySelect.className = 'priority-input';
    prioritySelect.style.width = '64px';
    prioritySelect.style.background = 'var(--card)';
    prioritySelect.style.color = 'inherit';
    prioritySelect.style.border = '1px solid var(--toggle-bg)';
    prioritySelect.style.borderRadius = '4px';
    prioritySelect.style.textAlign = 'center';
    prioritySelect.style.padding = '2px 4px';

    const currentPriority = getPriority(id);
    // Seçim aralığı 5 tier ile sınırlı (0-4). Mevcut değer bu aralığın
    // dışındaysa (örn. eski/varsayılan 100000) 1'e (Sıradan) sıkıştırılır.
    const TIER_OPTION_NAMES = { 0: 'Alt', 1: 'Sıradan', 2: 'Kıdemli', 3: 'Kural Tanımaz', 4: 'Fixes' };
    const clampedPriority = (Number.isFinite(currentPriority) && currentPriority >= 0 && currentPriority <= 4)
      ? currentPriority
      : 1;

    // Birden fazla liste aynı tier'i paylaşabilir (Fixes dahil); benzersizlik
    // kontrolü veya devre dışı bırakma yok.
    for (const val of [0, 1, 2, 3, 4]) {
      const opt = document.createElement('option');
      opt.value = String(val);
      opt.textContent = `${val} - ${TIER_OPTION_NAMES[val]}`;
      if (val === clampedPriority) opt.selected = true;
      prioritySelect.appendChild(opt);
    }

    prioritySelect.addEventListener('change', () => {
      const newValue = parseInt(prioritySelect.value, 10);
      if (Number.isNaN(newValue) || newValue < 0 || newValue > 4) return;
      listPriorities[id] = newValue;
      persistPriorities();
      renderFilterList();
    });
    priorityWrap.appendChild(prioritySelect);
    meta.appendChild(priorityWrap);

    info.appendChild(title);
    info.appendChild(meta);

    item.appendChild(toggle);
    item.appendChild(info);

    if (list.isCustom) {
      const editBtn = document.createElement('button');
      editBtn.className = 'btn';
      editBtn.type = 'button';
      editBtn.textContent = '✏️';
      editBtn.title = 'Düzenle';
      editBtn.addEventListener('click', () => openCustomListForm(id));

      const delBtn = document.createElement('button');
      delBtn.className = 'btn';
      delBtn.type = 'button';
      delBtn.textContent = '🗑️';
      delBtn.title = 'Sil';
      delBtn.addEventListener('click', () => deleteCustomList(id));

      item.appendChild(editBtn);
      item.appendChild(delBtn);
    }

    container.appendChild(item);
  }

  updateSaveButtonState();
}

async function persistPriorities() {
  // Sadece değişeni değil, TÜM listelerin çözümlenmiş öncelik değerlerini
  // gönderiyoruz; böylece bir override, henüz hiç ayarlanmamış bir listenin
  // varsayılan (filtre.json'daki) önceliğiyle sessizce çakışamaz.
  const fullMap = {};
  for (const id of Object.keys(availableLists)) fullMap[id] = getPriority(id);
  try {
    const res = await sendCoreMessage('setListPriorities', { priorities: fullMap });
    if (!res || res.ok === false) throw new Error((res && res.error) || 'Bilinmeyen hata');
    listPriorities = fullMap;
  } catch (e) {
    showErrorToast('Öncelik kaydedilemedi', e);
    await loadProtectionLists();
    renderFilterList();
  }
}

// Tek bir filtreyi aç/kapat: bu SADECE ekrandaki (henüz kaydedilmemiş)
// durumu değiştirir. core.js'e hiçbir şey yazılmaz ve filtreler yeniden
// derlenmez; bunun için kullanıcının "💾 Kaydet" butonuna basması gerekir.
function toggleFilter(id) {
  const item = document.querySelector(`.filter-item[data-id="${id}"]`);
  const toggleBtn = item ? item.querySelector('.filter-toggle') : null;

  if (activeLists.has(id)) {
    activeLists.delete(id);
  } else {
    activeLists.add(id);
  }

  if (item) item.classList.toggle('enabled', activeLists.has(id));
  if (toggleBtn) toggleBtn.classList.toggle('on', activeLists.has(id));

  updateSaveButtonState();
}

// ============================================================================
// ÖZEL (KULLANICI TANIMLI) LİSTELER
// ============================================================================
let editingCustomListId = null;

// "Kendi Kurallarım" sekmesi, arka planda normal bir manuel özel liste
// olarak saklanır ama bu sabit isimle işaretlenir; böylece diğer özel
// listelerden (uzak URL) ayırt edilip kendi sekmesinde tek bir metin
// kutusu olarak yönetilebilir.
const OWN_RULES_MARKER_NAME = '__adsecurity_own_rules__';

function findOwnRulesListId() {
  return Object.keys(availableLists).find(id => {
    const l = availableLists[id];
    return l && l.isCustom && l.type === 'manual' && l.ownRulesMarker === OWN_RULES_MARKER_NAME;
  }) || null;
}

function openCustomListForm(id) {
  editingCustomListId = id || null;
  const list = id ? availableLists[id] : null;

  $('custom-form').classList.add('active-form');
  $('custom-name').value = list ? list.name : '';
  $('custom-url').value = (list && list.urls && list.urls[0]) || '';
  $('custom-name').focus();
}

function closeCustomListForm() {
  editingCustomListId = null;
  $('custom-form').classList.remove('active-form');
}

async function saveCustomListForm() {
  const name = $('custom-name').value.trim();
  const url = $('custom-url').value.trim();

  if (!name) { $('custom-name').focus(); return; }
  if (!url) { $('custom-url').focus(); return; }

  const saveBtn = $('btn-custom-save');
  saveBtn.disabled = true;
  try {
    if (editingCustomListId) {
      await sendCoreMessage('updateCustomList', { id: editingCustomListId, data: { name, url } });
    } else {
      await sendCoreMessage('addCustomList', { data: { name, type: 'remote', url } });
    }
    closeCustomListForm();
    await loadProtectionLists();
    renderFilterList();
    showToast('msg-save-filters');
  } catch (e) {
    console.error('[AdSecurity Ayarlar] Özel liste kaydedilemedi:', e);
  } finally {
    saveBtn.disabled = false;
  }
}

async function deleteCustomList(id) {
  if (!confirm('Bu özel listeyi silmek istediğinize emin misiniz?')) return;
  try {
    await sendCoreMessage('removeCustomList', { id });
    await loadProtectionLists();
    renderFilterList();
  } catch (e) {
    console.error('[AdSecurity Ayarlar] Özel liste silinemedi:', e);
  }
}

function showToast(id) {
  const el = $(id);
  if (!el) return;
  el.classList.add('show');
  setTimeout(() => el.classList.remove('show'), 1800);
}

// Hem konsola (hata ayıklama için) hem de arayüzde kalıcı-ama-otomatik-
// kaybolan bir kırmızı toast olarak hata mesajı basar. alert()'in aksine
// arayüzü bloklamaz.
function showErrorToast(userMessage, error) {
  console.error('[AdSecurity Ayarlar]', userMessage, error);
  const el = $('msg-error');
  if (!el) return;
  const detail = error && error.message ? error.message : (error ? String(error) : '');
  el.textContent = detail ? `❌ ${userMessage}\n${detail}` : `❌ ${userMessage}`;
  el.classList.add('show');
  clearTimeout(el._hideTimer);
  el._hideTimer = setTimeout(() => el.classList.remove('show'), 5000);
}

// ============================================================================
// SEKME (TAB) GEÇİŞİ
// ============================================================================
function switchTab(targetId) {
  document.querySelectorAll('.section').forEach(sec => sec.classList.toggle('active', sec.id === targetId));
  document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.toggle('active', btn.dataset.target === targetId));
}

// ============================================================================
// "KENDİ KURALLARIM" SEKMESİ
// ============================================================================
async function loadOwnRulesIntoForm() {
  const id = findOwnRulesListId();
  const text = id ? (availableLists[id].rulesText || '') : '';
  $('own-rules-text').value = text;
}

async function saveOwnRules() {
  const rulesText = $('own-rules-text').value;
  const btn = $('btn-own-rules-save');
  btn.disabled = true;
  try {
    const id = findOwnRulesListId();
    if (id) {
      await sendCoreMessage('updateCustomList', { id, data: { rulesText } });
    } else {
      await sendCoreMessage('addCustomList', {
        data: {
          name: 'Kendi Kurallarım',
          type: 'manual',
          rulesText,
          icon: '✍️',
          ownRulesMarker: '__adsecurity_own_rules__'
        }
      });
    }
    await loadProtectionLists();
    renderFilterList();
    showToast('msg-save-filters');
  } catch (e) {
    showErrorToast('Kendi kurallar kaydedilemedi', e);
  } finally {
    btn.disabled = false;
  }
}

// ============================================================================
// BAŞLAT
// ============================================================================
document.addEventListener('DOMContentLoaded', async () => {
  try {
    await loadProtectionLists();
    renderFilterList();
    await loadOwnRulesIntoForm();
  } catch (e) {
    console.error('[AdSecurity Ayarlar] Filtre listesi yüklenemedi:', e);
    // Sessiz kalma: kullanıcıya görünür hata ver.
    try { renderFilterList(); } catch (_) {}
    showErrorToast('Filtre listesi yüklenemedi', e);
  }

  document.querySelectorAll('.tab-btn').forEach(btn => {
    btn.addEventListener('click', () => switchTab(btn.dataset.target));
  });

  $('btn-own-rules-save').addEventListener('click', saveOwnRules);

  // Filtre açma/kapatma ve yeni liste ekleme ekranda ANINDA uygulanmaz;
  // gerçek uygulama (core.js'e yazma + filtreleri yeniden derleme) sadece
  // bu butona basılınca gerçekleşir.
  $('btn-save-filters').addEventListener('click', async () => {
    const btn = $('btn-save-filters');
    btn.disabled = true;
    try {
      await persistActiveLists();
      savedActiveLists = new Set(activeLists);
      updateSaveButtonState();
      showToast('msg-save-filters');
    } catch (e) {
      showErrorToast('Kaydedilemedi', e);
    } finally {
      btn.disabled = false;
    }
  });

  $('btn-add-custom').addEventListener('click', () => openCustomListForm(null));
  $('btn-custom-cancel').addEventListener('click', () => closeCustomListForm());
  $('btn-custom-save').addEventListener('click', saveCustomListForm);

  $('btn-refresh-filters').addEventListener('click', async () => {
    const btn = $('btn-refresh-filters');
    const originalText = btn.textContent;
    btn.disabled = true;
    btn.textContent = '🔄 Güncelleniyor...';
    try {
      // Bu istek filtre listelerini, entities.json'u ve publicsuffix.org
      // listesini ZORLA (önbelleği yok sayarak) yeniden çeker.
      const res = await sendCoreMessage('refreshProtectionLists');
      if (!res || res.ok === false) {
        throw new Error((res && res.error) || 'Bilinmeyen hata');
      }
      // Aktif olarak işaretlenmiş ama henüz kaydedilmemiş (dirty) seçimleri
      // ezmemek için sadece liste tanımlarını/önceliklerini tazeleriz.
      const fresh = await sendCoreMessage('getProtectionLists');
      availableLists = (fresh && fresh.available) || availableLists;
      listPriorities = (fresh && fresh.priorities) || listPriorities;
      savedActiveLists = new Set((fresh && fresh.active) || []);
      renderFilterList();
      showToast('msg-save-filters');
    } catch (e) {
      showErrorToast('Güncelleme başarısız oldu', e);
    } finally {
      btn.disabled = false;
      btn.textContent = originalText;
    }
  });
});